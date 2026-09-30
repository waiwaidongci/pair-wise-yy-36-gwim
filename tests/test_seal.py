import json
import sqlite3
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path

from src.audit import calculate_hash
from src.domain import (NotFoundError, PermissionDenied, ValidationError,
                        VerificationConflict)
from src.http_api import make_handler
from src.repository import Repository
from src.service import Service


def make_item(service, external_ref, actor="creator", role="operator"):
    return service.create_item({
        "title": external_ref, "description": "排污事件",
        "severity": "exceedance", "quantity": 5, "threshold": 10,
        "external_ref": external_ref,
    }, actor, role)


class SealTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        self.service = Service(self.repo)
        make_item(self.service, "S-1")
        make_item(self.service, "S-2")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def test_seal_idempotent_by_request_id_and_matches_tail(self):
        first = self.service.seal_audit({"request_id": "REQ-1"},
                                        "officer-a", "compliance_officer")
        tail = self.repo.list_audit()[-1]
        # 凭据记下封存时间、链尾事件和哈希，且与链尾一致
        self.assertEqual(first["tail_event_id"], tail["id"])
        self.assertEqual(first["tail_hash"], tail["entry_hash"])
        self.assertEqual(first["sealed_at"], tail["created_at"])
        self.assertEqual(first["sealed_by"], "officer-a")
        events_after_first = len(self.repo.list_audit())
        # 重复请求（即使换人）返回首次结果，不再写封存事件
        again = self.service.seal_audit({"request_id": "REQ-1"},
                                        "officer-b", "compliance_officer")
        self.assertEqual(again, first)
        self.assertEqual(len(self.repo.list_audit()), events_after_first)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_concurrent_seal_leaves_single_credential(self):
        results, errors = [], []

        def worker(officer):
            try:
                results.append(self.service.seal_audit(
                    {"request_id": "REQ-RACE"}, officer, "compliance_officer"))
            except Exception as exc:  # pragma: no cover - 测试失败路径
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(worker, [f"officer-{i}" for i in range(8)]))
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r == results[0] for r in results))
        # 并发封存只留一份
        self.assertEqual(self.repo.get_seal("REQ-RACE"), results[0])
        seal_events = [e for e in self.repo.list_audit() if e["action"] == "seal"]
        self.assertEqual(len(seal_events), 1)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_sealed_chain_keeps_growing_and_verify_reports_lag(self):
        seal = self.service.seal_audit({"request_id": "REQ-2"},
                                       "officer-a", "compliance_officer")
        # 封存后新增事件照常写入
        make_item(self.service, "S-3")
        make_item(self.service, "S-4")
        report = self.service.verify_audit({"request_id": "REQ-2"}, "director")
        self.assertEqual(report["status"], "consistent")
        self.assertEqual(report["lag"], 2)
        self.assertEqual(report["tail_event_id"], seal["tail_event_id"])
        self.assertEqual(report["current_event_count"],
                         seal["tail_event_id"] + 2)
        # 立即封存立即核验，落后0条
        seal2 = self.service.seal_audit({"request_id": "REQ-2B"},
                                        "officer-a", "compliance_officer")
        report2 = self.service.verify_audit({"request_id": "REQ-2B"}, "viewer")
        self.assertEqual(report2["lag"], 0)
        self.assertEqual(report2["tail_hash"], seal2["tail_hash"])

    def test_verify_detects_rewritten_event_with_first_breakpoint(self):
        self.service.seal_audit({"request_id": "REQ-3"},
                                "officer-a", "compliance_officer")
        with self.repo._lock:
            self.repo.conn.execute(
                "UPDATE audit_events SET actor='mallory' WHERE id=2")
            self.repo.conn.commit()
        with self.assertRaises(VerificationConflict) as ctx:
            self.service.verify_audit({"request_id": "REQ-3"}, "director")
        self.assertEqual(ctx.exception.extra["status"], "conflict")
        bp = ctx.exception.extra["first_breakpoint"]
        self.assertEqual(bp["ordinal"], 2)
        self.assertEqual(bp["type"], "hash_mismatch")

    def test_verify_detects_deleted_middle_event(self):
        self.service.seal_audit({"request_id": "REQ-4"},
                                "officer-a", "compliance_officer")
        with self.repo._lock:
            self.repo.conn.execute("DELETE FROM audit_events WHERE id=2")
            self.repo.conn.commit()
        with self.assertRaises(VerificationConflict) as ctx:
            self.service.verify_audit({"request_id": "REQ-4"}, "viewer")
        bp = ctx.exception.extra["first_breakpoint"]
        self.assertEqual(bp["type"], "event_missing")
        self.assertEqual(bp["ordinal"], 2)
        self.assertEqual(bp["expected_event_id"], 2)
        self.assertEqual(bp["actual_event_id"], 3)

    def test_verify_detects_external_restore_truncation(self):
        seal = self.service.seal_audit({"request_id": "REQ-5"},
                                       "officer-a", "compliance_officer")
        # 数据库被外部恢复到封存之前的快照：封存点之后（含封存事件）丢失
        with self.repo._lock:
            self.repo.conn.execute(
                "DELETE FROM audit_events WHERE id>=?", (seal["tail_event_id"],))
            self.repo.conn.commit()
        with self.assertRaises(VerificationConflict) as ctx:
            self.service.verify_audit({"request_id": "REQ-5"}, "director")
        extra = ctx.exception.extra
        self.assertEqual(extra["reason"], "truncated")
        self.assertEqual(extra["current_event_count"],
                         seal["tail_event_id"] - 1)
        self.assertEqual(extra["first_breakpoint"]["ordinal"],
                         seal["tail_event_id"])
        # 连凭据记录一起被恢复：按请求编号查不到，但凭据正文仍可核验
        with self.repo._lock:
            self.repo.conn.execute(
                "DELETE FROM audit_seals WHERE request_id=?", ("REQ-5",))
            self.repo.conn.commit()
        with self.assertRaises(NotFoundError):
            self.service.verify_audit({"request_id": "REQ-5"}, "director")
        with self.assertRaises(VerificationConflict) as ctx2:
            self.service.verify_audit({
                "tail_event_id": seal["tail_event_id"],
                "tail_hash": seal["tail_hash"],
                "sealed_at": seal["sealed_at"],
            }, "director")
        self.assertEqual(ctx2.exception.extra["reason"], "truncated")

    def test_verify_detects_rewritten_tail_with_valid_rechain(self):
        # 事件被改写并把后续哈希链接全部重算：链内自洽，但与凭据不符
        seal = self.service.seal_audit({"request_id": "REQ-6"},
                                       "officer-a", "compliance_officer")
        with self.repo._lock:
            self.repo.conn.execute(
                "UPDATE audit_events SET actor='mallory' WHERE id=1")
            rows = self.repo.conn.execute(
                "SELECT * FROM audit_events ORDER BY id").fetchall()
            previous = "GENESIS"
            for row in rows:
                detail = json.loads(row["detail"])
                payload = {
                    "action": row["action"], "entity_type": row["entity_type"],
                    "entity_id": row["entity_id"], "actor": row["actor"],
                    "detail": detail, "created_at": row["created_at"],
                }
                entry_hash = calculate_hash(previous, payload)
                self.repo.conn.execute(
                    "UPDATE audit_events SET previous_hash=?, entry_hash=? WHERE id=?",
                    (previous, entry_hash, row["id"]))
                previous = entry_hash
            self.repo.conn.commit()
        with self.assertRaises(VerificationConflict) as ctx:
            self.service.verify_audit({"request_id": "REQ-6"}, "director")
        bp = ctx.exception.extra["first_breakpoint"]
        # 链内无断点，首个与凭据不一致的位置就是封存链尾
        self.assertEqual(bp["type"], "tail_hash_mismatch")
        self.assertEqual(bp["ordinal"], seal["tail_event_id"])

    def test_seal_roles_and_verify_roles(self):
        for role in ("operator", "device", "director", "viewer"):
            with self.assertRaises(PermissionDenied):
                self.service.seal_audit({"request_id": "DENY-" + role},
                                        "x", role)
        for role in ("operator", "device", "compliance_officer"):
            with self.assertRaises(PermissionDenied):
                self.service.verify_audit({"request_id": "whatever"}, role)

    def test_operator_and_device_only_read_own_events(self):
        make_item(self.service, "OWN-1", actor="op1")
        make_item(self.service, "OWN-2", actor="op2")
        op1_events = self.service.audit("operator", actor="op1")
        self.assertTrue(op1_events)
        self.assertTrue(all(e["actor"] == "op1" for e in op1_events))
        device_events = self.service.audit("device", actor="device-9")
        self.assertEqual(device_events, [])
        # 主管和审计员看全链
        all_events = self.service.audit("director")
        self.assertEqual(len(all_events), len(self.repo.list_audit()))
        self.assertEqual(len(self.service.audit("viewer")), len(all_events))
        # 运行人员必须声明身份
        with self.assertRaises(ValidationError):
            self.service.audit("operator", actor="  ")

    def test_failed_seal_rolls_back_and_retry_succeeds(self):
        calls = {"n": 0}

        def failing_insert(request_id, tail_event_id, tail_hash, actor, sealed_at):
            calls["n"] += 1
            raise sqlite3.Error("凭据存储故障")

        before = len(self.repo.list_audit())
        self.repo._insert_seal = failing_insert
        with self.assertRaises(sqlite3.Error):
            self.service.seal_audit({"request_id": "REQ-FAIL"},
                                    "officer-a", "compliance_officer")
        self.assertGreaterEqual(calls["n"], 1)
        del self.repo._insert_seal  # 故障排除后按同一请求编号重试
        # 失败后不留半条记录：封存事件回滚、凭据不存在
        self.assertEqual(len(self.repo.list_audit()), before)
        self.assertIsNone(self.repo.get_seal("REQ-FAIL"))
        self.assertTrue(self.repo.verify_audit_chain())
        # 按同一请求编号重试成功
        seal = self.service.seal_audit({"request_id": "REQ-FAIL"},
                                       "officer-a", "compliance_officer")
        self.assertEqual(seal["tail_event_id"], before + 1)
        self.assertEqual(self.repo.get_seal("REQ-FAIL"), seal)
        self.assertTrue(self.repo.verify_audit_chain())

    def test_empty_chain_seal(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            repo = Repository(str(Path(tmp.name) / "empty.db"))
            service = Service(repo)
            seal = service.seal_audit({"request_id": "REQ-EMPTY"},
                                      "officer-a", "compliance_officer")
            self.assertEqual(seal["tail_event_id"], 1)
            report = service.verify_audit({"request_id": "REQ-EMPTY"}, "viewer")
            self.assertEqual(report["status"], "consistent")
            self.assertEqual(report["lag"], 0)
            repo.close()
        finally:
            tmp.cleanup()


class HttpSealTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Repository(str(Path(self.tmp.name) / "test.db"))
        service = Service(self.repo)
        handler = make_handler(service, str(Path(__file__).resolve().parent.parent / "static"))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.repo.close()
        self.tmp.cleanup()

    def request(self, method, path, body=None, actor="x", role="director"):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}", data=data, method=method,
            headers={"Content-Type": "application/json",
                     "X-Actor": actor, "X-Role": role})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_seal_verify_and_conflict_over_http(self):
        status, body = self.request("POST", "/api/items", {
            "title": "http", "description": "d", "severity": "watch",
            "quantity": 1, "threshold": 1, "external_ref": "H-1",
        }, actor="op1", role="operator")
        self.assertEqual(status, 201)
        status, first = self.request("POST", "/api/audit/seals",
                                     {"request_id": "HTTP-1"},
                                     actor="off", role="compliance_officer")
        self.assertEqual(status, 201)
        status, again = self.request("POST", "/api/audit/seals",
                                     {"request_id": "HTTP-1"},
                                     actor="off", role="compliance_officer")
        self.assertEqual(status, 201)
        self.assertEqual(again, first)
        status, report = self.request("POST", "/api/audit/verify",
                                      {"request_id": "HTTP-1"}, role="director")
        self.assertEqual(status, 200)
        self.assertEqual(report["status"], "consistent")
        self.assertEqual(report["lag"], 0)
        # 运行人员不能核验
        status, body = self.request("POST", "/api/audit/verify",
                                    {"request_id": "HTTP-1"}, role="operator")
        self.assertEqual(status, 403)
        # 篡改后核验返回409冲突并指出断点
        with self.repo._lock:
            self.repo.conn.execute(
                "UPDATE audit_events SET actor='mallory' WHERE id=1")
            self.repo.conn.commit()
        status, body = self.request("POST", "/api/audit/verify",
                                    {"request_id": "HTTP-1"}, role="viewer")
        self.assertEqual(status, 409)
        self.assertEqual(body["status"], "conflict")
        self.assertEqual(body["first_breakpoint"]["ordinal"], 1)
        # 运行人员经HTTP只能读到自己的事件
        status, body = self.request("GET", "/api/audit", None,
                                    actor="op1", role="operator")
        self.assertEqual(status, 200)
        self.assertTrue(all(e["actor"] == "op1" for e in body["events"]))


if __name__ == "__main__":
    unittest.main()
