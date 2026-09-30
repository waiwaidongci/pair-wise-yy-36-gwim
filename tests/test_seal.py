import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import PermissionDenied, ValidationError
from src.repository import Repository
from src.service import Service
from src.rules import STATES, TRANSITION_ROLES


class SealVerifyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.tmp.name) / "test.db")
        self.repo = Repository(self.db_path)
        self.service = Service(self.repo)
        self.item = self.service.create_item(
            {"title": "seal item", "description": "seal flow", "severity": "exceedance",
             "quantity": 12, "threshold": 6, "external_ref": "SEAL-1"},
            "creator", "operator")

    def tearDown(self):
        self.repo.close()
        self.tmp.cleanup()

    def _last_event(self):
        events = self.repo.list_audit()
        return events[-1]

    def test_seal_captures_chain_tail(self):
        before = self._last_event()
        seal = self.service.seal_chain({"request_no": "REQ-1"}, "officer", "compliance_officer")
        self.assertEqual(seal["request_no"], "REQ-1")
        self.assertEqual(seal["tail_event_id"], before["id"])
        self.assertEqual(seal["tail_hash"], before["entry_hash"])
        self.assertEqual(seal["sealed_by"], "officer")
        self.assertTrue(seal["sealed_at"])
        # the seal itself appended an audit event, but the credential still
        # references the tail as it was before sealing
        after = self._last_event()
        self.assertGreater(after["id"], before["id"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_seal_is_idempotent_returns_first_result(self):
        first = self.service.seal_chain({"request_no": "REQ-2"}, "officer", "compliance_officer")
        # more events arrive between the two requests
        self.service.add_record(self.item["id"], {"kind": "evidence", "detail": "d1",
                                                  "status": "open", "external_ref": "E-1"},
                                "recorder", "operator")
        second = self.service.seal_chain({"request_no": "REQ-2"}, "officer", "compliance_officer")
        self.assertEqual(first["id"], second["id"])
        self.assertEqual(first["tail_event_id"], second["tail_event_id"])
        self.assertEqual(first["tail_hash"], second["tail_hash"])
        self.assertEqual(first["sealed_at"], second["sealed_at"])
        # only one credential exists for the request number
        self.assertEqual(len([s for s in self.repo.list_seals() if s["request_no"] == "REQ-2"]), 1)

    def test_concurrent_seal_same_request_no_keeps_one(self):
        results = []
        errors = []
        barrier = threading.Barrier(4)

        def worker():
            try:
                barrier.wait()
                results.append(self.service.seal_chain({"request_no": "REQ-RACE"}, "officer",
                                                       "compliance_officer"))
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 4)
        ids = {r["id"] for r in results}
        self.assertEqual(len(ids), 1)
        seals = [s for s in self.repo.list_seals() if s["request_no"] == "REQ-RACE"]
        self.assertEqual(len(seals), 1)
        # the single credential must match the real chain tail
        seal = seals[0]
        events = self.repo.list_audit()
        self.assertEqual(seal["tail_event_id"], events[seal["tail_event_id"] - 1]["id"])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_seal_permission(self):
        for role in ("operator", "viewer", "director"):
            with self.assertRaises(PermissionDenied):
                self.service.seal_chain({"request_no": "REQ-X"}, "actor", role)
        # compliance officer is allowed
        self.service.seal_chain({"request_no": "REQ-OK"}, "officer", "compliance_officer")

    def test_verify_shows_lag_after_new_events(self):
        seal = self.service.seal_chain({"request_no": "REQ-3"}, "officer", "compliance_officer")
        self.service.add_record(self.item["id"], {"kind": "evidence", "detail": "d1",
                                                  "status": "open", "external_ref": "E-2"},
                                "recorder", "operator")
        self.service.add_record(self.item["id"], {"kind": "evidence", "detail": "d2",
                                                  "status": "open", "external_ref": "E-3"},
                                "recorder", "operator")
        report = self.service.verify_chain("director", "REQ-3")
        self.assertTrue(report["valid"])
        self.assertTrue(report["chain_valid"])
        self.assertTrue(report["seal_valid"])
        self.assertIsNone(report["breakpoint"])
        self.assertEqual(report["seal"]["id"], seal["id"])
        # seal event + 2 record events were appended after the captured tail
        self.assertEqual(report["lag"], 3)

    def test_verify_detects_tampering_and_first_breakpoint(self):
        self.service.seal_chain({"request_no": "REQ-4"}, "officer", "compliance_officer")
        # tamper with an early audit event directly in the DB
        conn = sqlite3.connect(self.db_path)
        try:
            early = conn.execute("SELECT id FROM audit_events ORDER BY id LIMIT 1 OFFSET 1").fetchone()
            tampered_id = early[0]
            conn.execute("UPDATE audit_events SET actor=? WHERE id=?", ("evil", tampered_id))
            conn.commit()
        finally:
            conn.close()
        report = self.service.verify_chain("director", "REQ-4")
        self.assertFalse(report["valid"])
        self.assertFalse(report["chain_valid"])
        self.assertEqual(report["breakpoint"]["event_id"], tampered_id)
        self.assertEqual(report["breakpoint"]["reason"], "hash_mismatch")

    def test_verify_detects_rollback_and_points_to_missing_tail(self):
        seal = self.service.seal_chain({"request_no": "REQ-5"}, "officer", "compliance_officer")
        # externally restore the DB to before the seal: drop the tail event and
        # everything after it, while the seal credential itself survives
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM audit_events WHERE id>=?", (seal["tail_event_id"],))
            conn.commit()
        finally:
            conn.close()
        report = self.service.verify_chain("director", "REQ-5")
        self.assertFalse(report["valid"])
        self.assertTrue(report["chain_valid"])
        self.assertFalse(report["seal_valid"])
        self.assertEqual(report["breakpoint"]["event_id"], seal["tail_event_id"])
        self.assertEqual(report["breakpoint"]["reason"], "seal_tail_missing")

    def test_verify_permission(self):
        self.service.seal_chain({"request_no": "REQ-6"}, "officer", "compliance_officer")
        for role in ("operator", "compliance_officer"):
            with self.assertRaises(PermissionDenied):
                self.service.verify_chain(role, "REQ-6")
        for role in ("director", "viewer"):
            report = self.service.verify_chain(role, "REQ-6")
            self.assertTrue(report["valid"])

    def test_operator_reads_only_own_events(self):
        self.service.add_record(self.item["id"], {"kind": "evidence", "detail": "mine",
                                                  "status": "open", "external_ref": "E-4"},
                                "alice", "operator")
        self.service.add_record(self.item["id"], {"kind": "evidence", "detail": "theirs",
                                                  "status": "open", "external_ref": "E-5"},
                                "bob", "operator")
        alice_events = self.service.audit("operator", actor="alice")
        self.assertTrue(alice_events)
        self.assertTrue(all(e["actor"] == "alice" for e in alice_events))
        bob_events = self.service.audit("operator", actor="bob")
        self.assertTrue(all(e["actor"] == "bob" for e in bob_events))
        # a director/auditor sees everything
        all_events = self.service.audit("viewer")
        self.assertGreater(len(all_events), len(alice_events))

    def test_failed_seal_leaves_no_half_record(self):
        before_count = len(self.repo.list_audit())
        with self.assertRaises(ValidationError):
            self.service.seal_chain({"request_no": "  "}, "officer", "compliance_officer")
        with self.assertRaises(ValidationError):
            self.service.seal_chain({}, "officer", "compliance_officer")
        self.assertEqual(len(self.repo.list_audit()), before_count)
        self.assertEqual(self.repo.list_seals(), [])
        self.assertTrue(self.repo.verify_audit_chain())

    def test_seal_then_transition_keeps_chain_valid(self):
        self.service.seal_chain({"request_no": "REQ-7"}, "officer", "compliance_officer")
        current = self.item
        for target in STATES[1:]:
            current = self.service.transition(current["id"], target, current["version"],
                                              "reviewer", TRANSITION_ROLES[target][0])
        self.assertEqual(current["status"], STATES[-1])
        self.assertTrue(self.repo.verify_audit_chain())
        report = self.service.verify_chain("viewer", "REQ-7")
        self.assertTrue(report["valid"])
        self.assertGreater(report["lag"], 0)


if __name__ == "__main__":
    unittest.main()
