from __future__ import annotations

from typing import Any, Dict, Optional

from .audit import calculate_hash
from .domain import (NotFoundError, VerificationConflict, ensure_role,
                     normalize_severity, require_number, require_positive_int,
                     require_text)
from .repository import Repository
from .rules import (AUDIT_ROLES, AUDIT_SCOPED_ROLES, CREATE_ROLES, ENTITY,
                    RECORD_ROLES, SEAL_ROLES, TITLE, VERIFY_ROLES, VIEW_ROLES,
                    completion_blockers, escalation_required, priority_score,
                    response_deadline_hours, role_for_transition,
                    validate_transition)


class Service:
    def __init__(self, repository: Repository):
        self.repository = repository

    def _view(self, role: str) -> None:
        ensure_role(role, VIEW_ROLES)

    def create_item(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, CREATE_ROLES)
        actor = require_text(actor, "actor", 100)
        title = require_text(payload.get("title"), "title", 200)
        description = require_text(payload.get("description"), "description")
        severity = normalize_severity(payload.get("severity"))
        quantity = require_number(payload.get("quantity", 0), "quantity")
        threshold = require_number(payload.get("threshold", 1), "threshold", 0.000001)
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        item = self.repository.create_item(title, description, severity, quantity,
                                           threshold, external_ref, actor)
        self.repository.append_audit("create", ENTITY, item["id"], actor, {
            "title": title, "severity": severity, "quantity": quantity,
            "priority": priority_score(severity, quantity, threshold),
        })
        return self.enrich(item)

    def add_record(self, item_id: int, payload: Dict[str, Any], actor: str,
                   role: str) -> Dict[str, Any]:
        ensure_role(role, RECORD_ROLES)
        actor = require_text(actor, "actor", 100)
        kind = require_text(payload.get("kind"), "kind", 100)
        detail = require_text(payload.get("detail"), "detail")
        status = payload.get("status", "open")
        if status not in ("open", "closed"):
            raise ValueError("status必须是open或closed")
        external_ref = payload.get("external_ref")
        if external_ref is not None:
            external_ref = require_text(external_ref, "external_ref", 100)
        record = self.repository.add_record(item_id, kind, detail, status,
                                            external_ref, actor)
        self.repository.append_audit("record", ENTITY, item_id, actor, {
            "record_id": record["id"], "kind": kind, "status": status,
        })
        return record

    def transition(self, item_id: int, target: str, expected_version: int,
                   actor: str, role: str) -> Dict[str, Any]:
        actor = require_text(actor, "actor", 100)
        item = self.repository.get_item(item_id)
        validate_transition(item["status"], target)
        ensure_role(role, role_for_transition(target))
        if not isinstance(expected_version, int) or expected_version < 1:
            raise ValueError("expected_version必须是正整数")
        blockers = completion_blockers(target, self.repository.open_record_count(item_id))
        if blockers:
            from .domain import ConflictError
            raise ConflictError("；".join(blockers))
        updated = self.repository.transition_item(item_id, target, expected_version, actor)
        self.repository.append_audit("transition", ENTITY, item_id, actor, {
            "from": item["status"], "to": target,
            "escalation_required": escalation_required(
                item["severity"], item["quantity"], item["threshold"]),
        })
        return self.enrich(updated)

    def get_item(self, item_id: int, role: str) -> Dict[str, Any]:
        self._view(role)
        return self.enrich(self.repository.get_item(item_id))

    def list_items(self, role: str, status: Optional[str] = None) -> list:
        self._view(role)
        return [self.enrich(item) for item in self.repository.list_items(status)]

    def list_records(self, item_id: int, role: str) -> list:
        self._view(role)
        return self.repository.list_records(item_id)

    def audit(self, role: str, item_id: Optional[int] = None,
              actor: Optional[str] = None) -> list:
        # 主管/审计员/合规员读全链；运行人员和现场设备只能读取自己的事件
        ensure_role(role, AUDIT_ROLES | SEAL_ROLES | AUDIT_SCOPED_ROLES)
        scoped_actor = None
        if role in AUDIT_SCOPED_ROLES:
            scoped_actor = require_text(actor or "", "actor", 100)
        return self.repository.list_audit(item_id, scoped_actor)

    def seal_audit(self, payload: Dict[str, Any], actor: str, role: str) -> Dict[str, Any]:
        ensure_role(role, SEAL_ROLES)
        actor = require_text(actor, "actor", 100)
        request_id = require_text(payload.get("request_id"), "request_id", 100)
        # 重复请求编号返回首次封存结果；并发封存只落一份，且凭据与链尾一致
        return self.repository.seal_audit_chain(request_id, actor)

    def verify_audit(self, payload: Dict[str, Any], role: str) -> Dict[str, Any]:
        ensure_role(role, VERIFY_ROLES)
        request_id = payload.get("request_id")
        if request_id is not None:
            request_id = require_text(request_id, "request_id", 100)
        seal = self.repository.get_seal(request_id) if request_id else None
        if request_id is not None and seal is None:
            raise NotFoundError("封存凭据不存在")
        if seal is not None:
            tail_event_id = int(seal["tail_event_id"])
            tail_hash = seal["tail_hash"]
            sealed_at = seal["sealed_at"]
        else:
            # 凭据可能保存在数据库之外（监管带回来核验）：按凭据正文定位
            tail_event_id = require_positive_int(payload.get("tail_event_id"), "tail_event_id")
            tail_hash = require_text(payload.get("tail_hash"), "tail_hash", 128)
            sealed_at = require_text(payload.get("sealed_at"), "sealed_at", 100)
        sealed = {
            "request_id": request_id, "sealed_at": sealed_at,
            "tail_event_id": tail_event_id, "tail_hash": tail_hash,
        }
        events = self.repository.list_audit()
        count = len(events)
        present_ids = {event["id"] for event in events}
        if tail_event_id not in present_ids:
            # 封存点事件已不在链上：恢复到更早快照（截断）或封存点被定向删除
            truncated = count == 0 or max(present_ids) < tail_event_id
            self._raise_conflict("审计链在封存点之前被截断，数据库疑似被外部恢复"
                                 if truncated else "封存点事件缺失，数据库疑似被外部恢复", {
                "reason": "truncated" if truncated else "tail_missing",
                "first_breakpoint": {
                    "type": "tail_missing", "ordinal": count + 1,
                    "expected_event_id": tail_event_id,
                },
            }, sealed, count)
        previous = "GENESIS"
        first_breakpoint: Optional[Dict[str, Any]] = None
        sealed_entry: Optional[Dict[str, Any]] = None
        for ordinal, event in enumerate(events, start=1):
            if event["id"] != ordinal:
                first_breakpoint = {
                    "type": "event_missing", "ordinal": ordinal,
                    "expected_event_id": ordinal, "actual_event_id": event["id"],
                }
                break
            body = {
                "action": event["action"], "entity_type": event["entity_type"],
                "entity_id": event["entity_id"], "actor": event["actor"],
                "detail": event["detail"], "created_at": event["created_at"],
            }
            if event["previous_hash"] != previous:
                first_breakpoint = {
                    "type": "previous_hash_mismatch", "ordinal": ordinal,
                    "event_id": event["id"], "expected_previous_hash": previous,
                    "actual_previous_hash": event["previous_hash"],
                }
                break
            if calculate_hash(previous, body) != event["entry_hash"]:
                first_breakpoint = {
                    "type": "hash_mismatch", "ordinal": ordinal,
                    "event_id": event["id"], "expected_event_hash": calculate_hash(previous, body),
                    "actual_event_hash": event["entry_hash"],
                }
                break
            if ordinal == tail_event_id:
                sealed_entry = event
            previous = event["entry_hash"]
        if first_breakpoint is not None:
            self._raise_conflict("审计链与封存凭据不一致，首个断点位于第"
                                 f"{first_breakpoint['ordinal']}条事件", {
                "reason": "chain_broken", "first_breakpoint": first_breakpoint,
            }, sealed, count)
        if sealed_entry is None or sealed_entry["id"] != tail_event_id:
            self._raise_conflict("封存点事件缺失，数据库疑似被外部恢复", {
                "reason": "tail_missing",
                "first_breakpoint": {
                    "type": "tail_missing", "ordinal": tail_event_id,
                    "expected_event_id": tail_event_id,
                },
            }, sealed, count)
        if sealed_entry["entry_hash"] != tail_hash:
            # 位置在、哈希不对：封存点事件被改写
            self._raise_conflict("封存点链尾哈希与凭据不一致，事件已被改写", {
                "reason": "tail_hash_mismatch",
                "first_breakpoint": {
                    "type": "tail_hash_mismatch", "ordinal": tail_event_id,
                    "event_id": tail_event_id, "expected_event_hash": tail_hash,
                    "actual_event_hash": sealed_entry["entry_hash"],
                },
            }, sealed, count)
        return {
            "status": "consistent", **sealed,
            "current_event_count": count,
            "lag": count - tail_event_id,
        }

    @staticmethod
    def _raise_conflict(message: str, info: Dict[str, Any], sealed: Dict[str, Any],
                        current_event_count: int) -> None:
        raise VerificationConflict(message, {
            "status": "conflict", **info, "sealed": sealed,
            "current_event_count": current_event_count,
        })

    @staticmethod
    def enrich(item: Dict[str, Any]) -> Dict[str, Any]:
        result = dict(item)
        result["priority"] = priority_score(
            item["severity"], item["quantity"], item["threshold"])
        result["deadline_hours"] = response_deadline_hours(
            item["severity"], item["quantity"], item["threshold"])
        result["escalation_required"] = escalation_required(
            item["severity"], item["quantity"], item["threshold"])
        return result
