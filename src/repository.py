from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional

from .audit import make_entry, utc_now
from .domain import ConflictError, NotFoundError
from .rules import ID_PREFIX, STATES


class Repository:
    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self._create_schema()

    def _create_schema(self) -> None:
        statuses = ",".join("'" + s.replace("'", "''") + "'" for s in STATES)
        with self.conn:
            self.conn.executescript(f"""
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    quantity REAL NOT NULL DEFAULT 0,
                    threshold REAL NOT NULL DEFAULT 1,
                    status TEXT NOT NULL CHECK(status IN ({statuses})),
                    version INTEGER NOT NULL DEFAULT 1,
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ux_items_external_ref
                    ON items(external_ref) WHERE external_ref IS NOT NULL;
                CREATE TABLE IF NOT EXISTS records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
                    kind TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open'
                        CHECK(status IN ('open','closed')),
                    external_ref TEXT,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(item_id, external_ref)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    entity_id INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    entry_hash TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_seals (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_no TEXT NOT NULL UNIQUE,
                    tail_event_id INTEGER NOT NULL,
                    tail_hash TEXT NOT NULL,
                    event_count INTEGER NOT NULL,
                    sealed_by TEXT NOT NULL,
                    sealed_at TEXT NOT NULL
                );
            """)

    @staticmethod
    def _item(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def create_item(self, title: str, description: str, severity: str,
                    quantity: float, threshold: float, external_ref: Optional[str],
                    actor: str) -> Dict[str, Any]:
        now = utc_now()
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO items(title, description, severity, quantity, threshold,
                       status, version, external_ref, created_by, created_at, updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                    (title, description, severity, quantity, threshold, STATES[0], 1,
                     external_ref, actor, now, now),
                )
                item_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("external_ref已存在") from exc
        return self.get_item(item_id)

    def get_item(self, item_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if row is None:
            raise NotFoundError("项目不存在")
        return self._item(row)

    def list_items(self, status: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM items"
        params: tuple = ()
        if status:
            sql += " WHERE status=?"
            params = (status,)
        sql += " ORDER BY id DESC"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [self._item(row) for row in rows]

    def transition_item(self, item_id: int, target: str, expected_version: int,
                        actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            cur = self.conn.execute(
                """UPDATE items SET status=?, version=version+1, updated_at=?
                   WHERE id=? AND version=?""",
                (target, now, item_id, expected_version),
            )
            if cur.rowcount == 0:
                exists = self.conn.execute("SELECT 1 FROM items WHERE id=?", (item_id,)).fetchone()
                if exists is None:
                    raise NotFoundError("项目不存在")
                raise ConflictError("版本冲突，请刷新后重试")
        return self.get_item(item_id)

    def add_record(self, item_id: int, kind: str, detail: str, status: str,
                   external_ref: Optional[str], actor: str) -> Dict[str, Any]:
        now = utc_now()
        self.get_item(item_id)
        try:
            with self._lock, self.conn:
                cur = self.conn.execute(
                    """INSERT INTO records(item_id, kind, detail, status, external_ref,
                       created_by, created_at) VALUES(?,?,?,?,?,?,?)""",
                    (item_id, kind, detail, status, external_ref, actor, now),
                )
                record_id = int(cur.lastrowid)
        except sqlite3.IntegrityError as exc:
            raise ConflictError("记录唯一标识已存在") from exc
        with self._lock:
            row = self.conn.execute("SELECT * FROM records WHERE id=?", (record_id,)).fetchone()
        return dict(row)

    def list_records(self, item_id: int) -> List[Dict[str, Any]]:
        self.get_item(item_id)
        with self._lock:
            rows = self.conn.execute(
                "SELECT * FROM records WHERE item_id=? ORDER BY id", (item_id,)
            ).fetchall()
        return [dict(row) for row in rows]

    def open_record_count(self, item_id: int) -> int:
        with self._lock:
            row = self.conn.execute(
                "SELECT COUNT(*) AS n FROM records WHERE item_id=? AND status='open'",
                (item_id,),
            ).fetchone()
        return int(row["n"])

    def append_audit(self, action: str, entity_type: str, entity_id: int,
                     actor: str, detail: dict) -> Dict[str, Any]:
        with self._lock, self.conn:
            row = self.conn.execute(
                "SELECT entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            previous = row["entry_hash"] if row else "GENESIS"
            event = make_entry(action, entity_type, entity_id, actor, detail, previous)
            cur = self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
            event_id = int(cur.lastrowid)
        event["id"] = event_id
        return event

    def list_audit(self, entity_id: Optional[int] = None,
                   actor: Optional[str] = None) -> List[Dict[str, Any]]:
        sql = "SELECT * FROM audit_events"
        params: list = []
        conditions: list = []
        if entity_id is not None:
            conditions.append("entity_id=?")
            params.append(entity_id)
        if actor is not None:
            conditions.append("actor=?")
            params.append(actor)
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)
        sql += " ORDER BY id"
        with self._lock:
            rows = self.conn.execute(sql, params).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["detail"] = json.loads(item["detail"])
            result.append(item)
        return result

    def verify_audit_chain(self) -> bool:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
        previous = "GENESIS"
        for row in rows:
            if row["previous_hash"] != previous:
                return False
            payload = {
                "action": row["action"], "entity_type": row["entity_type"],
                "entity_id": row["entity_id"], "actor": row["actor"],
                "detail": json.loads(row["detail"]), "created_at": row["created_at"],
            }
            if calculate_hash(previous, payload) != row["entry_hash"]:
                return False
            previous = row["entry_hash"]
        return True

    @staticmethod
    def _seal_row(row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": row["id"],
            "request_no": row["request_no"],
            "tail_event_id": row["tail_event_id"],
            "tail_hash": row["tail_hash"],
            "event_count": row["event_count"],
            "sealed_by": row["sealed_by"],
            "sealed_at": row["sealed_at"],
        }

    def create_seal(self, request_no: str, actor: str) -> Dict[str, Any]:
        now = utc_now()
        with self._lock, self.conn:
            existing = self.conn.execute(
                "SELECT * FROM audit_seals WHERE request_no=?", (request_no,)
            ).fetchone()
            if existing is not None:
                return self._seal_row(existing)
            tail = self.conn.execute(
                "SELECT id, entry_hash FROM audit_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if tail is None:
                tail_event_id = 0
                tail_hash = "GENESIS"
            else:
                tail_event_id = int(tail["id"])
                tail_hash = tail["entry_hash"]
            event_count = int(self.conn.execute(
                "SELECT COUNT(*) AS n FROM audit_events"
            ).fetchone()["n"])
            try:
                cur = self.conn.execute(
                    """INSERT INTO audit_seals(request_no, tail_event_id, tail_hash,
                       event_count, sealed_by, sealed_at) VALUES(?,?,?,?,?,?)""",
                    (request_no, tail_event_id, tail_hash, event_count, actor, now),
                )
                seal_id = int(cur.lastrowid)
            except sqlite3.IntegrityError:
                winner = self.conn.execute(
                    "SELECT * FROM audit_seals WHERE request_no=?", (request_no,)
                ).fetchone()
                return self._seal_row(winner)
            event = make_entry(
                "seal", "audit_chain", seal_id, actor,
                {"request_no": request_no, "tail_event_id": tail_event_id,
                 "tail_hash": tail_hash},
                tail_hash,
            )
            self.conn.execute(
                """INSERT INTO audit_events(action, entity_type, entity_id, actor, detail,
                   previous_hash, entry_hash, created_at) VALUES(?,?,?,?,?,?,?,?)""",
                (event["action"], event["entity_type"], event["entity_id"], event["actor"],
                 json.dumps(event["detail"], ensure_ascii=False, sort_keys=True),
                 event["previous_hash"], event["entry_hash"], event["created_at"]),
            )
        return self.get_seal_by_id(seal_id)

    def get_seal_by_id(self, seal_id: int) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM audit_seals WHERE id=?", (seal_id,)
            ).fetchone()
        if row is None:
            raise NotFoundError("封存凭据不存在")
        return self._seal_row(row)

    def get_seal(self, request_no: str) -> Dict[str, Any]:
        with self._lock:
            row = self.conn.execute(
                "SELECT * FROM audit_seals WHERE request_no=?", (request_no,)
            ).fetchone()
        if row is None:
            raise NotFoundError("封存凭据不存在")
        return self._seal_row(row)

    def list_seals(self) -> List[Dict[str, Any]]:
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_seals ORDER BY id").fetchall()
        return [self._seal_row(row) for row in rows]

    def verify_seal(self, request_no: Optional[str] = None) -> Dict[str, Any]:
        from .audit import calculate_hash
        with self._lock:
            rows = self.conn.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
            events: List[Dict[str, Any]] = []
            for row in rows:
                item = dict(row)
                item["detail"] = json.loads(item["detail"])
                events.append(item)

            chain_valid = True
            breakpoint: Optional[Dict[str, Any]] = None
            previous = "GENESIS"
            for event in events:
                if event["previous_hash"] != previous:
                    chain_valid = False
                    breakpoint = {
                        "event_id": event["id"],
                        "reason": "previous_hash_mismatch",
                        "expected_hash": previous,
                        "actual_hash": event["previous_hash"],
                    }
                    break
                payload = {
                    "action": event["action"], "entity_type": event["entity_type"],
                    "entity_id": event["entity_id"], "actor": event["actor"],
                    "detail": event["detail"], "created_at": event["created_at"],
                }
                calculated = calculate_hash(previous, payload)
                if calculated != event["entry_hash"]:
                    chain_valid = False
                    breakpoint = {
                        "event_id": event["id"],
                        "reason": "hash_mismatch",
                        "expected_hash": calculated,
                        "actual_hash": event["entry_hash"],
                    }
                    break
                previous = event["entry_hash"]

            if request_no is not None:
                seal_row = self.conn.execute(
                    "SELECT * FROM audit_seals WHERE request_no=?", (request_no,)
                ).fetchone()
            else:
                seal_row = self.conn.execute(
                    "SELECT * FROM audit_seals ORDER BY id DESC LIMIT 1"
                ).fetchone()
            seal = self._seal_row(seal_row) if seal_row is not None else None

            seal_valid = True
            lag: Optional[int] = None
            if seal is not None:
                tail_event = next(
                    (e for e in events if e["id"] == seal["tail_event_id"]), None
                )
                if tail_event is None:
                    seal_valid = False
                    if breakpoint is None:
                        breakpoint = {
                            "event_id": seal["tail_event_id"],
                            "reason": "seal_tail_missing",
                            "expected_hash": seal["tail_hash"],
                            "actual_hash": None,
                        }
                elif tail_event["entry_hash"] != seal["tail_hash"]:
                    seal_valid = False
                    if breakpoint is None:
                        breakpoint = {
                            "event_id": seal["tail_event_id"],
                            "reason": "seal_tail_hash_mismatch",
                            "expected_hash": seal["tail_hash"],
                            "actual_hash": tail_event["entry_hash"],
                        }
                else:
                    lag = sum(1 for e in events if e["id"] > seal["tail_event_id"])

        return {
            "valid": chain_valid and seal_valid,
            "chain_valid": chain_valid,
            "seal_valid": seal_valid,
            "seal": seal,
            "lag": lag,
            "breakpoint": breakpoint,
            "total_events": len(events),
        }

    def close(self) -> None:
        with self._lock:
            self.conn.close()
