"""SQLite data layer for SentinelSOC.

Design notes
------------
SentinelSOC is a single-host agent with a handful of background
collector threads, a detection loop, and a FastAPI server all touching
the same database. Rather than share one long-lived connection across
threads, DBManager opens a short-lived connection per call (WAL mode +
a busy timeout), which keeps the code simple and is more than fast
enough at the write volumes this agent produces (telemetry events, not
a high-frequency trading feed).

All timestamps are stored as ISO-8601 UTC strings so they sort
correctly as text and are human-readable in the raw .db file.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source TEXT NOT NULL,
    event_type TEXT,
    timestamp TEXT NOT NULL,
    host TEXT,
    details_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    category TEXT,
    mitre_technique TEXT,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'NEW',
    title TEXT NOT NULL,
    description TEXT,
    source_event_id INTEGER,
    pid INTEGER,
    process_name TEXT,
    account_name TEXT,
    remote_addr TEXT,
    file_path TEXT,
    incident_id INTEGER,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'OPEN',
    risk_score INTEGER NOT NULL,
    alert_count INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processes_seen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER NOT NULL,
    name TEXT,
    exe_path TEXT,
    cmdline TEXT,
    username TEXT,
    ppid INTEGER,
    parent_name TEXT,
    create_time TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT DEFAULT 'running'
);
CREATE INDEX IF NOT EXISTS idx_proc_pid_ct ON processes_seen(pid, create_time);
CREATE INDEX IF NOT EXISTS idx_proc_last_seen ON processes_seen(last_seen);

CREATE TABLE IF NOT EXISTS network_connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pid INTEGER,
    process_name TEXT,
    local_addr TEXT,
    local_port INTEGER,
    remote_addr TEXT,
    remote_port INTEGER,
    protocol TEXT,
    status TEXT,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_netconn_timestamp ON network_connections(timestamp);

CREATE TABLE IF NOT EXISTS response_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type TEXT NOT NULL,
    target TEXT NOT NULL,
    target_meta_json TEXT,
    reason TEXT,
    alert_id INTEGER,
    status TEXT NOT NULL DEFAULT 'PENDING',
    requested_by TEXT,
    approved_by TEXT,
    notes TEXT,
    result_message TEXT,
    created_at TEXT NOT NULL,
    decided_at TEXT,
    executed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_response_status ON response_actions(status);

CREATE TABLE IF NOT EXISTS quarantine_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id INTEGER NOT NULL,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256 TEXT,
    size_bytes INTEGER,
    quarantined_at TEXT NOT NULL,
    restored INTEGER DEFAULT 0,
    restored_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT,
    action TEXT NOT NULL,
    target TEXT,
    details TEXT,
    timestamp TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);

CREATE TABLE IF NOT EXISTS collector_state (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class DBManager:
    def __init__(self, config):
        self.path = config.resolve_path("database.path", "./data/sentinelsoc.db")
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._write_lock = threading.Lock()
        self.init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=30000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn

    def init_schema(self) -> None:
        with self._write_lock:
            conn = self._connect()
            try:
                conn.executescript(SCHEMA)
                conn.commit()
            finally:
                conn.close()

    # ---------------------------------------------------------------- events
    def insert_event(self, record: dict) -> int:
        with self._write_lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO events (source, event_type, timestamp, host, "
                    "details_json, created_at) VALUES (?,?,?,?,?,?)",
                    (
                        record.get("source"),
                        record.get("event_type"),
                        record.get("timestamp") or now_iso(),
                        record.get("host"),
                        json.dumps(record, default=str),
                        now_iso(),
                    ),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def get_events(
        self,
        source: Optional[str] = None,
        event_type: Optional[str] = None,
        since_seconds: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        conn = self._connect()
        try:
            clauses, params = [], []
            if source:
                clauses.append("source = ?")
                params.append(source)
            if event_type:
                clauses.append("event_type = ?")
                params.append(event_type)
            if since_seconds:
                clauses.append("timestamp >= datetime('now', ?)")
                params.append(f"-{int(since_seconds)} seconds")
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = conn.execute(
                f"SELECT * FROM events {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["details"] = json.loads(d.pop("details_json"))
                except (TypeError, ValueError):
                    d["details"] = {}
                out.append(d)
            return out
        finally:
            conn.close()

    # ---------------------------------------------------------------- alerts
    def insert_alert(self, alert: dict) -> int:
        with self._write_lock:
            conn = self._connect()
            try:
                ts = now_iso()
                cur = conn.execute(
                    "INSERT INTO alerts (rule_id, rule_name, category, mitre_technique, "
                    "severity, risk_score, status, title, description, source_event_id, "
                    "pid, process_name, account_name, remote_addr, file_path, timestamp, "
                    "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        alert["rule_id"],
                        alert["rule_name"],
                        alert.get("category"),
                        alert.get("mitre_technique"),
                        alert["severity"],
                        int(alert["risk_score"]),
                        alert.get("status", "NEW"),
                        alert["title"],
                        alert.get("description"),
                        alert.get("source_event_id"),
                        alert.get("pid"),
                        alert.get("process_name"),
                        alert.get("account_name"),
                        alert.get("remote_addr"),
                        alert.get("file_path"),
                        alert.get("timestamp") or ts,
                        ts,
                        ts,
                    ),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def get_alert(self, alert_id: int) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_alerts(
        self,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        incident_id: Optional[int] = None,
        without_incident: bool = False,
        since_seconds: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        conn = self._connect()
        try:
            clauses, params = [], []
            if status:
                clauses.append("status = ?")
                params.append(status)
            if severity:
                clauses.append("severity = ?")
                params.append(severity)
            if incident_id is not None:
                clauses.append("incident_id = ?")
                params.append(incident_id)
            if without_incident:
                clauses.append("incident_id IS NULL")
            if since_seconds:
                clauses.append("timestamp >= datetime('now', ?)")
                params.append(f"-{int(since_seconds)} seconds")
            where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
            rows = conn.execute(
                f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ? OFFSET ?",
                (*params, limit, offset),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def update_alert(self, alert_id: int, **fields) -> None:
        if not fields:
            return
        fields["updated_at"] = now_iso()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    f"UPDATE alerts SET {set_clause} WHERE id = ?",
                    (*fields.values(), alert_id),
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------ incidents
    def create_incident(self, title: str, risk_score: int, timestamp: str) -> int:
        with self._write_lock:
            conn = self._connect()
            try:
                ts = now_iso()
                cur = conn.execute(
                    "INSERT INTO incidents (title, status, risk_score, alert_count, "
                    "first_seen, last_seen, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                    (title, "OPEN", risk_score, 0, timestamp, timestamp, ts, ts),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def update_incident(self, incident_id: int, **fields) -> None:
        if not fields:
            return
        fields["updated_at"] = now_iso()
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    f"UPDATE incidents SET {set_clause} WHERE id = ?",
                    (*fields.values(), incident_id),
                )
                conn.commit()
            finally:
                conn.close()

    def get_incidents(self, status: Optional[str] = None, limit: int = 50) -> list[dict]:
        conn = self._connect()
        try:
            if status:
                rows = conn.execute(
                    "SELECT * FROM incidents WHERE status = ? ORDER BY id DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM incidents ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ----------------------------------------------------------- processes
    def upsert_process(self, record: dict) -> None:
        with self._write_lock:
            conn = self._connect()
            try:
                existing = conn.execute(
                    "SELECT id FROM processes_seen WHERE pid = ? AND create_time = ?",
                    (record.get("pid"), str(record.get("create_time"))),
                ).fetchone()
                ts = now_iso()
                if existing:
                    conn.execute(
                        "UPDATE processes_seen SET last_seen = ?, status = ? WHERE id = ?",
                        (ts, record.get("status", "running"), existing["id"]),
                    )
                else:
                    conn.execute(
                        "INSERT INTO processes_seen (pid, name, exe_path, cmdline, username, "
                        "ppid, parent_name, create_time, first_seen, last_seen, status) "
                        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            record.get("pid"),
                            record.get("name"),
                            record.get("exe_path"),
                            record.get("cmdline"),
                            record.get("username"),
                            record.get("ppid"),
                            record.get("parent_name"),
                            str(record.get("create_time")),
                            ts,
                            ts,
                            record.get("status", "running"),
                        ),
                    )
                conn.commit()
            finally:
                conn.close()

    def get_processes_history(self, limit: int = 200) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM processes_seen ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # --------------------------------------------------------------- network
    def insert_network_connection(self, record: dict) -> int:
        with self._write_lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO network_connections (pid, process_name, local_addr, "
                    "local_port, remote_addr, remote_port, protocol, status, timestamp) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        record.get("pid"),
                        record.get("process_name"),
                        record.get("local_addr"),
                        record.get("local_port"),
                        record.get("remote_addr"),
                        record.get("remote_port"),
                        record.get("protocol"),
                        record.get("status"),
                        record.get("timestamp") or now_iso(),
                    ),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def get_network_history(self, limit: int = 200) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM network_connections ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ---------------------------------------------------------- response
    def create_response_action(
        self,
        action_type: str,
        target: str,
        reason: str,
        requested_by: str,
        alert_id: Optional[int] = None,
        target_meta: Optional[dict] = None,
    ) -> int:
        with self._write_lock:
            conn = self._connect()
            try:
                ts = now_iso()
                cur = conn.execute(
                    "INSERT INTO response_actions (action_type, target, target_meta_json, "
                    "reason, alert_id, status, requested_by, created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        action_type,
                        str(target),
                        json.dumps(target_meta or {}, default=str),
                        reason,
                        alert_id,
                        "PENDING",
                        requested_by,
                        ts,
                    ),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def get_response_action(self, action_id: int) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM response_actions WHERE id = ?", (action_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_response_actions(self, status: Optional[str] = None, limit: int = 100) -> list[dict]:
        conn = self._connect()
        try:
            if status:
                rows = conn.execute(
                    "SELECT * FROM response_actions WHERE status = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM response_actions ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def update_response_action(self, action_id: int, **fields) -> None:
        if not fields:
            return
        set_clause = ", ".join(f"{k} = ?" for k in fields)
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    f"UPDATE response_actions SET {set_clause} WHERE id = ?",
                    (*fields.values(), action_id),
                )
                conn.commit()
            finally:
                conn.close()

    def create_quarantine_item(
        self, action_id: int, original_path: str, quarantine_path: str, sha256: str, size_bytes: int
    ) -> int:
        with self._write_lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    "INSERT INTO quarantine_items (action_id, original_path, quarantine_path, "
                    "sha256, size_bytes, quarantined_at) VALUES (?,?,?,?,?,?)",
                    (action_id, original_path, quarantine_path, sha256, size_bytes, now_iso()),
                )
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    def get_quarantine_items(self, limit: int = 100) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM quarantine_items ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def get_quarantine_item(self, item_id: int) -> Optional[dict]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT * FROM quarantine_items WHERE id = ?", (item_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def mark_quarantine_restored(self, item_id: int) -> None:
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "UPDATE quarantine_items SET restored = 1, restored_at = ? WHERE id = ?",
                    (now_iso(), item_id),
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------- audit
    def write_audit(self, actor: str, action: str, target: str = "", details: str = "") -> None:
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO audit_log (actor, action, target, details, timestamp) "
                    "VALUES (?,?,?,?,?)",
                    (actor, action, target, details, now_iso()),
                )
                conn.commit()
            finally:
                conn.close()

    def get_audit_log(self, limit: int = 200) -> list[dict]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    # ------------------------------------------------------- collector state
    def get_state(self, key: str) -> Optional[str]:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else None
        finally:
            conn.close()

    def set_state(self, key: str, value: str) -> None:
        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute(
                    "INSERT INTO collector_state (key, value) VALUES (?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, value),
                )
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------- stats
    def counts_by_severity(self, since_seconds: int = 86400) -> dict[str, int]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts "
                "WHERE timestamp >= datetime('now', ?) GROUP BY severity",
                (f"-{since_seconds} seconds",),
            ).fetchall()
            return {r["severity"]: r["n"] for r in rows}
        finally:
            conn.close()

    def pending_response_count(self) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM response_actions WHERE status = 'PENDING'"
            ).fetchone()
            return row["n"] if row else 0
        finally:
            conn.close()
