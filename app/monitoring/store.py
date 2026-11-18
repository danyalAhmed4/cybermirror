"""SQLite persistence for request logs, alerts, and sessions."""
from __future__ import annotations

import csv
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Optional


_DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.db")
_lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


class MonitorStore:
    """Thin SQLite wrapper for CyberMirror request monitoring."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or _DEFAULT_DB_PATH
        self.init_db()

    @contextmanager
    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_db(self) -> None:
        """Create tables if they do not already exist."""
        with _lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    user_agent TEXT,
                    method TEXT,
                    path TEXT,
                    query_string TEXT,
                    form_values TEXT,
                    session_hash TEXT,
                    status_code INTEGER,
                    true_label TEXT DEFAULT 'unlabeled',
                    detection_ms REAL,
                    referer TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    attack_type TEXT,
                    field TEXT,
                    probability REAL,
                    action TEXT,
                    FOREIGN KEY (request_id) REFERENCES requests(id)
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_hash TEXT PRIMARY KEY,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    ips TEXT,
                    user_agents TEXT,
                    request_count INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            self._ensure_column(conn, "requests", "detection_ms", "REAL")
            self._ensure_column(conn, "requests", "referer", "TEXT")
            # Default detection mode for dashboard / runtime toggles
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?",
                ("detection_mode",),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?)",
                    ("detection_mode", "OFF"),
                )

    @staticmethod
    def _ensure_column(
        conn: sqlite3.Connection, table: str, column: str, typedef: str
    ) -> None:
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in cols:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {typedef}")

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with _lock, self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM settings WHERE key = ?",
                (key,),
            ).fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with _lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO settings (key, value) VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value
                """,
                (key, value),
            )

    def get_detection_mode(self) -> str:
        raw = (self.get_setting("detection_mode", "OFF") or "OFF").strip().upper()
        if raw not in {"OFF", "MONITOR", "BLOCK"}:
            return "OFF"
        return raw

    def set_detection_mode(self, mode: str) -> str:
        normalized = (mode or "OFF").strip().upper()
        if normalized not in {"OFF", "MONITOR", "BLOCK"}:
            raise ValueError(f"Invalid detection mode: {mode!r}")
        self.set_setting("detection_mode", normalized)
        return normalized

    def insert_request(
        self,
        *,
        source_ip: Optional[str],
        user_agent: Optional[str],
        method: str,
        path: str,
        query_string: Optional[str],
        form_values: Any,
        session_hash: Optional[str],
        status_code: Optional[int],
        true_label: str = "unlabeled",
        detection_ms: Optional[float] = None,
        referer: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> int:
        """Insert a request row and refresh the matching session aggregate."""
        ts = timestamp or _utc_now()
        form_json = json.dumps(form_values if form_values is not None else {})

        with _lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO requests (
                    timestamp, source_ip, user_agent, method, path, query_string,
                    form_values, session_hash, status_code, true_label, detection_ms,
                    referer
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ts,
                    source_ip,
                    user_agent,
                    method,
                    path,
                    query_string or "",
                    form_json,
                    session_hash,
                    status_code,
                    true_label or "unlabeled",
                    detection_ms,
                    referer,
                ),
            )
            request_id = int(cur.lastrowid)

            if session_hash:
                self._upsert_session(
                    conn,
                    session_hash=session_hash,
                    source_ip=source_ip,
                    user_agent=user_agent,
                    timestamp=ts,
                )

            return request_id

    def _upsert_session(
        self,
        conn: sqlite3.Connection,
        *,
        session_hash: str,
        source_ip: Optional[str],
        user_agent: Optional[str],
        timestamp: str,
    ) -> None:
        row = conn.execute(
            "SELECT * FROM sessions WHERE session_hash = ?",
            (session_hash,),
        ).fetchone()

        if row is None:
            ips = [source_ip] if source_ip else []
            user_agents = [user_agent] if user_agent else []
            conn.execute(
                """
                INSERT INTO sessions (
                    session_hash, first_seen, last_seen, ips, user_agents, request_count
                ) VALUES (?, ?, ?, ?, ?, 1)
                """,
                (
                    session_hash,
                    timestamp,
                    timestamp,
                    json.dumps(ips),
                    json.dumps(user_agents),
                ),
            )
            return

        ips = json.loads(row["ips"] or "[]")
        user_agents = json.loads(row["user_agents"] or "[]")
        if source_ip and source_ip not in ips:
            ips.append(source_ip)
        if user_agent and user_agent not in user_agents:
            user_agents.append(user_agent)

        conn.execute(
            """
            UPDATE sessions
            SET last_seen = ?, ips = ?, user_agents = ?, request_count = request_count + 1
            WHERE session_hash = ?
            """,
            (timestamp, json.dumps(ips), json.dumps(user_agents), session_hash),
        )

    def insert_alert(
        self,
        *,
        request_id: Optional[int],
        source_ip: Optional[str],
        attack_type: str,
        field: Optional[str],
        probability: float,
        action: str,
        timestamp: Optional[str] = None,
    ) -> int:
        """Insert an alert linked to a logged request."""
        ts = timestamp or _utc_now()
        with _lock, self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO alerts (
                    request_id, timestamp, source_ip, attack_type, field, probability, action
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    ts,
                    source_ip,
                    attack_type,
                    field,
                    probability,
                    action,
                ),
            )
            return int(cur.lastrowid)

    def export_requests_csv(
        self,
        dest_path: str,
        *,
        true_label: Optional[str] = None,
    ) -> int:
        """Export request rows to CSV. Returns the number of rows written."""
        query = "SELECT * FROM requests"
        params: tuple = ()
        if true_label is not None:
            query += " WHERE true_label = ?"
            params = (true_label,)
        query += " ORDER BY id ASC"

        with _lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        fieldnames = [
            "id",
            "timestamp",
            "source_ip",
            "user_agent",
            "method",
            "path",
            "query_string",
            "form_values",
            "session_hash",
            "status_code",
            "true_label",
            "detection_ms",
            "referer",
        ]
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)) or ".", exist_ok=True)
        with open(dest_path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for row in rows:
                writer.writerow({name: row[name] for name in fieldnames})
        return len(rows)


    def fetch_requests_for_session(self, session_hash: str) -> list[sqlite3.Row]:
        """Return request rows for a session_hash ordered by id ascending."""
        with _lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM requests
                WHERE session_hash = ?
                ORDER BY id ASC
                """,
                (session_hash,),
            ).fetchall()
            return [dict(r) for r in rows]

    def count_distinct_ips_for_session(
        self, session_hash: str, *, since_ts: Optional[str] = None
    ) -> int:
        query = "SELECT COUNT(DISTINCT source_ip) AS n FROM requests WHERE session_hash = ?"
        params: list[Any] = [session_hash]
        if since_ts:
            query += " AND timestamp >= ?"
            params.append(since_ts)
        with _lock, self._connect() as conn:
            row = conn.execute(query, params).fetchone()
            return int(row["n"] if row and row["n"] is not None else 0)

    def count_sids_for_ip_last_minute(
        self, source_ip: str, *, now_ts: Optional[str] = None
    ) -> float:
        """Distinct session_hash values from source_ip in the last 60 seconds."""
        with _lock, self._connect() as conn:
            row = conn.execute(
                """
                SELECT COUNT(DISTINCT session_hash) AS n
                FROM requests
                WHERE source_ip = ?
                  AND session_hash IS NOT NULL
                  AND timestamp >= datetime(COALESCE(?, datetime('now')), '-60 seconds')
                """,
                (source_ip, now_ts),
            ).fetchone()
            return float(row["n"] if row and row["n"] is not None else 0.0)

    # ---- Dashboard helpers ----

    def count_requests(self) -> int:
        with _lock, self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM requests").fetchone()["n"])

    def count_alerts(self) -> int:
        with _lock, self._connect() as conn:
            return int(conn.execute("SELECT COUNT(*) AS n FROM alerts").fetchone()["n"])

    def average_detection_ms(self) -> Optional[float]:
        with _lock, self._connect() as conn:
            row = conn.execute(
                "SELECT AVG(detection_ms) AS avg_ms FROM requests WHERE detection_ms IS NOT NULL"
            ).fetchone()
            if row is None or row["avg_ms"] is None:
                return None
            return float(row["avg_ms"])

    def timeseries_requests_alerts(self, *, limit_buckets: int = 48) -> list[dict[str, Any]]:
        """Bucket counts by minute for the recent window."""
        with _lock, self._connect() as conn:
            req_rows = conn.execute(
                """
                SELECT substr(timestamp, 1, 16) AS bucket, COUNT(*) AS n
                FROM requests
                GROUP BY bucket
                ORDER BY bucket DESC
                LIMIT ?
                """,
                (limit_buckets,),
            ).fetchall()
            alert_rows = conn.execute(
                """
                SELECT substr(timestamp, 1, 16) AS bucket, COUNT(*) AS n
                FROM alerts
                GROUP BY bucket
                ORDER BY bucket DESC
                LIMIT ?
                """,
                (limit_buckets,),
            ).fetchall()

        req_map = {r["bucket"]: int(r["n"]) for r in req_rows}
        alert_map = {a["bucket"]: int(a["n"]) for a in alert_rows}
        buckets = sorted(set(req_map) | set(alert_map))
        return [
            {
                "bucket": b,
                "requests": req_map.get(b, 0),
                "alerts": alert_map.get(b, 0),
            }
            for b in buckets
        ]

    def alerts_by_type(self) -> list[dict[str, Any]]:
        with _lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT COALESCE(attack_type, 'unknown') AS attack_type, COUNT(*) AS n
                FROM alerts
                GROUP BY attack_type
                ORDER BY n DESC
                """
            ).fetchall()
        return [{"attack_type": r["attack_type"], "count": int(r["n"])} for r in rows]

    def list_alerts(
        self,
        *,
        attack_type: Optional[str] = None,
        sort: str = "desc",
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        order = "DESC" if str(sort).lower() != "asc" else "ASC"
        query = """
            SELECT id, timestamp, source_ip, attack_type, field, probability, action, request_id
            FROM alerts
        """
        params: list[Any] = []
        if attack_type:
            query += " WHERE attack_type = ?"
            params.append(attack_type)
        query += f" ORDER BY timestamp {order}, id {order} LIMIT ?"
        params.append(limit)
        with _lock, self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def list_alert_types(self) -> list[str]:
        with _lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT attack_type
                FROM alerts
                WHERE attack_type IS NOT NULL AND attack_type != ''
                ORDER BY attack_type ASC
                """
            ).fetchall()
        return [r["attack_type"] for r in rows]

    def list_sessions(self, *, limit: int = 200) -> list[dict[str, Any]]:
        with _lock, self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    s.session_hash,
                    s.first_seen,
                    s.last_seen,
                    s.ips,
                    s.user_agents,
                    s.request_count,
                    (
                        SELECT a.attack_type
                        FROM alerts a
                        JOIN requests r ON r.id = a.request_id
                        WHERE r.session_hash = s.session_hash
                          AND lower(COALESCE(a.attack_type, '')) NOT IN ('sqli', 'xss')
                        ORDER BY a.id DESC
                        LIMIT 1
                    ) AS predicted_class
                FROM sessions s
                ORDER BY s.last_seen DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            try:
                item["ips"] = json.loads(item.get("ips") or "[]")
            except Exception:
                item["ips"] = []
            try:
                item["user_agents"] = json.loads(item.get("user_agents") or "[]")
            except Exception:
                item["user_agents"] = []
            out.append(item)
        return out

    def clear_logs(self) -> None:
        with _lock, self._connect() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM requests")
            conn.execute("DELETE FROM sessions")

    def is_vulnerable_page_enabled(self, default: bool = False) -> bool:
        raw = self.get_setting("enable_vulnerable_page")
        if raw is None:
            return default
        return str(raw).strip().lower() in ("1", "true", "yes", "on")

    def set_vulnerable_page_enabled(self, enabled: bool) -> bool:
        self.set_setting("enable_vulnerable_page", "true" if enabled else "false")
        return enabled

    def export_requests_csv_rows(self) -> list[dict[str, Any]]:
        """Return request rows as dicts for streaming CSV export."""
        with _lock, self._connect() as conn:
            rows = conn.execute("SELECT * FROM requests ORDER BY id ASC").fetchall()
        return [dict(r) for r in rows]


# Process-wide default store (lazy)
_store: Optional[MonitorStore] = None


def get_store(db_path: Optional[str] = None) -> MonitorStore:
    """Return the shared MonitorStore instance."""
    global _store
    if _store is None or (db_path and db_path != _store.db_path):
        _store = MonitorStore(db_path=db_path)
    return _store
