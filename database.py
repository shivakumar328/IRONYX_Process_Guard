"""
IRONYX Process Guard — SQLite Database Layer
=============================================

Provides schema creation, connection pooling, and CRUD operations for
storing process snapshots, alerts, hashes, and risk scores.

Schema
------
* **process_events**  — one row per process observation
* **alerts**          — one row per high-risk alert
* **executable_hashes** — known-good / seen-before hashes
* **risk_history**    — rolling risk score per PID

Author : IRONYX Security
License: MIT
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

from config import Config, load_config

# ── Schema DDL ──────────────────────────────────────────────────────────────

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS process_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    pid         INTEGER NOT NULL,
    ppid        INTEGER,
    name        TEXT,
    exe         TEXT,
    cmdline     TEXT,
    username    TEXT,
    cpu_percent REAL,
    mem_mb      REAL,
    status      TEXT,
    create_time TEXT,
    exe_hash    TEXT,
    risk_score  INTEGER DEFAULT 0,
    risk_level  TEXT    DEFAULT 'low',
    reason      TEXT,
    action      TEXT    DEFAULT 'monitor'
);

CREATE INDEX IF NOT EXISTS idx_pe_pid    ON process_events(pid);
CREATE INDEX IF NOT EXISTS idx_pe_ts     ON process_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_pe_risk   ON process_events(risk_score);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    pid         INTEGER,
    process_name TEXT,
    risk_score  INTEGER,
    risk_level  TEXT,
    reason      TEXT,
    details     TEXT,
    acknowledged INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);

CREATE TABLE IF NOT EXISTS executable_hashes (
    hash        TEXT    PRIMARY KEY,
    exe_path    TEXT,
    first_seen  TEXT,
    last_seen   TEXT,
    known_good  INTEGER DEFAULT 0,
    signature   TEXT
);

CREATE TABLE IF NOT EXISTS risk_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    pid         INTEGER NOT NULL,
    risk_score  INTEGER NOT NULL,
    risk_level  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rh_pid ON risk_history(pid);
"""


class Database:
    """Thread-safe SQLite wrapper with connection-per-call semantics."""

    def __init__(self, cfg: Config | None = None) -> None:
        self.cfg = cfg or load_config()
        self.db_path = self.cfg.db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._init_schema()

    # ── connection management ───────────────────────────────────────────────
    def _get_conn(self) -> sqlite3.Connection:
        """Return a thread-local connection."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager that commits on success, rolls back on error."""
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_schema(self) -> None:
        """Create tables if they don't exist."""
        with self.transaction() as conn:
            conn.executescript(SCHEMA_SQL)

    # ── process events ──────────────────────────────────────────────────────
    def insert_process_event(self, event: dict[str, Any]) -> int:
        """Insert a process observation row."""
        cols = (
            "timestamp", "pid", "ppid", "name", "exe", "cmdline",
            "username", "cpu_percent", "mem_mb", "status", "create_time",
            "exe_hash", "risk_score", "risk_level", "reason", "action",
        )
        values = [event.get(c) for c in cols]
        placeholders = ",".join("?" * len(cols))
        sql = f"INSERT INTO process_events ({','.join(cols)}) VALUES ({placeholders})"
        with self.transaction() as conn:
            cur = conn.execute(sql, values)
            return cur.lastrowid or -1

    def get_recent_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """Return the most recent *limit* process events."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM process_events ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── alerts ──────────────────────────────────────────────────────────────
    def insert_alert(self, alert: dict[str, Any]) -> int:
        """Insert an alert row."""
        cols = ("timestamp", "pid", "process_name", "risk_score",
                "risk_level", "reason", "details")
        values = [alert.get(c) for c in cols]
        placeholders = ",".join("?" * len(cols))
        sql = f"INSERT INTO alerts ({','.join(cols)}) VALUES ({placeholders})"
        with self.transaction() as conn:
            cur = conn.execute(sql, values)
            return cur.lastrowid or -1

    def get_recent_alerts(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent alerts newest-first."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int) -> None:
        """Mark an alert as acknowledged."""
        with self.transaction() as conn:
            conn.execute(
                "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
            )

    # ── executable hashes ───────────────────────────────────────────────────
    def upsert_hash(self, sha256: str, exe_path: str, signature: str | None = None) -> None:
        """Insert or update an executable hash record."""
        now = datetime.now().astimezone().isoformat()
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO executable_hashes (hash, exe_path, first_seen, last_seen, signature)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(hash) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       exe_path  = excluded.exe_path""",
                (sha256, exe_path, now, now, signature),
            )

    def is_hash_known(self, sha256: str) -> bool:
        """Check whether *sha256* has been seen before."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM executable_hashes WHERE hash = ?", (sha256,)
            ).fetchone()
        return row is not None

    def mark_hash_known_good(self, sha256: str) -> None:
        """Mark a hash as known-good (whitelisted)."""
        with self.transaction() as conn:
            conn.execute(
                "UPDATE executable_hashes SET known_good = 1 WHERE hash = ?", (sha256,)
            )

    # ── risk history ────────────────────────────────────────────────────────
    def insert_risk_history(self, pid: int, score: int, level: str) -> None:
        """Append a risk-history data point."""
        now = datetime.now().astimezone().isoformat()
        with self.transaction() as conn:
            conn.execute(
                "INSERT INTO risk_history (timestamp, pid, risk_score, risk_level) VALUES (?, ?, ?, ?)",
                (now, pid, score, level),
            )

    def get_risk_history(self, pid: int, limit: int = 60) -> list[dict[str, Any]]:
        """Return risk history for a PID."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_history WHERE pid = ? ORDER BY timestamp DESC LIMIT ?",
                (pid, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── statistics ───────────────────────────────────────────────────────────
    def get_stats(self) -> dict[str, Any]:
        """Return summary statistics for the dashboard."""
        with self._get_conn() as conn:
            total_events = conn.execute("SELECT COUNT(*) FROM process_events").fetchone()[0]
            total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            unack_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
            ).fetchone()[0]
            high_alerts = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE risk_level = 'high'"
            ).fetchone()[0]
            known_hashes = conn.execute("SELECT COUNT(*) FROM executable_hashes").fetchone()[0]

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "unacknowledged_alerts": unack_alerts,
            "high_risk_alerts": high_alerts,
            "known_hashes": known_hashes,
        }

    def close(self) -> None:
        """Close the thread-local connection if open."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None
