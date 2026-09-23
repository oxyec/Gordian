"""Storage backend abstraction — RAM dict or SQLite.

The user picks at startup with ``--storage ram`` (default) or ``--storage sqlite``.
Both backends expose the same thin interface so ``ScanManager`` never cares
which one is active.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


# ── Portable scan record ─────────────────────────────────────────────

@dataclass
class ScanRecord:
    """Flat representation of one scan's data — serialisable to SQLite."""

    scan_id: str
    status: str = "idle"  # idle | running | completed | failed
    stage: str = "idle"
    progress_percent: float = 0.0
    progress_message: str = ""
    elapsed_seconds: float = 0.0
    error: str | None = None

    # Serialised JSON blobs
    config_json: str = "{}"
    graph_json: str = "{}"
    kill_chains_json: str = "[]"
    findings_json: str = "[]"
    offensive_json: str = "{}"
    stats_json: str = "{}"

    created_at: str = ""
    updated_at: str = ""

    def __post_init__(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        if not self.created_at:
            self.created_at = now
        if not self.updated_at:
            self.updated_at = now


# ── Abstract interface ───────────────────────────────────────────────

class StorageBackend(ABC):
    """Minimal contract for persisting scan state."""

    @abstractmethod
    def create_scan(self, config: dict[str, Any]) -> ScanRecord:
        ...

    @abstractmethod
    def get_scan(self, scan_id: str) -> ScanRecord | None:
        ...

    @abstractmethod
    def update_scan(self, record: ScanRecord) -> None:
        ...

    @abstractmethod
    def list_scans(self, limit: int = 50) -> list[ScanRecord]:
        ...

    @abstractmethod
    def delete_scan(self, scan_id: str) -> bool:
        ...

    @abstractmethod
    def store_events(self, scan_id: str, events: list[dict[str, Any]]) -> None:
        ...

    @abstractmethod
    def get_events(self, scan_id: str, limit: int = 500) -> list[dict[str, Any]]:
        ...


# ── RAM backend ──────────────────────────────────────────────────────

class RAMStorage(StorageBackend):
    """In-memory storage — blazing fast, no persistence across restarts."""

    def __init__(self, max_events_per_scan: int = 5000) -> None:
        self._scans: dict[str, ScanRecord] = {}
        self._events: dict[str, deque[dict[str, Any]]] = {}
        self._max_events = max_events_per_scan
        self._lock = threading.Lock()
        log.info("RAM storage backend initialised")

    def create_scan(self, config: dict[str, Any]) -> ScanRecord:
        scan_id = str(uuid.uuid4())
        record = ScanRecord(
            scan_id=scan_id,
            config_json=json.dumps(config, default=str),
        )
        with self._lock:
            self._scans[scan_id] = record
            self._events[scan_id] = deque(maxlen=self._max_events)
        return record

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        return self._scans.get(scan_id)

    def update_scan(self, record: ScanRecord) -> None:
        record.updated_at = datetime.now(timezone.utc).isoformat()
        with self._lock:
            self._scans[record.scan_id] = record

    def list_scans(self, limit: int = 50) -> list[ScanRecord]:
        ordered = sorted(self._scans.values(), key=lambda r: r.created_at, reverse=True)
        return ordered[:limit]

    def delete_scan(self, scan_id: str) -> bool:
        with self._lock:
            removed = self._scans.pop(scan_id, None)
            self._events.pop(scan_id, None)
        return removed is not None

    def store_events(self, scan_id: str, events: list[dict[str, Any]]) -> None:
        with self._lock:
            buf = self._events.setdefault(scan_id, deque(maxlen=self._max_events))
            buf.extend(events)

    def get_events(self, scan_id: str, limit: int = 500) -> list[dict[str, Any]]:
        buf = self._events.get(scan_id)
        if buf is None:
            return []
        items = list(buf)
        return items[-limit:]


# ── SQLite backend ───────────────────────────────────────────────────

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id          TEXT PRIMARY KEY,
    status           TEXT NOT NULL DEFAULT 'idle',
    stage            TEXT NOT NULL DEFAULT 'idle',
    progress_percent REAL NOT NULL DEFAULT 0.0,
    progress_message TEXT NOT NULL DEFAULT '',
    elapsed_seconds  REAL NOT NULL DEFAULT 0.0,
    error            TEXT,
    config_json      TEXT NOT NULL DEFAULT '{}',
    graph_json       TEXT NOT NULL DEFAULT '{}',
    kill_chains_json TEXT NOT NULL DEFAULT '[]',
    findings_json    TEXT NOT NULL DEFAULT '[]',
    offensive_json   TEXT NOT NULL DEFAULT '{}',
    stats_json       TEXT NOT NULL DEFAULT '{}',
    created_at       TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  TEXT NOT NULL,
    payload  TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_scan ON events(scan_id);
"""


class SQLiteStorage(StorageBackend):
    """Persistent storage backed by a local SQLite file."""

    def __init__(self, db_path: str | Path = "gordian_scans.db") -> None:
        self._db_path = str(db_path)
        self._local = threading.local()
        self._init_schema()
        log.info("SQLite storage backend initialised at %s", self._db_path)

    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = self._conn()
        conn.executescript(_SCHEMA_SQL)
        conn.commit()

    def close(self) -> None:
        """Close the coordinator thread's connection at application shutdown."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None

    # ── CRUD ──

    def create_scan(self, config: dict[str, Any]) -> ScanRecord:
        scan_id = str(uuid.uuid4())
        record = ScanRecord(
            scan_id=scan_id,
            config_json=json.dumps(config, default=str),
        )
        conn = self._conn()
        conn.execute(
            """INSERT INTO scans
               (scan_id, status, stage, progress_percent, progress_message,
                elapsed_seconds, error, config_json, graph_json,
                kill_chains_json, findings_json, offensive_json, stats_json,
                created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                record.scan_id, record.status, record.stage,
                record.progress_percent, record.progress_message,
                record.elapsed_seconds, record.error,
                record.config_json, record.graph_json,
                record.kill_chains_json, record.findings_json,
                record.offensive_json, record.stats_json,
                record.created_at, record.updated_at,
            ),
        )
        conn.commit()
        return record

    def get_scan(self, scan_id: str) -> ScanRecord | None:
        row = self._conn().execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_record(row)

    def update_scan(self, record: ScanRecord) -> None:
        record.updated_at = datetime.now(timezone.utc).isoformat()
        conn = self._conn()
        conn.execute(
            """UPDATE scans SET
                status=?, stage=?, progress_percent=?, progress_message=?,
                elapsed_seconds=?, error=?, config_json=?, graph_json=?,
                kill_chains_json=?, findings_json=?, offensive_json=?,
                stats_json=?, updated_at=?
               WHERE scan_id=?""",
            (
                record.status, record.stage, record.progress_percent,
                record.progress_message, record.elapsed_seconds, record.error,
                record.config_json, record.graph_json, record.kill_chains_json,
                record.findings_json, record.offensive_json, record.stats_json,
                record.updated_at, record.scan_id,
            ),
        )
        conn.commit()

    def list_scans(self, limit: int = 50) -> list[ScanRecord]:
        rows = self._conn().execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [self._row_to_record(r) for r in rows]

    def delete_scan(self, scan_id: str) -> bool:
        conn = self._conn()
        cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        conn.commit()
        return cursor.rowcount > 0

    def store_events(self, scan_id: str, events: list[dict[str, Any]]) -> None:
        conn = self._conn()
        conn.executemany(
            "INSERT INTO events (scan_id, payload) VALUES (?, ?)",
            [(scan_id, json.dumps(ev, default=str)) for ev in events],
        )
        conn.commit()

    def get_events(self, scan_id: str, limit: int = 500) -> list[dict[str, Any]]:
        rows = self._conn().execute(
            "SELECT payload FROM events WHERE scan_id = ? ORDER BY id DESC LIMIT ?",
            (scan_id, limit),
        ).fetchall()
        result = []
        for row in reversed(rows):
            try:
                result.append(json.loads(row["payload"]))
            except (json.JSONDecodeError, KeyError):
                continue
        return result

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ScanRecord:
        return ScanRecord(
            scan_id=row["scan_id"],
            status=row["status"],
            stage=row["stage"],
            progress_percent=row["progress_percent"],
            progress_message=row["progress_message"],
            elapsed_seconds=row["elapsed_seconds"],
            error=row["error"],
            config_json=row["config_json"],
            graph_json=row["graph_json"],
            kill_chains_json=row["kill_chains_json"],
            findings_json=row["findings_json"],
            offensive_json=row["offensive_json"],
            stats_json=row["stats_json"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )


# ── Factory ──────────────────────────────────────────────────────────

def create_storage(backend: str = "ram", **kwargs: Any) -> StorageBackend:
    """Factory — pick *ram* for speed, *sqlite* for persistence."""
    if backend == "sqlite":
        return SQLiteStorage(**kwargs)
    return RAMStorage(**kwargs)
