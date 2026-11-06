"""SQLite state: devices, workspaces, tasks, audit.

Design notes
------------
* WAL journal so a reader (audit tail, future dashboard) never blocks the
  request path, and short transactions only.
* One connection per thread (``threading.local``): the HTTP server is
  thread-per-connection, and sqlite3 connections are not shareable. No locking
  ceremony needed; WAL gives us concurrent readers plus a single writer.
* ``check_same_thread=False`` is still required because a connection may be
  released on a different thread than the one that created it when the server
  shuts down.
"""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    token_prefix  TEXT NOT NULL,
    scopes        TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_seen_at  INTEGER,
    revoked_at    INTEGER,
    note          TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token_hash);

CREATE TABLE IF NOT EXISTS workspaces (
    id             TEXT PRIMARY KEY,
    device_id      TEXT NOT NULL,
    name           TEXT NOT NULL,
    trusted        INTEGER NOT NULL DEFAULT 0,
    last_active_at INTEGER,
    updated_at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_workspaces_device ON workspaces(device_id);

CREATE TABLE IF NOT EXISTS tasks (
    id                TEXT PRIMARY KEY,
    device_id         TEXT NOT NULL,
    workspace_id      TEXT NOT NULL,
    prompt            TEXT NOT NULL,
    mode              TEXT NOT NULL,
    status            TEXT NOT NULL,
    created_at        INTEGER NOT NULL,
    expires_at        INTEGER NOT NULL,
    claimed_at        INTEGER,
    finished_at       INTEGER,
    result_summary    TEXT,
    exit_code         INTEGER,
    error             TEXT,
    origin_run_id     TEXT,
    origin_session_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_tasks_device_status ON tasks(device_id, status);

CREATE TABLE IF NOT EXISTS audit (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    at        INTEGER NOT NULL,
    kind      TEXT NOT NULL,
    device_id TEXT,
    path      TEXT,
    status    INTEGER,
    detail    TEXT,
    ip        TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);
"""


class Database:
    """Thread-local SQLite access with WAL and a tiny migration hook."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._all: list[sqlite3.Connection] = []
        self._all_lock = threading.Lock()
        with self.connection() as conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT INTO meta(key, value) VALUES('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(SCHEMA_VERSION),),
            )

    def connection(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        conn = sqlite3.connect(self.path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        self._local.conn = conn
        with self._all_lock:
            self._all.append(conn)
        return conn

    def close(self) -> None:
        """Close every thread's connection (shutdown, plugin update, tests)."""
        with self._all_lock:
            conns, self._all = self._all, []
        for conn in conns:
            try:
                conn.close()
            except Exception:  # pragma: no cover - best effort
                pass
        self._local.conn = None
