"""Audit trail: SQLite rows for queries + a JSONL mirror for ``tail -f``.

Two sinks on purpose: the DB is for the hub's own needs (and future device
pages), the JSONL survives a corrupted/locked DB and is what an operator reads
during an incident.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from .db import Database

_REDACTED_KEYS = frozenset({"authorization", "x-pi-admin-key", "api_server_key", "token", "prompt"})


def _redact(detail: Any) -> Any:
    if isinstance(detail, dict):
        return {k: ("<redacted>" if k.lower() in _REDACTED_KEYS else _redact(v)) for k, v in detail.items()}
    if isinstance(detail, list):
        return [_redact(v) for v in detail]
    return detail


class Auditor:
    def __init__(self, db: Database, jsonl_path: str | Path):
        self.db = db
        self.jsonl_path = Path(jsonl_path)
        self._lock = threading.Lock()

    def record(
        self,
        kind: str,
        *,
        device_id: str | None = None,
        path: str | None = None,
        status: int | None = None,
        detail: Any = None,
        ip: str | None = None,
        now: int | None = None,
    ) -> None:
        now = int(time.time()) if now is None else int(now)
        clean = _redact(detail)
        text = json.dumps(clean, ensure_ascii=False, sort_keys=True) if clean is not None else None
        try:
            conn = self.db.connection()
            with conn:
                conn.execute(
                    "INSERT INTO audit(at, kind, device_id, path, status, detail, ip) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (now, kind, device_id, path, status, text, ip),
                )
        except Exception:  # pragma: no cover - never fail a request because of audit
            pass
        try:
            with self._lock:
                self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
                with self.jsonl_path.open("a", encoding="utf-8") as fh:
                    fh.write(
                        json.dumps(
                            {
                                "at": now,
                                "kind": kind,
                                "deviceId": device_id,
                                "path": path,
                                "status": status,
                                "ip": ip,
                                "detail": clean,
                            },
                            ensure_ascii=False,
                            sort_keys=True,
                        )
                        + "\n"
                    )
        except Exception:  # pragma: no cover
            pass

    def recent(self, limit: int = 50) -> list[dict]:
        rows = self.db.connection().execute(
            "SELECT at, kind, device_id, path, status, detail, ip FROM audit ORDER BY id DESC LIMIT ?",
            (max(1, min(int(limit), 500)),),
        ).fetchall()
        return [dict(r) for r in rows]
