"""Device tokens, scopes and rate limiting.

The token is the only identity the hub trusts. Anything the client *claims*
about itself (device name, ``author``, paths) is advisory: the device id always
comes from the token, and ``author`` is rewritten from it (H1).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import threading
import time

from .db import Database
from .errors import HubError

TOKEN_PREFIX = "pi_"
TOKEN_BYTES = 32
SCOPES = ("chat", "dispatch", "admin")
DEFAULT_SCOPES = ("chat",)


def new_token() -> str:
    return TOKEN_PREFIX + base64.urlsafe_b64encode(secrets.token_bytes(TOKEN_BYTES)).decode().rstrip("=")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_prefix(token: str) -> str:
    """First 12 chars — enough for a human to match a log line to a device."""
    return token[:12]


_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")


def _clean_device_id(raw: str | None) -> str | None:
    candidate = str(raw or "").strip()
    return candidate if _DEVICE_ID_RE.match(candidate) else None


def scopes_list(raw: str) -> list[str]:
    """``"chat,dispatch"`` or a row value -> ``["chat", "dispatch"]``."""
    return [part.strip() for part in str(raw or "").split(",") if part.strip()]


def looks_like_token(token: str) -> bool:
    return token.startswith(TOKEN_PREFIX) and 8 <= len(token) <= 128


class RateLimiter:
    """Token bucket per device: ``limit`` requests per rolling minute."""

    def __init__(self, limit: int = 60, window: float = 60.0):
        self.limit = max(1, int(limit))
        self.window = float(window)
        self._lock = threading.Lock()
        self._hits: dict[str, list[float]] = {}

    def check(self, key: str, now: float | None = None) -> None:
        now = time.time() if now is None else now
        cutoff = now - self.window
        with self._lock:
            hits = [t for t in self._hits.get(key, ()) if t > cutoff]
            if len(hits) >= self.limit:
                retry = max(1, int(self.window - (now - hits[0])) + 1)
                self._hits[key] = hits
                raise HubError("rate_limited", retry_after=retry)
            hits.append(now)
            self._hits[key] = hits

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


class Authenticator:
    def __init__(self, db: Database, *, rate_limit: int = 60):
        self.db = db
        self.limiter = RateLimiter(rate_limit)

    # -- tokens ------------------------------------------------------------

    def authenticate(self, token: str | None) -> dict:
        """Resolve a bearer token to its device row, or raise."""
        if not token or not looks_like_token(token):
            raise HubError("unauthorized")
        digest = hash_token(token)
        row = self.db.connection().execute(
            "SELECT * FROM devices WHERE token_hash = ?", (digest,)
        ).fetchone()
        if row is None:
            raise HubError("unauthorized")
        if not hmac.compare_digest(row["token_hash"], digest):  # paranoia, index already matched
            raise HubError("unauthorized")
        if row["revoked_at"] is not None:
            raise HubError("device_revoked")
        return dict(row)

    @staticmethod
    def scopes_of(device: dict) -> tuple[str, ...]:
        return tuple(scopes_list(device.get("scopes")))

    def require_scope(self, device: dict, scope: str) -> None:
        scopes = self.scopes_of(device)
        if scope not in scopes:
            raise HubError("scope_required", f"token lacks scope {scope!r}")

    def check_admin(self, provided: str | None, admin_key: str) -> None:
        if not admin_key:
            raise HubError("hub_disabled")
        if not provided or not hmac.compare_digest(provided, admin_key):
            raise HubError("admin_required")

    # -- registry ----------------------------------------------------------

    def register_device(
        self,
        name: str,
        *,
        scopes: tuple[str, ...] = DEFAULT_SCOPES,
        note: str | None = None,
        now: int | None = None,
        device_id: str | None = None,
    ) -> tuple[dict, str, bool]:
        """Create — or re-issue — a device and return ``(row, plaintext_token, rotated)``.

        The plaintext token is returned exactly once; only its hash is stored.
        Registration is admin-authenticated, so a caller may pin the id to the
        one its local install already uses (``data/cloud-agent/device.json``) —
        that keeps ``author.id`` stable across the hub instead of inventing a
        second identity for the same machine.

        Re-registering the **same id** is a normal operation (token lost, app
        reinstalled, revoked by mistake): it rotates the token instead of
        failing on the primary key. The old token stops working immediately,
        which is the point — one device must never hold two live tokens. A
        revoked device is reactivated by the same call, because the caller had
        to prove it holds the admin key.
        """
        now = int(time.time()) if now is None else int(now)
        clean_name = " ".join(str(name or "").split())[:40] or "unnamed"
        clean_scopes = tuple(s for s in scopes if s in SCOPES) or DEFAULT_SCOPES
        token = new_token()
        device_id = _clean_device_id(device_id) or secrets.token_hex(16)
        conn = self.db.connection()
        with conn:
            existing = conn.execute("SELECT id FROM devices WHERE id = ?", (device_id,)).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO devices(id, name, token_hash, token_prefix, scopes, created_at, note) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (
                        device_id,
                        clean_name,
                        hash_token(token),
                        token_prefix(token),
                        ",".join(clean_scopes),
                        now,
                        note,
                    ),
                )
                rotated = False
            else:
                # 同一个 id 再登记 = 换 token（旧 token 立刻失效），撤销状态一并清掉
                conn.execute(
                    "UPDATE devices SET name = ?, token_hash = ?, token_prefix = ?, scopes = ?, "
                    "revoked_at = NULL, note = ? WHERE id = ?",
                    (
                        clean_name,
                        hash_token(token),
                        token_prefix(token),
                        ",".join(clean_scopes),
                        note,
                        device_id,
                    ),
                )
                rotated = True
        row = dict(conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone())
        return row, token, rotated

    def revoke_device(self, device_id: str, now: int | None = None) -> bool:
        now = int(time.time()) if now is None else int(now)
        conn = self.db.connection()
        with conn:
            cur = conn.execute(
                "UPDATE devices SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                (now, device_id),
            )
        return cur.rowcount > 0

    def list_devices(self) -> list[dict]:
        rows = self.db.connection().execute(
            "SELECT id, name, token_prefix, scopes, created_at, last_seen_at, revoked_at, note "
            "FROM devices ORDER BY created_at"
        ).fetchall()
        return [dict(r) for r in rows]

    def touch(self, device_id: str, now: int | None = None) -> None:
        now = int(time.time()) if now is None else int(now)
        conn = self.db.connection()
        with conn:
            conn.execute("UPDATE devices SET last_seen_at = ? WHERE id = ?", (now, device_id))
