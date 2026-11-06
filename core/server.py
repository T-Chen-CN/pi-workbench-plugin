"""The hub HTTP server: one stdlib ``ThreadingHTTPServer`` per gateway process.

Why stdlib and not aiohttp (which Hermes already ships)
------------------------------------------------------
1. It runs in a *separate thread*, so a bug here cannot poison the gateway's
   asyncio loop — the single most likely way for this plugin to take the whole
   agent down.
2. Tests run with a bare ``python -m unittest``; nothing to install.
3. Upstream does the same thing for its own ``a2a`` platform plugin.

Routing model
-------------
Three families:

* **own routes** — devices, hub health (handled in this process);
* **api routes** — everything the local app talks to on ``:8642``
  (``/v1/runs*``, ``/v1/capabilities``, ``/health/detailed``, sessions, jobs…),
  proxied with identity rewritten and SSE streamed through;
* **dashboard routes** — the two side-channel calls the local app makes on
  ``:9119`` (image upload, file read-back), proxied so the local machine never
  needs the dashboard token, with a path allowlist on reads.

Prefix rules are ordered: the first match wins, so the specific device routes are
registered before the prefix catch-alls.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

from . import auth as auth_mod
from . import fsguard
from .audit import Auditor
from .db import Database
from .errors import HubError
from .proxy import Response, StreamResponse, Upstream

VERSION = "0.1.0"

# 在线判定窗口：本地每 30s 心跳一次，超过 90s 没动静就算离线
ONLINE_WINDOW_S = 90
MAX_BODY_BYTES = 32 * 1024 * 1024  # image uploads go through the hub
LOGGER = logging.getLogger(__name__)

# Prefixes forwarded to api_server (:8642).
API_PREFIXES = ("/v1/runs", "/v1/capabilities", "/v1/toolsets", "/v1/skills", "/v1/models",
                "/v1/devices/me/tasks", "/health", "/api/sessions", "/api/jobs")
# Prefixes forwarded to the dashboard (:9119).
DASHBOARD_PREFIXES = ("/api/chat/image-upload", "/api/fs/read-data-url", "/api/config")
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass
class Request:
    method: str
    path: str
    query: str
    headers: dict[str, str]
    body: bytes
    client_ip: str
    device: dict | None = None

    def header(self, name: str, default: str | None = None) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default

    def json(self) -> dict:
        if not self.body:
            return {}
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise HubError("bad_request", "body is not valid JSON") from exc
        if not isinstance(data, dict):
            raise HubError("bad_request", "body must be a JSON object")
        return data

    @property
    def full_path(self) -> str:
        return self.path + (f"?{self.query}" if self.query else "")


@dataclass
class Route:
    method: str  # "*" matches any
    pattern: re.Pattern
    handler: str
    mode: str  # "anon" | "admin" | "chat" | "dispatch"


class HubContext:
    """Everything a handler needs, assembled once at startup."""

    def __init__(
        self,
        *,
        data_dir: str | Path,
        upstream_base: str,
        upstream_key: str,
        admin_key: str,
        rate_limit: int = 60,
        dashboard_base: str = "",
        dashboard_key: str = "",
        fs_roots: list[Path] | None = None,
    ):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.db = Database(self.data_dir / "hub.db")
        self.auth = auth_mod.Authenticator(self.db, rate_limit=rate_limit)
        self.audit = Auditor(self.db, self.data_dir / "audit.jsonl")
        self.api = Upstream(upstream_base, upstream_key)
        self.dashboard = Upstream(dashboard_base, dashboard_key) if dashboard_base else None
        self.fs_roots = fs_roots or []
        self.admin_key = admin_key
        self.started_at = time.time()

    def close(self) -> None:
        self.db.close()


class Hub:
    """Routes and handlers. No HTTP plumbing beyond building Response objects."""

    def __init__(self, ctx: HubContext):
        self.ctx = ctx
        self.routes: list[Route] = []
        for method, pattern, handler, mode in self._table():
            self._add(method, pattern, handler, mode)

    def _add(self, method: str, pattern: str, handler: Callable, mode: str) -> None:
        name = handler.__name__
        self.routes.append(Route(method, re.compile(f"^{pattern}$"), name, mode))
        if not hasattr(type(self), name):
            setattr(self, name, handler)

    def _table(self) -> list[tuple[str, str, Callable, str]]:
        t: list[tuple[str, str, Callable, str]] = [
            # -- self ------------------------------------------------------
            ("GET", r"/health", self.upstream_health, "anon"),
            ("GET", r"/v1/hub/health", self.hub_health, "anon"),
            # -- device administration (admin key) -------------------------
            ("POST", r"/v1/devices/register", self.register_device, "admin"),
            ("GET", r"/v1/devices", self.list_devices, "admin"),
            # 注销：管理密钥 / admin token / **设备注销自己**（chat scope 即可）。
            # 自注销是设备能对自己做的最不危险的事 —— 它只会切断自己。
            ("POST", r"/v1/devices/(?P<device_id>[A-Za-z0-9_.:-]+)/revoke", self.revoke_device, "admin_or_self"),
            # -- device self (own token) -----------------------------------
            ("GET", r"/v1/devices/me", self.device_me, "chat"),
            # 心跳：本地每 30s 一次，让云端知道这台机器还开着（在线判定 90s）
            ("POST", r"/v1/devices/me/heartbeat", self.device_heartbeat, "chat"),
            # -- passthrough: api_server -----------------------------------
            ("GET", r"/health/detailed", self.api_passthrough, "chat"),
            ("GET", r"/v1/(?:capabilities|toolsets|skills|models)", self.api_passthrough, "chat"),
            ("*", r"/api/sessions", self.api_passthrough, "chat"),
            ("*", r"/api/sessions/[^/]+", self.api_passthrough, "chat"),
            ("*", r"/api/sessions/[^/]+/messages", self.api_passthrough, "chat"),
            ("*", r"/api/jobs", self.api_passthrough, "chat"),
            ("*", r"/api/jobs/[^/]+", self.api_passthrough, "chat"),
            ("*", r"/v1/runs", self.api_passthrough, "chat"),
            ("*", r"/v1/runs/[^/]+", self.api_passthrough, "chat"),
            ("*", r"/v1/runs/[^/]+/[A-Za-z0-9_-]+", self.api_passthrough, "chat"),
            # -- passthrough: dashboard side channels ----------------------
            ("POST", r"/api/chat/image-upload", self.dashboard_passthrough, "chat"),
            ("GET", r"/api/fs/read-data-url", self.dashboard_passthrough, "chat"),
            # 读配置（审批档位那一小块）是纯只读：设备凭 chat 就该能读，
            # 否则「连接页显示当前档位」会 403。写配置仍然只有 admin 能做。
            ("GET", r"/api/config", self.dashboard_passthrough, "chat"),
            ("PUT", r"/api/config", self.dashboard_passthrough, "admin"),
        ]
        return t

    # -- dispatch ----------------------------------------------------------

    def match(self, method: str, path: str) -> tuple[Route, dict]:
        allowed_elsewhere = False
        for route in self.routes:
            found = route.pattern.match(path)
            if not found:
                continue
            if route.method not in ("*", method):
                allowed_elsewhere = True
                continue
            return route, {k: v for k, v in found.groupdict().items() if v is not None}
        if allowed_elsewhere:
            raise HubError("method_not_allowed", f"{method} is not allowed on {path}")
        raise HubError("not_found", f"no hub route for {method} {path}")

    # -- handlers: self ----------------------------------------------------

    def upstream_health(self, req: Request, **_: str) -> Response:
        return self.ctx.api.request("GET", "/health", headers=req.headers)

    def hub_health(self, req: Request, **_: str) -> Response:
        devices = self.ctx.auth.list_devices()
        online_at = int(time.time()) - ONLINE_WINDOW_S
        payload: dict[str, Any] = {
            "status": "ok",
            "hub": VERSION,
            "upstream": self.ctx.api.base_url,
            "upstreamOk": None,
            "dashboard": self.ctx.dashboard.base_url if self.ctx.dashboard else None,
            "devices": {
                "total": len(devices),
                "active": sum(1 for d in devices if (d.get("last_seen_at") or 0) >= online_at),
                "revoked": sum(1 for d in devices if d.get("revoked_at")),
            },
            "adminKeyConfigured": bool(self.ctx.admin_key),
            "uptimeSeconds": int(time.time() - self.ctx.started_at),
        }
        try:
            response = self.ctx.api.request("GET", "/health", cacheable=False, timeout=5.0)
            payload["upstreamOk"] = response.status == 200
            payload["upstreamVersion"] = _json_field(response, "version")
        except HubError as exc:
            payload["upstreamOk"] = False
            payload["upstreamError"] = exc.code
        return _json_response(payload, status=200 if payload["upstreamOk"] else 503)

    # -- handlers: device admin -------------------------------------------

    def register_device(self, req: Request, **_: str) -> Response:
        body = req.json()
        row, token, rotated = self.ctx.auth.register_device(
            body.get("name") or "unnamed",
            scopes=tuple(body.get("scopes") or auth_mod.DEFAULT_SCOPES),
            note=body.get("note"),
            device_id=body.get("deviceId"),
        )
        status = 200 if rotated else 201
        self.ctx.audit.record(
            "device.register",
            device_id=row["id"],
            status=status,
            detail={"name": row["name"], "scopes": row["scopes"], "rotated": rotated},
            ip=req.client_ip,
        )
        return _json_response(
            {
                "deviceId": row["id"],
                "name": row["name"],
                "scopes": auth_mod.scopes_list(row["scopes"]),
                "token": token,
                "tokenPrefix": row["token_prefix"],
                "rotated": rotated,
                "note": "token is shown once; the hub only stores its hash",
            },
            status=status,
        )

    def list_devices(self, req: Request, **_: str) -> Response:
        now = int(time.time())
        devices = []
        for row in self.ctx.auth.list_devices():
            last_seen = row.get("last_seen_at")
            devices.append(
                {
                    "deviceId": row["id"],
                    "name": row["name"],
                    "scopes": auth_mod.scopes_list(row["scopes"]),
                    "tokenPrefix": row["token_prefix"],
                    "createdAt": row["created_at"],
                    "lastSeenAt": last_seen,
                    "online": bool(
                        last_seen and now - last_seen < ONLINE_WINDOW_S and not row.get("revoked_at")
                    ),
                    "revokedAt": row["revoked_at"],
                    "note": row.get("note"),
                }
            )
        return _json_response({"devices": devices})

    def revoke_device(self, req: Request, device_id: str = "", **_: str) -> Response:
        changed = self.ctx.auth.revoke_device(device_id)
        self.ctx.audit.record(
            "device.revoke", device_id=device_id, status=200 if changed else 404, ip=req.client_ip
        )
        if not changed:
            raise HubError("not_found", "no such device, or already revoked")
        return _json_response({"deviceId": device_id, "revoked": True})

    # -- handlers: device self --------------------------------------------

    def device_me(self, req: Request, **_: str) -> Response:
        device = req.device or {}
        last_seen = device.get("last_seen_at")
        return _json_response(
            {
                "deviceId": device.get("id"),
                "name": device.get("name"),
                "scopes": auth_mod.scopes_list(device.get("scopes", "")),
                "createdAt": device.get("created_at"),
                "lastSeenAt": last_seen,
                "online": bool(device.get("id")),
                "onlineWindow": ONLINE_WINDOW_S,
                "serverTime": int(time.time()),
                "hub": VERSION,
            }
        )

    def device_heartbeat(self, req: Request, **_: str) -> Response:
        device = req.device or {}
        now = int(time.time())
        self.ctx.auth.touch(str(device.get("id") or ""), now)
        return _json_response(
            {
                "ok": True,
                "deviceId": device.get("id"),
                "serverTime": now,
                "onlineWindow": ONLINE_WINDOW_S,
            }
        )

    # -- handlers: passthrough --------------------------------------------

    def api_passthrough(self, req: Request, **_: str) -> Response | StreamResponse:
        body = req.body
        headers = dict(req.headers)
        if req.method == "POST" and req.path == "/v1/runs":
            body = _rewrite_author(body, req.device or {})
            headers = _prefix_idempotency(headers, (req.device or {}).get("id", ""))

        if _wants_stream(req):
            return self.ctx.api.stream(
                req.method,
                req.full_path,
                headers=headers,
                body=body or None,
                device_id=(req.device or {}).get("id"),
            )
        return self.ctx.api.request(
            req.method,
            req.full_path,
            headers=headers,
            body=body or None,
            device_id=(req.device or {}).get("id"),
        )

    def dashboard_passthrough(self, req: Request, **_: str) -> Response:
        dashboard = self.ctx.dashboard
        if dashboard is None:
            raise HubError("upstream_unavailable", "dashboard side channel is not configured")
        path = req.full_path
        if req.path == "/api/fs/read-data-url":
            wanted = urllib.parse.parse_qs(req.query).get("path", [""])[0]
            fsguard.ensure_allowed(wanted, self.ctx.fs_roots)
        return dashboard.request(
            req.method, path, headers=req.headers, body=req.body or None,
            device_id=(req.device or {}).get("id"),
        )


# -- helpers ---------------------------------------------------------------


def _json_field(response: Response, name: str) -> Any:
    try:
        return json.loads(response.body.decode("utf-8")).get(name)
    except Exception:
        return None


def _wants_stream(req: Request) -> bool:
    if req.method != "GET":
        return False
    accept = (req.header("Accept") or "").lower()
    return "text/event-stream" in accept or req.path.endswith("/events")


def _rewrite_author(body: bytes, device: dict) -> bytes:
    """The token decides who you are: replace any client-supplied ``author``."""
    if not body or not device:
        return body
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return body  # let upstream produce the real error
    if not isinstance(payload, dict):
        return body
    payload["author"] = {
        "id": f"pi-workbench/{device.get('id', '')}",
        "name": device.get("name") or "unknown device",
        "is_bot": False,
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _prefix_idempotency(headers: dict[str, str], device_id: str) -> dict[str, str]:
    out = dict(headers)
    for key in list(out.keys()):
        if key.lower() != "idempotency-key":
            continue
        value = out.pop(key)
        if not device_id or value.startswith("pi:"):
            out["Idempotency-Key"] = value
        else:
            out["Idempotency-Key"] = f"pi:{device_id}:{value}"
    return out


def _json_response(payload: dict, status: int = 200) -> Response:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return Response(status, {"Content-Type": "application/json; charset=utf-8"}, body)


class HubRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"pi-workbench/{VERSION}"
    sys_version = ""

    @property
    def hub(self) -> Hub:
        return self.server.hub  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003 - stdlib signature
        LOGGER.debug("[hub] %s - %s", self.address_string(), fmt % args)

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    # -- plumbing ----------------------------------------------------------

    def _read_body(self) -> bytes:
        raw_length = self.headers.get("Content-Length")
        if not raw_length:
            return b""
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise HubError("bad_request", "invalid Content-Length") from exc
        if length > MAX_BODY_BYTES:
            raise HubError("payload_too_large", f"body exceeds {MAX_BODY_BYTES} bytes")
        return self.rfile.read(length) if length > 0 else b""

    def _dispatch(self, method: str) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        started = time.time()
        req = Request(
            method=method,
            path=path,
            query=parsed.query,
            headers={k: v for k, v in self.headers.items()},
            body=b"",
            client_ip=_client_ip(self.headers, self.address_string()),
        )
        try:
            req.body = self._read_body()
            route, params = self.hub.match(method, path)
            self._authorize(route, req, params)
            result = getattr(self.hub, route.handler)(req, **params)
            if method in WRITE_METHODS:
                # Record before emitting so a client disconnect cannot lose the
                # trail, and so "response received" implies "audited".
                self.hub.ctx.audit.record(
                    f"http.{method.lower()}",
                    device_id=(req.device or {}).get("id"),
                    path=path,
                    status=result.status,
                    detail={"durationMs": int((time.time() - started) * 1000)},
                    ip=req.client_ip,
                )
            self._emit(result)
        except HubError as exc:
            self._emit(_json_response(exc.payload(), status=exc.status), extra_headers=exc.headers())
        except Exception:  # pragma: no cover - last resort, keep the socket healthy
            LOGGER.exception("[hub] unhandled error on %s %s", method, path)
            err = HubError("internal_error")
            self._emit(_json_response(err.payload(), status=err.status))

    def _authorize(self, route: Route, req: Request, params: dict | None = None) -> None:
        ctx = self.hub.ctx
        params = params or {}
        if route.mode == "anon":
            return
        if route.mode == "admin_or_self":
            key = req.header("X-Pi-Admin-Key")
            if key:
                ctx.auth.check_admin(key, ctx.admin_key)
                return
            token = _bearer(req.header("Authorization"))
            if not token:
                raise HubError("admin_required")
            device = ctx.auth.authenticate(token)
            target = params.get("device_id") or ""
            if device["id"] != target:
                # 不是自己：仍需 admin scope
                ctx.auth.require_scope(device, "admin")
            ctx.auth.touch(device["id"])
            req.device = device
            return
        if route.mode == "admin":
            key = req.header("X-Pi-Admin-Key")
            if key:
                ctx.auth.check_admin(key, ctx.admin_key)
                return
            token = _bearer(req.header("Authorization"))
            if not token:
                raise HubError("admin_required")
            # An admin-scoped device token is equally acceptable.
            device = ctx.auth.authenticate(token)
            ctx.auth.require_scope(device, "admin")
            ctx.auth.touch(device["id"])
            req.device = device
            return
        token = _bearer(req.header("Authorization"))
        device = ctx.auth.authenticate(token)
        ctx.auth.limiter.check(device["id"])
        ctx.auth.touch(device["id"])
        req.device = device
        ctx.auth.require_scope(device, route.mode)

    def _emit(self, result: Response | StreamResponse, extra_headers: dict[str, str] | None = None) -> None:
        if isinstance(result, StreamResponse):
            self._emit_stream(result)
            return
        self.send_response(result.status)
        headers = dict(result.headers)
        headers.update(extra_headers or {})
        payload = result.body or b""
        if not any(k.lower() == "content-type" for k in headers):
            headers["Content-Type"] = "application/json; charset=utf-8"
        headers["Content-Length"] = str(len(payload))
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _emit_stream(self, result: StreamResponse) -> None:
        self.send_response(result.status)
        headers = dict(result.headers)
        headers.setdefault("Cache-Control", "no-cache, no-store")
        headers.setdefault("X-Accel-Buffering", "no")
        headers["Connection"] = "close"
        for key, value in headers.items():
            self.send_header(key, value)
        self.end_headers()
        self.close_connection = True
        chunks = result.chunks
        try:
            for chunk in chunks:
                if not chunk:
                    continue
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            LOGGER.debug("[hub] client disconnected mid-stream")
        finally:
            close = getattr(chunks, "close", None)
            if callable(close):
                close()


def _client_ip(headers, peer: str) -> str:
    """Caddy terminates TLS, so the socket peer is always 127.0.0.1.

    The hub only ever listens on loopback with Caddy in front, which makes the
    last ``X-Forwarded-For`` hop trustworthy — and the audit trail useless
    without it.
    """
    forwarded = headers.get("X-Forwarded-For") if headers else None
    if forwarded:
        hops = [part.strip() for part in str(forwarded).split(",") if part.strip()]
        if hops:
            return hops[-1]
    return peer


def _bearer(header: str | None) -> str | None:
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


class HubServer:
    """Owns the socket and the background thread."""

    def __init__(
        self,
        *,
        data_dir: str | Path,
        upstream_base: str,
        upstream_key: str,
        admin_key: str,
        host: str = "127.0.0.1",
        port: int = 8484,
        rate_limit: int = 60,
        dashboard_base: str = "",
        dashboard_key: str = "",
        fs_roots: list[Path] | None = None,
    ):
        self.ctx = HubContext(
            data_dir=data_dir,
            upstream_base=upstream_base,
            upstream_key=upstream_key,
            admin_key=admin_key,
            rate_limit=rate_limit,
            dashboard_base=dashboard_base,
            dashboard_key=dashboard_key,
            fs_roots=fs_roots,
        )
        self.hub = Hub(self.ctx)
        self.host = host
        self.port = port
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        httpd = ThreadingHTTPServer((self.host, self.port), HubRequestHandler)
        httpd.daemon_threads = True
        httpd.hub = self.hub  # type: ignore[attr-defined]
        self._httpd = httpd
        self.port = httpd.server_address[1]
        self._thread = threading.Thread(
            target=lambda: httpd.serve_forever(poll_interval=0.1),
            name="pi-workbench-hub",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        httpd, self._httpd = self._httpd, None
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5)
        self.ctx.close()

    @property
    def is_running(self) -> bool:
        return self._httpd is not None and self._thread is not None and self._thread.is_alive()

    @property
    def address(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def upstream_base(self) -> str:
        return self.ctx.api.base_url
