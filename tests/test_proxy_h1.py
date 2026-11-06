"""H1: the proxied surface the local app actually uses.

Covers the three things that break silently in a reverse proxy: event-stream
fidelity, identity rewriting, and file-read scoping.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.parse
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from core import fsguard  # noqa: E402
from core.errors import HubError  # noqa: E402
from core.server import HubServer  # noqa: E402
from tests import TempDirMixin  # noqa: E402
from tests.fake_upstream import FakeUpstream  # noqa: E402

ADMIN_KEY = "admin-secret"
UPSTREAM_KEY = "upstream-secret"
DASH_KEY = "dash-secret"


class H1TestCase(TempDirMixin):
    def setUp(self):
        super().setUp()
        self.api = FakeUpstream(api_key=UPSTREAM_KEY).start()
        self.dash = FakeUpstream(api_key=DASH_KEY).start()
        self.uploads = os.path.join(self.tmpdir, "uploads")
        os.makedirs(self.uploads, exist_ok=True)
        self.staged = os.path.join(self.uploads, "web-abc-picture.png")
        with open(self.staged, "wb") as fh:
            fh.write(b"\x89PNG\r\n\x1a\n")
        self.outside = os.path.join(self.tmpdir, "secret.txt")
        with open(self.outside, "w", encoding="utf-8") as fh:
            fh.write("do not read me\n")

        self.api.route("/v1/runs", status=202, body={"run_id": "run_1", "status": "accepted"})
        self.api.route("/v1/runs/run_1", body={"run_id": "run_1", "status": "running"})
        self.api.route("/health/detailed", body={"status": "ok", "detail": "all green"})
        self.api.route("/api/sessions", body={"sessions": [{"id": "s1"}]})
        self.api.route("/api/jobs", body={"jobs": []})
        self.dash.route("/api/chat/image-upload", body={"path": self.staged, "bytes": 8})
        self.dash.route("/api/fs/read-data-url", body={"url": "data:image/png;base64,AAA"})
        self.dash.route("/api/config", body={"config": {"approvals": {"mode": "ask"}}})

        self.hub = HubServer(
            data_dir=self.tmpdir,
            upstream_base=self.api.base_url,
            upstream_key=UPSTREAM_KEY,
            admin_key=ADMIN_KEY,
            port=0,
            dashboard_base=self.dash.base_url,
            dashboard_key=DASH_KEY,
            fs_roots=[self.uploads],
        )
        self.hub.start()

    def tearDown(self):
        self.hub.stop()
        self.api.stop()
        self.dash.stop()
        super().tearDown()

    # -- helpers -----------------------------------------------------------

    def request(self, method, path, *, token=None, admin=None, body=None, headers=None, timeout=10):
        req = urllib.request.Request(f"{self.hub.address}{path}", method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if admin:
            req.add_header("X-Pi-Admin-Key", admin)
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        req.data = data
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def json_request(self, *args, **kwargs):
        status, headers, raw = self.request(*args, **kwargs)
        return status, (json.loads(raw) if raw else {})

    def register(self, name="Test-Laptop", scopes=("chat", "dispatch"), device_id=None):
        body = {"name": name, "scopes": list(scopes)}
        if device_id:
            body["deviceId"] = device_id
        status, payload = self.json_request("POST", "/v1/devices/register", admin=ADMIN_KEY, body=body)
        self.assertEqual(status, 201, payload)
        return payload["deviceId"], payload["token"]


class DeviceIdPinningTests(H1TestCase):
    def test_client_may_pin_the_device_id(self):
        device_id, _ = self.register(device_id="b8235e0e-1111-2222-3333-444455556666")
        self.assertEqual(device_id, "b8235e0e-1111-2222-3333-444455556666")

    def test_junk_device_id_falls_back_to_generated(self):
        body = {"name": "x", "deviceId": "../../etc/passwd"}
        status, payload = self.json_request("POST", "/v1/devices/register", admin=ADMIN_KEY, body=body)
        self.assertEqual(status, 201)
        self.assertNotEqual(payload["deviceId"], "../../etc/passwd")


class RunsProxyTests(H1TestCase):
    def test_start_run_rewrites_author_from_the_token(self):
        device_id, token = self.register(name="Test-Laptop")
        status, payload = self.json_request(
            "POST",
            "/v1/runs",
            token=token,
            body={"input": "hello", "author": {"id": "forged", "name": "someone else"}},
        )
        self.assertEqual(status, 202)
        self.assertEqual(payload["run_id"], "run_1")
        forwarded = json.loads(self.api.last()["body"])
        self.assertEqual(forwarded["author"], {
            "id": f"pi-workbench/{device_id}",
            "name": "Test-Laptop",
            "is_bot": False,
        })
        self.assertEqual(forwarded["input"], "hello")

    def test_idempotency_key_is_namespaced_per_device(self):
        device_id, token = self.register()
        self.request("POST", "/v1/runs", token=token, body={"input": "hi"},
                     headers={"Idempotency-Key": "turn-7"})
        self.assertEqual(
            self.api.last()["headers"]["idempotency-key"], f"pi:{device_id}:turn-7"
        )

    def test_already_prefixed_idempotency_key_is_left_alone(self):
        device_id, token = self.register()
        self.request("POST", "/v1/runs", token=token, body={"input": "hi"},
                     headers={"Idempotency-Key": f"pi:{device_id}:turn-7"})
        self.assertEqual(
            self.api.last()["headers"]["idempotency-key"], f"pi:{device_id}:turn-7"
        )

    def test_run_status_is_proxied(self):
        _, token = self.register()
        status, payload = self.json_request("GET", "/v1/runs/run_1", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(payload["status"], "running")

    def test_control_endpoints_are_proxied(self):
        _, token = self.register()
        for suffix in ("steer", "stop", "approval", "clarify", "resolve-unknown"):
            self.api.route(f"/v1/runs/run_1/{suffix}", body={"ok": True})
            status, _ = self.json_request("POST", f"/v1/runs/run_1/{suffix}", token=token, body={"x": 1})
            self.assertEqual(status, 200, suffix)
            self.assertEqual(self.api.last()["path"], f"/v1/runs/run_1/{suffix}")

    def test_runs_require_a_token(self):
        status, payload = self.json_request("POST", "/v1/runs", body={"input": "hi"})
        self.assertEqual(status, 401)
        self.assertEqual(self.api.requests, [])


class StreamTests(H1TestCase):
    def setUp(self):
        super().setUp()
        self.frames = [
            b"id: 0\ndata: {\"seq\":0,\"kind\":\"start\"}\n\n",
            b": keepalive\n\n",
            b"id: 1\ndata: {\"seq\":1,\"kind\":\"text\",\"text\":\"hi\"}\n\n",
            b"id: 2\ndata: {\"seq\":2,\"kind\":\"done\"}\n\n",
        ]
        self.api.stream("/v1/runs/run_1/events", self.frames)

    def _read_stream(self, token, last_event_id=None):
        req = urllib.request.Request(f"{self.hub.address}/v1/runs/run_1/events")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "text/event-stream")
        if last_event_id is not None:
            req.add_header("Last-Event-ID", str(last_event_id))
        received: list[bytes] = []
        with urllib.request.urlopen(req, timeout=10) as response:
            self.assertEqual(response.headers.get("Content-Type"), "text/event-stream")
            self.assertEqual(response.headers.get("X-Accel-Buffering"), "no")
            while True:
                chunk = response.read1(65536)
                if not chunk:
                    break
                received.append(chunk)
        return b"".join(received)

    def test_stream_is_forwarded_verbatim_in_order(self):
        _, token = self.register()
        body = self._read_stream(token)
        self.assertEqual(body, b"".join(self.frames))
        self.assertEqual(body.count(b"id: "), 3)

    def test_last_event_id_header_reaches_upstream(self):
        _, token = self.register()
        self._read_stream(token, last_event_id=1)
        self.assertEqual(self.api.last()["headers"].get("last-event-id"), "1")

    def test_stream_strips_client_auth_and_injects_upstream_key(self):
        device_id, token = self.register()
        self._read_stream(token)
        headers = self.api.last()["headers"]
        self.assertEqual(headers["authorization"], f"Bearer {UPSTREAM_KEY}")
        self.assertEqual(headers["x-pi-device"], device_id)
        self.assertEqual(headers["accept-encoding"], "identity")

    def test_stream_requires_token(self):
        status, _, raw = self.request("GET", "/v1/runs/run_1/events")
        self.assertEqual(status, 401)
        self.assertEqual(self.api.requests, [])


class ClientIpTests(H1TestCase):
    def test_forwarded_for_is_used_for_the_audit_ip(self):
        _, token = self.register()
        self.request(
            "POST", "/v1/runs", token=token, body={"input": "hi"},
            headers={"X-Forwarded-For": "203.0.113.9, 127.0.0.1"},
        )
        rows = self.hub.ctx.audit.recent(5)
        posts = [r for r in rows if r["path"] == "/v1/runs"]
        self.assertTrue(posts)
        self.assertEqual(posts[0]["ip"], "127.0.0.1")  # last hop wins

    def test_missing_forwarded_for_falls_back_to_peer(self):
        _, token = self.register()
        self.request("POST", "/v1/runs", token=token, body={"input": "hi"})
        rows = [r for r in self.hub.ctx.audit.recent(5) if r["path"] == "/v1/runs"]
        self.assertEqual(rows[0]["ip"], "127.0.0.1")


class SessionsAndJobsTests(H1TestCase):
    def test_sessions_are_proxied(self):
        _, token = self.register()
        status, payload = self.json_request("GET", "/api/sessions", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(payload["sessions"][0]["id"], "s1")

    def test_jobs_are_proxied(self):
        _, token = self.register()
        status, payload = self.json_request("GET", "/api/jobs", token=token)
        self.assertEqual(status, 200)
        self.assertIn("jobs", payload)

    def test_health_detailed_is_proxied(self):
        _, token = self.register()
        status, payload = self.json_request("GET", "/health/detailed", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(payload["detail"], "all green")


class DashboardSideChannelTests(H1TestCase):
    def test_image_upload_goes_to_dashboard_with_dashboard_key(self):
        _, token = self.register()
        status, payload = self.json_request(
            "POST", "/api/chat/image-upload", token=token,
            body={"dataUrl": "data:image/png;base64,AAA", "filename": "a.png"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["path"], self.staged)
        forwarded = self.dash.last()
        self.assertEqual(forwarded["headers"]["authorization"], f"Bearer {DASH_KEY}")
        self.assertEqual(self.api.requests, [])

    def test_fs_read_inside_uploads_is_allowed(self):
        _, token = self.register()
        status, payload = self.json_request(
            "GET", f"/api/fs/read-data-url?path={urllib.parse.quote(self.staged)}", token=token
        )
        self.assertEqual(status, 200)
        self.assertIn("url", payload)

    def test_fs_read_outside_roots_is_403_and_never_reaches_dashboard(self):
        _, token = self.register()
        status, payload = self.json_request(
            "GET", f"/api/fs/read-data-url?path={urllib.parse.quote(self.outside)}", token=token
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "path_not_allowed")
        self.assertEqual(self.dash.requests, [])

    def test_fs_read_relative_path_is_403(self):
        _, token = self.register()
        status, payload = self.json_request(
            "GET", "/api/fs/read-data-url?path=../../etc/passwd", token=token
        )
        self.assertEqual(status, 403)

    def test_config_read_is_allowed_with_chat_scope(self):
        """读审批档位是纯只读：设备凭 chat 就该读到，否则连接页显示不了当前档位。"""
        _, token = self.register(scopes=("chat",))
        status, payload = self.json_request("GET", "/api/config", token=token)
        self.assertEqual(status, 200, payload)
        self.assertIn("config", payload)

    def test_config_write_still_needs_admin_scope(self):
        """读放宽了，写没有：改审批档位仍然是 admin 的事。"""
        _, token = self.register(scopes=("chat",))
        status, payload = self.json_request(
            "PUT", "/api/config", token=token, body={"config": {"approvals": {"mode": "manual"}}}
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_required")

    def test_admin_scoped_token_may_read_config(self):
        _, token = self.register(scopes=("chat", "admin"))
        status, payload = self.json_request("GET", "/api/config", token=token)
        self.assertEqual(status, 200)
        self.assertIn("config", payload)

    def test_admin_scope_token_may_register_devices(self):
        _, token = self.register(name="ops", scopes=("chat", "admin"))
        status, payload = self.json_request(
            "POST", "/v1/devices/register", token=token, body={"name": "second"}
        )
        self.assertEqual(status, 201)
        self.assertEqual(payload["name"], "second")

    def test_chat_token_cannot_register_devices(self):
        _, token = self.register(scopes=("chat",))
        status, payload = self.json_request(
            "POST", "/v1/devices/register", token=token, body={"name": "second"}
        )
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "scope_required")


class FsGuardUnitTests(unittest.TestCase):
    def test_resolve_roots_from_env(self):
        roots = fsguard.resolve_roots(os.pathsep.join(("/a", "/b")), None)
        self.assertEqual(len(roots), 2)

    def test_default_roots_include_profile_uploads(self):
        roots = fsguard.default_roots("/home/x/.hermes/profiles/p")
        self.assertTrue(any(str(r).endswith("uploads") for r in roots))

    def test_default_roots_cover_where_the_dashboard_writes_images(self):
        """聊天里的图片路径是 `cache/images/…`，根里没有它 → 每张缩略图都 403。"""
        roots = fsguard.default_roots("/home/x/.hermes/profiles/p")
        joined = [str(r) for r in roots]
        self.assertTrue(any(path.endswith(os.path.join("cache", "images")) for path in joined))
        self.assertTrue(any(path.endswith("image_cache") for path in joined))

    def test_default_roots_never_include_browser_profile(self):
        """`cache/browser*` 里是 Cookie 和登录数据，绝不进白名单。"""
        roots = [str(r) for r in fsguard.default_roots("/home/x/.hermes/profiles/p")]
        self.assertFalse(any("browser" in path for path in roots))

    def test_rejects_empty_and_relative(self):
        for path in ("", "relative.txt"):
            with self.assertRaises(HubError) as ctx:
                fsguard.ensure_allowed(path, [])
            self.assertIn(ctx.exception.code, ("bad_request", "path_not_allowed"))

    def test_rejects_nonexistent(self):
        with self.assertRaises(HubError):
            fsguard.ensure_allowed("/definitely/not/here.txt", [])


if __name__ == "__main__":
    unittest.main()
