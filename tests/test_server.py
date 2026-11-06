"""End-to-end hub behaviour against a fake api_server.

These tests are the G0 acceptance criteria in code form: a token works, no token
is a 401, revocation is immediate, scopes are enforced, and the proxy rewrites
identity instead of trusting the client.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from core.server import HubServer  # noqa: E402
from tests import TempDirMixin  # noqa: E402
from tests.fake_upstream import FakeUpstream  # noqa: E402

ADMIN_KEY = "admin-secret"
UPSTREAM_KEY = "upstream-secret"


class HubTestCase(TempDirMixin):
    rate_limit = 1000

    def setUp(self):
        super().setUp()
        self.upstream = FakeUpstream(api_key=UPSTREAM_KEY).start()
        self.upstream.route(
            "/health", body={"status": "ok", "platform": "hermes-agent", "version": "0.22.6"}
        )
        self.upstream.route(
            "/v1/capabilities",
            body={"version": "0.22.6", "platforms": ["api_server"], "tools": ["read_file"]},
        )
        self.upstream.route("/v1/toolsets", body={"toolsets": ["file", "terminal"]})
        self.hub = HubServer(
            data_dir=self.tmpdir,
            upstream_base=self.upstream.base_url,
            upstream_key=UPSTREAM_KEY,
            admin_key=ADMIN_KEY,
            port=0,
            rate_limit=self.rate_limit,
        )
        self.hub.start()

    def tearDown(self):
        self.hub.stop()
        self.upstream.stop()
        super().tearDown()

    # -- helpers -----------------------------------------------------------

    def call(self, method, path, *, token=None, admin=None, body=None, headers=None):
        url = f"{self.hub.address}{path}"
        data = None
        if body is not None:
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method)
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        if admin:
            req.add_header("X-Pi-Admin-Key", admin)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        for key, value in (headers or {}).items():
            req.add_header(key, value)
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                raw = response.read()
                return response.status, dict(response.headers), raw
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers), exc.read()

    def json_call(self, *args, **kwargs):
        status, headers, raw = self.call(*args, **kwargs)
        return status, (json.loads(raw) if raw else {}), raw

    def register(self, name="Test-Laptop", scopes=None):
        body = {"name": name}
        if scopes:
            body["scopes"] = scopes
        status, payload, _ = self.json_call("POST", "/v1/devices/register", admin=ADMIN_KEY, body=body)
        self.assertEqual(status, 201, payload)
        return payload["deviceId"], payload["token"]

    def error_code(self, raw):
        return json.loads(raw)["error"]["code"]


class HealthTests(HubTestCase):
    def test_hub_health_is_anonymous(self):
        status, payload, _ = self.json_call("GET", "/v1/hub/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload["hub"], "0.1.0")
        self.assertTrue(payload["upstreamOk"])
        self.assertEqual(payload["upstreamVersion"], "0.22.6")
        self.assertTrue(payload["adminKeyConfigured"])

    def test_hub_health_reports_upstream_down(self):
        self.upstream.stop()
        status, payload, _ = self.json_call("GET", "/v1/hub/health")
        self.assertEqual(status, 503)
        self.assertFalse(payload["upstreamOk"])
        self.assertIn("upstreamError", payload)

    def test_health_passthrough_is_anonymous_and_forwarded(self):
        status, _, raw = self.call("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["status"], "ok")
        self.assertEqual(self.upstream.last()["path"], "/health")

    def test_unknown_route_is_404(self):
        status, payload, _ = self.json_call("GET", "/v1/nope")
        self.assertEqual(status, 404)
        self.assertEqual(payload["error"]["code"], "not_found")

    def test_wrong_method_is_405(self):
        status, payload, _ = self.json_call("POST", "/v1/hub/health")
        self.assertEqual(status, 405)
        self.assertEqual(payload["error"]["code"], "method_not_allowed")


class AuthenticationTests(HubTestCase):
    def test_capabilities_without_token_is_401(self):
        status, payload, _ = self.json_call("GET", "/v1/capabilities")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "unauthorized")
        self.assertEqual(self.upstream.requests, [])  # never reached the agent

    def test_capabilities_with_valid_token_is_200(self):
        _, token = self.register()
        status, payload, _ = self.json_call("GET", "/v1/capabilities", token=token)
        self.assertEqual(status, 200)
        self.assertIn("platforms", payload)

    def test_revoked_token_is_401_immediately(self):
        device_id, token = self.register()
        self.assertEqual(self.json_call("GET", "/v1/capabilities", token=token)[0], 200)
        status, payload, _ = self.json_call("POST", f"/v1/devices/{device_id}/revoke", admin=ADMIN_KEY)
        self.assertEqual(status, 200)
        status, payload, _ = self.json_call("GET", "/v1/capabilities", token=token)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "device_revoked")

    def test_revoking_one_device_leaves_the_other_working(self):
        device_a, token_a = self.register("a")
        _, token_b = self.register("b")
        self.json_call("POST", f"/v1/devices/{device_a}/revoke", admin=ADMIN_KEY)
        self.assertEqual(self.json_call("GET", "/v1/capabilities", token=token_a)[0], 401)
        self.assertEqual(self.json_call("GET", "/v1/capabilities", token=token_b)[0], 200)

    def test_junk_bearer_is_401(self):
        for header in ("", "Bearer", "Basic abc", "Bearer pi_deadbeef"):
            status, payload, _ = self.json_call(
                "GET", "/v1/capabilities", headers={"Authorization": header, "X-Pi-Device": "forged"}
            )
            self.assertEqual(status, 401, header)

    def test_device_me_returns_token_identity(self):
        device_id, token = self.register("Test-Laptop", scopes=["chat", "dispatch"])
        status, payload, _ = self.json_call("GET", "/v1/devices/me", token=token)
        self.assertEqual(status, 200)
        self.assertEqual(payload["deviceId"], device_id)
        self.assertEqual(payload["name"], "Test-Laptop")
        self.assertEqual(payload["scopes"], ["chat", "dispatch"])
        # 在线判定窗口要跟着设备一起回，本地不必猜
        self.assertEqual(payload["onlineWindow"], 90)
        self.assertTrue(payload["online"])


class HeartbeatTests(HubTestCase):
    def test_heartbeat_refreshes_last_seen(self):
        device_id, token = self.register("legion")
        status, payload, _ = self.json_call("POST", "/v1/devices/me/heartbeat", token=token)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["deviceId"], device_id)
        self.assertEqual(payload["onlineWindow"], 90)
        self.assertIsInstance(payload["serverTime"], int)

        status, listing, _ = self.json_call("GET", "/v1/devices", admin=ADMIN_KEY)
        self.assertEqual(status, 200)
        row = [d for d in listing["devices"] if d["deviceId"] == device_id][0]
        self.assertTrue(row["online"])
        self.assertGreaterEqual(row["lastSeenAt"], payload["serverTime"] - 2)

    def test_heartbeat_needs_a_device_token(self):
        status, payload, _ = self.json_call("POST", "/v1/devices/me/heartbeat")
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "unauthorized")

    def test_a_revoked_device_cannot_keep_heartbeating(self):
        device_id, token = self.register()
        self.json_call("POST", f"/v1/devices/{device_id}/revoke", admin=ADMIN_KEY)
        status, payload, _ = self.json_call("POST", "/v1/devices/me/heartbeat", token=token)
        self.assertEqual(status, 401)
        self.assertEqual(payload["error"]["code"], "device_revoked")


class AdminTests(HubTestCase):
    def test_a_device_can_revoke_itself_with_chat_scope(self):
        """注销按钮用的是设备 token（只有 chat/dispatch）——自注销不能要求 admin。

        否则用户点「注销这台设备」只会看到一个 403 scope_required。
        """
        device_id, token = self.register(scopes=["chat", "dispatch"])
        status, payload, _ = self.json_call("POST", f"/v1/devices/{device_id}/revoke", token=token)
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["revoked"])

        after, _, raw = self.call("GET", "/v1/devices/me", token=token)
        self.assertEqual(after, 401)
        self.assertEqual(self.error_code(raw), "device_revoked")

    def test_a_device_cannot_revoke_someone_else(self):
        """自己注销自己是自助，注销**别的**设备仍然要 admin。"""
        _, token = self.register("a", scopes=["chat", "dispatch"])
        other, _ = self.register("b", scopes=["chat", "dispatch"])
        status, payload, _ = self.json_call("POST", f"/v1/devices/{other}/revoke", token=token)
        self.assertEqual(status, 403, payload)
        self.assertEqual(payload["error"]["code"], "scope_required")

    def test_registering_a_known_id_returns_200_and_rotates(self):
        """已登记的 id 再登记 → 200 + rotated，绝不能 500（应用里就点这一个按钮）"""
        body = {"deviceId": "dev-same", "name": "Test-Laptop", "scopes": ["chat"]}
        first_status, first, _ = self.json_call(
            "POST", "/v1/devices/register", admin=ADMIN_KEY, body=body
        )
        self.assertEqual(first_status, 201)
        self.assertFalse(first["rotated"])

        second_status, second, _ = self.json_call(
            "POST", "/v1/devices/register", admin=ADMIN_KEY, body=body
        )
        self.assertEqual(second_status, 200)
        self.assertTrue(second["rotated"])
        self.assertEqual(second["deviceId"], "dev-same")
        self.assertNotEqual(second["token"], first["token"])

        # 新 token 能用，旧 token 立刻不能
        ok, _, _ = self.call("GET", "/v1/devices/me", token=second["token"])
        self.assertEqual(ok, 200)
        stale, _, raw = self.call("GET", "/v1/devices/me", token=first["token"])
        self.assertEqual(stale, 401)
        self.assertEqual(self.error_code(raw), "unauthorized")

    def test_register_requires_admin_key(self):
        status, payload, _ = self.json_call("POST", "/v1/devices/register", body={"name": "x"})
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"]["code"], "admin_required")

    def test_register_with_wrong_admin_key_is_403(self):
        status, payload, _ = self.json_call(
            "POST", "/v1/devices/register", admin="nope", body={"name": "x"}
        )
        self.assertEqual(status, 403)

    def test_register_returns_token_once_and_never_again(self):
        _, token = self.register()
        status, payload, raw = self.json_call("GET", "/v1/devices", admin=ADMIN_KEY)
        self.assertEqual(status, 200)
        self.assertNotIn(token, raw.decode())
        self.assertEqual(payload["devices"][0]["tokenPrefix"], token[:12])

    def test_device_list_shows_online_after_use(self):
        _, token = self.register()
        self.json_call("GET", "/v1/capabilities", token=token)
        _, payload, _ = self.json_call("GET", "/v1/devices", admin=ADMIN_KEY)
        self.assertTrue(payload["devices"][0]["online"])

    def test_hub_without_admin_key_disables_registration(self):
        self.hub.stop()
        self.hub = HubServer(
            data_dir=os.path.join(self.tmpdir, "no-admin"),
            upstream_base=self.upstream.base_url,
            upstream_key=UPSTREAM_KEY,
            admin_key="",
            port=0,
        )
        self.hub.start()
        status, payload, _ = self.json_call("POST", "/v1/devices/register", admin="anything", body={})
        self.assertEqual(status, 503)
        self.assertEqual(payload["error"]["code"], "hub_disabled")


class ScopeTests(HubTestCase):
    def test_chat_only_device_can_read(self):
        _, token = self.register(scopes=["chat"])
        self.assertEqual(self.json_call("GET", "/v1/capabilities", token=token)[0], 200)


class RateLimitTests(HubTestCase):
    rate_limit = 3

    def test_fourth_request_in_a_minute_is_429(self):
        _, token = self.register()
        codes = [self.json_call("GET", "/v1/capabilities", token=token)[0] for _ in range(3)]
        self.assertEqual(codes, [200, 200, 200])
        status, payload, raw = self.json_call("GET", "/v1/capabilities", token=token)
        self.assertEqual(status, 429)
        self.assertEqual(payload["error"]["code"], "rate_limited")

    def test_429_carries_retry_after(self):
        _, token = self.register()
        for _ in range(3):
            self.json_call("GET", "/v1/capabilities", token=token)
        status, headers, _ = self.call("GET", "/v1/capabilities", token=token)
        self.assertEqual(status, 429)
        self.assertIn("Retry-After", headers)

    def test_limits_are_per_device(self):
        _, token_a = self.register("a")
        _, token_b = self.register("b")
        for _ in range(3):
            self.json_call("GET", "/v1/capabilities", token=token_a)
        self.assertEqual(self.json_call("GET", "/v1/capabilities", token=token_a)[0], 429)
        self.assertEqual(self.json_call("GET", "/v1/capabilities", token=token_b)[0], 200)


class ProxyTests(HubTestCase):
    def test_upstream_auth_is_rewritten_and_device_header_injected(self):
        device_id, token = self.register()
        self.call(
            "GET",
            "/v1/capabilities",
            token=token,
            headers={"Authorization": f"Bearer {token}", "X-Pi-Device": "forged"},
        )
        forwarded = self.upstream.last()
        self.assertEqual(forwarded["headers"]["authorization"], f"Bearer {UPSTREAM_KEY}")
        self.assertEqual(forwarded["headers"]["x-pi-device"], device_id)  # client value dropped
        self.assertEqual(forwarded["headers"]["accept-encoding"], "identity")

    def test_read_only_get_is_cached(self):
        _, token = self.register()
        for _ in range(3):
            self.assertEqual(self.json_call("GET", "/v1/capabilities", token=token)[0], 200)
        forwarded = [r for r in self.upstream.requests if r["path"] == "/v1/capabilities"]
        self.assertEqual(len(forwarded), 1)

    def test_upstream_down_reports_502(self):
        _, token = self.register()
        self.hub.ctx.api.flush_cache()
        self.upstream.stop()
        status, payload, _ = self.json_call("GET", "/v1/toolsets", token=token)
        self.assertEqual(status, 502)
        self.assertEqual(payload["error"]["code"], "upstream_unavailable")

    def test_upstream_error_status_is_passed_through(self):
        self.upstream.route("/v1/models", status=418, body={"error": {"code": "teapot"}})
        _, token = self.register()
        status, payload, _ = self.json_call("GET", "/v1/models", token=token)
        self.assertEqual(status, 418)
        self.assertEqual(payload["error"]["code"], "teapot")  # not rewritten to a hub code


class AuditTests(HubTestCase):
    def test_register_and_revoke_are_audited_to_jsonl(self):
        device_id, _ = self.register()
        self.json_call("POST", f"/v1/devices/{device_id}/revoke", admin=ADMIN_KEY)
        path = os.path.join(self.tmpdir, "audit.jsonl")
        self.assertTrue(os.path.exists(path))
        kinds = [json.loads(line)["kind"] for line in open(path, encoding="utf-8")]
        self.assertIn("device.register", kinds)
        self.assertIn("device.revoke", kinds)

    def test_audit_never_contains_tokens_or_admin_key(self):
        device_id, token = self.register()
        self.json_call("POST", f"/v1/devices/{device_id}/revoke", admin=ADMIN_KEY)
        contents = open(os.path.join(self.tmpdir, "audit.jsonl"), encoding="utf-8").read()
        self.assertNotIn(token, contents)
        self.assertNotIn(ADMIN_KEY, contents)


if __name__ == "__main__":
    unittest.main()
