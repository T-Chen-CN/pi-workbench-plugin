"""Token, scope and rate-limit behaviour — the hub's whole security story."""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)

from core.db import Database  # noqa: E402
from core.errors import HubError  # noqa: E402
from tests import TempDirMixin  # noqa: E402
from core import auth  # noqa: E402


class TokenShapeTests(unittest.TestCase):
    def test_token_is_urlsafe_and_prefixed(self):
        token = auth.new_token()
        self.assertTrue(token.startswith(auth.TOKEN_PREFIX))
        body = token[len(auth.TOKEN_PREFIX):]
        self.assertGreaterEqual(len(body), 40)
        self.assertNotIn("=", body)
        self.assertNotIn("+", body)
        self.assertNotIn("/", body)

    def test_tokens_are_unique(self):
        self.assertEqual(len({auth.new_token() for _ in range(200)}), 200)

    def test_hash_is_stable_and_not_the_token(self):
        token = auth.new_token()
        self.assertEqual(auth.hash_token(token), auth.hash_token(token))
        self.assertNotEqual(auth.hash_token(token), token)
        self.assertEqual(len(auth.hash_token(token)), 64)

    def test_looks_like_token_rejects_junk(self):
        self.assertTrue(auth.looks_like_token(auth.new_token()))
        for junk in ("", "pi_", "sk-abc", "pi_" + "x" * 200, "Bearer pi_abc", None):
            self.assertFalse(auth.looks_like_token(junk or ""), junk)

    def test_token_prefix_is_first_12_chars(self):
        token = auth.new_token()
        self.assertEqual(auth.token_prefix(token), token[:12])


class DeviceRegistryTests(TempDirMixin):
    def setUp(self):
        super().setUp()
        self.db = Database(os.path.join(self.tmpdir, "hub.db"))
        self.auth = auth.Authenticator(self.db, rate_limit=5)

    def tearDown(self):
        self.db.close()
        super().tearDown()

    def test_reregistering_the_same_id_rotates_the_token(self):
        """同一个 id 再登记必须换 token，而不是撞主键报 500。

        真实场景：本机 `connection.json` 里的 token 丢了、应用重装、或者误点注销
        —— 用户会再按一次「登记」，那时 id 还是同一个（id 是身份，不该变）。
        """
        first, token_a, rotated_a = self.auth.register_device("Test-Laptop", device_id="dev-1")
        self.assertFalse(rotated_a)

        second, token_b, rotated_b = self.auth.register_device(
            "Test-Laptop-2", device_id="dev-1", scopes=("chat",)
        )
        self.assertTrue(rotated_b)
        self.assertEqual(second["id"], first["id"])
        self.assertNotEqual(token_a, token_b)
        self.assertEqual(second["name"], "Test-Laptop-2")
        self.assertEqual(second["scopes"], "chat")

        # 一台设备不允许同时有两个活 token：旧的立刻失效
        self.auth.authenticate(token_b)
        with self.assertRaises(auth.HubError):
            self.auth.authenticate(token_a)

    def test_reregistering_reactivates_a_revoked_device(self):
        row, token, _ = self.auth.register_device("d", device_id="dev-2")
        self.assertTrue(self.auth.revoke_device(row["id"]))
        with self.assertRaises(auth.HubError):
            self.auth.authenticate(token)

        revived, token_2, rotated = self.auth.register_device("d", device_id="dev-2")
        self.assertTrue(rotated)
        self.assertIsNone(revived["revoked_at"])
        self.assertEqual(self.auth.authenticate(token_2)["id"], "dev-2")

    def test_register_returns_row_and_plaintext_once(self):
        row, token, _rotated = self.auth.register_device("Test-Laptop")
        self.assertTrue(token.startswith("pi_"))
        self.assertEqual(row["name"], "Test-Laptop")
        self.assertEqual(row["scopes"], "chat")
        self.assertNotIn(token, str(dict(row)))  # only the hash is stored
        self.assertEqual(row["token_hash"], auth.hash_token(token))

    def test_register_normalises_name(self):
        row, _, _rotated = self.auth.register_device("  TChen \t  Legion  ")
        self.assertEqual(row["name"], "TChen Legion")

    def test_register_clamps_name_length(self):
        row, _, _rotated = self.auth.register_device("x" * 200)
        self.assertEqual(len(row["name"]), 40)

    def test_register_rejects_unknown_scopes(self):
        row, _, _rotated = self.auth.register_device("d", scopes=("root", "chat"))
        self.assertEqual(row["scopes"], "chat")

    def test_register_with_no_valid_scope_falls_back_to_chat(self):
        row, _, _rotated = self.auth.register_device("d", scopes=("root",))
        self.assertEqual(row["scopes"], "chat")

    def test_authenticate_accepts_valid_token(self):
        row, token, _rotated = self.auth.register_device("d", scopes=("chat", "dispatch"))
        device = self.auth.authenticate(token)
        self.assertEqual(device["id"], row["id"])

    def test_authenticate_rejects_unknown_token(self):
        self.auth.register_device("d")
        with self.assertRaises(HubError) as ctx:
            self.auth.authenticate(auth.new_token())
        self.assertEqual(ctx.exception.code, "unauthorized")
        self.assertEqual(ctx.exception.status, 401)

    def test_authenticate_rejects_garbage(self):
        for junk in (None, "", "hello", "Bearer pi_x"):
            with self.assertRaises(HubError):
                self.auth.authenticate(junk)

    def test_revoked_device_is_rejected_immediately(self):
        row, token, _rotated = self.auth.register_device("d")
        self.assertTrue(self.auth.revoke_device(row["id"]))
        with self.assertRaises(HubError) as ctx:
            self.auth.authenticate(token)
        self.assertEqual(ctx.exception.code, "device_revoked")

    def test_revoke_is_idempotent(self):
        row, _, _rotated = self.auth.register_device("d")
        self.assertTrue(self.auth.revoke_device(row["id"]))
        self.assertFalse(self.auth.revoke_device(row["id"]))

    def test_revoke_only_affects_one_device(self):
        row_a, token_a, _rotated = self.auth.register_device("a")
        _, token_b, _rotated = self.auth.register_device("b")
        self.auth.revoke_device(row_a["id"])
        self.auth.authenticate(token_b)  # must not raise

    def test_scope_enforcement(self):
        _, token, _rotated = self.auth.register_device("d", scopes=("chat",))
        device = self.auth.authenticate(token)
        self.auth.require_scope(device, "chat")
        with self.assertRaises(HubError) as ctx:
            self.auth.require_scope(device, "dispatch")
        self.assertEqual(ctx.exception.code, "scope_required")
        self.assertEqual(ctx.exception.status, 403)

    def test_admin_key_is_required_and_constant_time(self):
        self.auth.check_admin("k", "k")
        for wrong in (None, "", "K", "kk"):
            with self.assertRaises(HubError) as ctx:
                self.auth.check_admin(wrong, "k")
            self.assertEqual(ctx.exception.code, "admin_required")

    def test_missing_admin_key_disables_administration(self):
        with self.assertRaises(HubError) as ctx:
            self.auth.check_admin("anything", "")
        self.assertEqual(ctx.exception.code, "hub_disabled")

    def test_touch_updates_last_seen(self):
        row, token, _rotated = self.auth.register_device("d")
        self.auth.touch(row["id"], now=1000)
        device = self.auth.authenticate(token)
        self.assertEqual(device["last_seen_at"], 1000)

    def test_list_devices_hides_secrets(self):
        self.auth.register_device("d")
        devices = self.auth.list_devices()
        self.assertEqual(len(devices), 1)
        self.assertNotIn("token_hash", devices[0])
        self.assertIn("token_prefix", devices[0])


class RateLimiterTests(unittest.TestCase):
    def test_allows_up_to_limit_then_rejects(self):
        limiter = auth.RateLimiter(limit=3, window=60)
        for i in range(3):
            limiter.check("dev", now=1000 + i)
        with self.assertRaises(HubError) as ctx:
            limiter.check("dev", now=1003)
        self.assertEqual(ctx.exception.code, "rate_limited")
        self.assertEqual(ctx.exception.status, 429)
        self.assertIsNotNone(ctx.exception.retry_after)
        self.assertGreaterEqual(ctx.exception.retry_after, 1)

    def test_window_slides(self):
        limiter = auth.RateLimiter(limit=2, window=60)
        limiter.check("dev", now=1000)
        limiter.check("dev", now=1001)
        limiter.check("dev", now=1062)  # first hit has expired
        limiter.check("dev", now=1063)

    def test_buckets_are_per_device(self):
        limiter = auth.RateLimiter(limit=1, window=60)
        limiter.check("a", now=1000)
        limiter.check("b", now=1000)


if __name__ == "__main__":
    unittest.main()
