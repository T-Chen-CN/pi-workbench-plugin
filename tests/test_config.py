"""Contract tests: the manifest, the code, and the config layer must agree.

These are cheap drift detectors, not behaviour tests:

* every environment variable the code reads is either declared in
  ``plugin.yaml`` (plugin-owned) or listed in ``config.HOST_ENV`` (host-owned);
* every declared variable is actually read;
* ``plugin.yaml``'s ``version`` matches the version the hub reports;
* secrets are declared with the rich format (prompt hidden), and we declare no
  privileged ``capabilities`` we do not use.

They run with the standard library only — the same rule as the rest of the
suite — so the manifest is parsed with a tiny line scanner instead of PyYAML.
"""

from __future__ import annotations

import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import config  # noqa: E402
from core.server import VERSION  # noqa: E402

MANIFEST = os.path.join(ROOT, "plugin.yaml")


def manifest_text() -> str:
    with open(MANIFEST, encoding="utf-8") as handle:
        return handle.read()


def scalar(text: str, key: str) -> str | None:
    match = re.search(rf"^{key}:\s*(\S+)\s*$", text, re.MULTILINE)
    return match.group(1) if match else None


def block(text: str, key: str) -> str:
    """Return the raw YAML block for a top-level ``key:`` (until the next one)."""
    match = re.search(rf"^{key}:[^\n]*\n((?:[ \t]+.*\n|\n)*)", text, re.MULTILINE)
    return match.group(1) if match else ""


def declared_env_names(text: str) -> set[str]:
    names: set[str] = set()
    for key in ("requires_env", "optional_env"):
        for line in block(text, key).splitlines():
            item = re.match(r"^\s*-\s*(?:name:\s*)?([A-Z][A-Z0-9_]*)\s*$", line)
            if item:
                names.add(item.group(1))
    return names


_ENV_READ = re.compile(
    r"""(?:
        os\.environ\.get\(
      | os\.environ\[
      | os\.getenv\(
      | \b(?:config\.)?(?:get|get_int)\(\s*[A-Za-z_][\w.]*\s*,\s*
    )["']([A-Z][A-Z0-9_]*)["']""",
    re.VERBOSE,
)

# Our own namespaces: a literal matching this is an env variable even when it is
# read through an idiom the accessor pattern above does not know yet.
_NAMESPACED = re.compile(r"""["']((?:PI_|HERMES_)[A-Z0-9_]+)["']""")
_NOT_ENV = {"PI_WORKBENCH"}


def read_env_names() -> set[str]:
    """Every env variable name the non-test code mentions.

    Two nets: the accessor idioms we actually use, plus *any* literal in our own
    namespaces (``PI_*`` / ``HERMES_*``) so a future read pattern cannot slip
    past the check. ``PI_WORKBENCH`` is the gateway's enum attribute name.
    """
    names: set[str] = set()
    skip_dirs = {"tests", "__pycache__", ".git", ".pi-workbench"}
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [entry for entry in dirs if entry not in skip_dirs]
        for name in files:
            if not name.endswith(".py"):
                continue
            with open(os.path.join(base, name), encoding="utf-8") as handle:
                source = handle.read()
            names.update(_ENV_READ.findall(source))
            names.update(_NAMESPACED.findall(source))
    return names - _NOT_ENV


class ManifestContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = manifest_text()

    def test_it_is_a_v2_platform_plugin(self) -> None:
        self.assertEqual(scalar(self.text, "name"), "pi-workbench")
        self.assertEqual(scalar(self.text, "kind"), "platform")
        self.assertEqual(scalar(self.text, "manifest_version"), "2")
        self.assertEqual(scalar(self.text, "api_version"), "1")
        self.assertEqual(scalar(self.text, "license"), "MIT")
        self.assertEqual(
            scalar(self.text, "homepage"), "https://github.com/T-Chen-CN/pi-workbench-plugin"
        )

    def test_requires_hermes_range_is_pinned(self) -> None:
        # A missing upper bound is how a plugin silently rides into an API break.
        self.assertEqual(scalar(self.text, "requires_hermes"), '">=0.22.6,<0.24"')

    def test_manifest_version_matches_reported_version(self) -> None:
        self.assertEqual(scalar(self.text, "version"), VERSION)

    def test_license_file_matches_the_manifest(self) -> None:
        path = os.path.join(ROOT, "LICENSE")
        self.assertTrue(os.path.exists(path), "MIT declared in the manifest needs a LICENSE file")
        with open(path, encoding="utf-8") as handle:
            self.assertTrue(handle.readline().strip().endswith("MIT License"))

    def test_declares_no_privileged_capabilities(self) -> None:
        # We ask for no host surface (no tool override, no ctx.llm, no platform
        # actions), so there must be no consent prompt to answer.
        self.assertIsNone(scalar(self.text, "capabilities"))
        self.assertEqual(block(self.text, "capabilities").strip(), "")

    def test_admin_key_is_declared_as_a_hidden_secret(self) -> None:
        required = block(self.text, "requires_env")
        self.assertIn("PI_HUB_ADMIN_KEY", required)
        self.assertIn("secret: true", required)
        self.assertIn("password: true", required)

    def test_declared_env_matches_the_code(self) -> None:
        declared = declared_env_names(self.text)
        read = read_env_names()
        plugin_owned = set(config.PLUGIN_ENV)
        host_owned = set(config.HOST_ENV)

        self.assertEqual(declared, plugin_owned, "plugin.yaml and config.PLUGIN_ENV drifted")
        self.assertEqual(read, plugin_owned | host_owned, "code reads an undeclared env var")
        self.assertFalse(plugin_owned & host_owned, "a variable cannot be both ours and the host's")


class ConfigLoadTest(unittest.TestCase):
    def test_defaults(self) -> None:
        cfg = config.load({})
        self.assertEqual(cfg.api_base, config.DEFAULT_API_BASE)
        self.assertEqual(cfg.dashboard_base, config.DEFAULT_DASHBOARD_BASE)
        self.assertEqual(cfg.host, config.DEFAULT_HOST)
        self.assertEqual(cfg.port, config.DEFAULT_PORT)
        self.assertEqual(cfg.rate_limit, config.DEFAULT_RATE_LIMIT)
        self.assertEqual(cfg.fs_roots, "")
        self.assertFalse(cfg.admin_enabled)

    def test_reads_every_plugin_owned_variable(self) -> None:
        env = {
            "PI_HUB_ADMIN_KEY": "k",
            "HERMES_API_BASE": "http://127.0.0.1:9999",
            "PI_HUB_PORT": "8585",
            "PI_HUB_HOST": "127.0.0.2",
            "PI_HUB_RATE_LIMIT": "120",
            "PI_HUB_DASHBOARD_BASE": "http://127.0.0.1:9998",
            "PI_HUB_FS_ROOTS": "/tmp/a:/tmp/b",
        }
        cfg = config.load(env)
        self.assertEqual(cfg.admin_key, "k")
        self.assertTrue(cfg.admin_enabled)
        self.assertEqual(cfg.api_base, "http://127.0.0.1:9999")
        self.assertEqual(cfg.port, 8585)
        self.assertEqual(cfg.host, "127.0.0.2")
        self.assertEqual(cfg.rate_limit, 120)
        self.assertEqual(cfg.dashboard_base, "http://127.0.0.1:9998")
        self.assertEqual(cfg.fs_roots, "/tmp/a:/tmp/b")

    def test_host_owned_variables_pass_through(self) -> None:
        cfg = config.load({"API_SERVER_KEY": "up", "HERMES_HOME": "/srv/hermes/profiles/p"})
        self.assertEqual(cfg.api_key, "up")
        self.assertEqual(cfg.profile_home, "/srv/hermes/profiles/p")

    def test_garbage_values_degrade_instead_of_raising(self) -> None:
        cfg = config.load({"PI_HUB_PORT": "eighty-forty"})
        self.assertEqual(cfg.port, config.DEFAULT_PORT)
        cfg = config.load({"PI_HUB_RATE_LIMIT": ""})
        self.assertEqual(cfg.rate_limit, config.DEFAULT_RATE_LIMIT)

    def test_out_of_range_values_fall_back(self) -> None:
        # 70000 would raise OverflowError in the socket layer: never let a typo
        # reach ThreadingHTTPServer.
        self.assertEqual(config.load({"PI_HUB_PORT": "70000"}).port, config.DEFAULT_PORT)
        self.assertEqual(config.load({"PI_HUB_PORT": "0"}).port, config.DEFAULT_PORT)
        self.assertEqual(config.load({"PI_HUB_RATE_LIMIT": "0"}).rate_limit, config.DEFAULT_RATE_LIMIT)

    def test_quoted_values_are_unwrapped(self) -> None:
        self.assertEqual(config.load({"PI_HUB_HOST": ' "10.0.0.5" '}).host, "10.0.0.5")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
