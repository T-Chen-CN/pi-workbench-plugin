"""Every environment variable this plugin reads, in one auditable place.

Two families, deliberately kept apart:

* **plugin-owned** (``PLUGIN_ENV``) — declared in ``plugin.yaml`` under
  ``requires_env`` / ``optional_env``, so ``hermes plugins show`` and the install
  prompt can see them. Changing one is a plugin change.
* **host-provided** (``HOST_ENV``) — set by the gateway or its systemd unit
  (api_server key, dashboard session token, profile home). We read them but must
  never ask the user for them: Hermes owns their lifecycle, and the manifest is
  not the place to duplicate host credentials.

``load()`` is a pure function over a mapping, which keeps the whole config layer
testable without Hermes and gives the gateway a cheap, side-effect free way to
inspect what the adapter would do.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Mapping

LOGGER = logging.getLogger("hermes.plugins.pi-workbench")

# --- defaults (also mirrored in the manifest descriptions) -----------------

DEFAULT_API_BASE = "http://127.0.0.1:8642"
DEFAULT_DASHBOARD_BASE = "http://127.0.0.1:9119"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8484
DEFAULT_RATE_LIMIT = 60

PLUGIN_ID = "pi-workbench"

# Declared in plugin.yaml. Keep both lists and the manifest in sync — the
# contract test (`tests/test_config.py`) fails when they drift.
PLUGIN_ENV = (
    "PI_HUB_ADMIN_KEY",
    "HERMES_API_BASE",
    "PI_HUB_PORT",
    "PI_HUB_HOST",
    "PI_HUB_RATE_LIMIT",
    "PI_HUB_DASHBOARD_BASE",
    "PI_HUB_FS_ROOTS",
)

# Owned by Hermes / systemd; read-only for us, never declared in the manifest.
HOST_ENV = (
    "API_SERVER_KEY",
    "HERMES_DASHBOARD_SESSION_TOKEN",
    "HERMES_HOME",
)


@dataclass(frozen=True)
class HubConfig:
    """Resolved configuration for one hub instance."""

    admin_key: str = ""
    api_base: str = DEFAULT_API_BASE
    api_key: str = ""
    dashboard_base: str = DEFAULT_DASHBOARD_BASE
    dashboard_key: str = ""
    host: str = DEFAULT_HOST
    port: int = DEFAULT_PORT
    rate_limit: int = DEFAULT_RATE_LIMIT
    fs_roots: str = ""
    profile_home: str = ""

    @property
    def admin_enabled(self) -> bool:
        """Registration/revocation need the admin key; everything else works without it."""
        return bool(self.admin_key)


def get(environ: Mapping[str, str] | None, name: str) -> str:
    """Read one variable, tolerating a mangled value (quotes, stray whitespace)."""
    if environ is None:
        environ = os.environ
    raw = environ.get(name)
    if raw is None:
        return ""
    return str(raw).strip().strip('"').strip("'")


def get_int(
    environ: Mapping[str, str] | None,
    name: str,
    default: int,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Parse an int, falling back to ``default`` on garbage *or* out-of-range values.

    A bad port must degrade to the default instead of raising inside the
    gateway's connect path: a config typo should never cost us the process.
    """
    raw = get(environ, name)
    if not raw:
        return default
    try:
        value = int(raw, 10)
    except (TypeError, ValueError):
        LOGGER.warning("[hub] %s=%r is not an integer, using %d", name, raw, default)
        return default
    if minimum is not None and value < minimum:
        LOGGER.warning("[hub] %s=%d is below %d, using %d", name, value, minimum, default)
        return default
    if maximum is not None and value > maximum:
        LOGGER.warning("[hub] %s=%d is above %d, using %d", name, value, maximum, default)
        return default
    return value


def load(environ: Mapping[str, str] | None = None) -> HubConfig:
    """Build a :class:`HubConfig` from the process environment (or any mapping)."""
    return HubConfig(
        admin_key=get(environ, "PI_HUB_ADMIN_KEY"),
        api_base=get(environ, "HERMES_API_BASE") or DEFAULT_API_BASE,
        api_key=get(environ, "API_SERVER_KEY"),
        dashboard_base=get(environ, "PI_HUB_DASHBOARD_BASE") or DEFAULT_DASHBOARD_BASE,
        dashboard_key=get(environ, "HERMES_DASHBOARD_SESSION_TOKEN"),
        host=get(environ, "PI_HUB_HOST") or DEFAULT_HOST,
        port=get_int(environ, "PI_HUB_PORT", DEFAULT_PORT, minimum=1, maximum=65535),
        rate_limit=get_int(environ, "PI_HUB_RATE_LIMIT", DEFAULT_RATE_LIMIT, minimum=1),
        fs_roots=get(environ, "PI_HUB_FS_ROOTS"),
        profile_home=get(environ, "HERMES_HOME"),
    )
