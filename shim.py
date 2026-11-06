"""The only file in this plugin that touches the Hermes plugin API.

Keep it small: upstream signature churn should never reach ``core/``.

Responsibilities
----------------
* declare the platform to the gateway (``register_platform``) so the gateway
  owns the hub server's lifecycle (start on connect, stop on disconnect);
* resolve where durable state may live (``plugin_data_dir``) and hand it to
  ``core``;
* read configuration through ``config.load()`` (one auditable place for env).

Nothing here raises at import time: a broken hub must degrade to a logged
warning, never to an import error that would take the gateway down with it.
"""

from __future__ import annotations

import logging

from . import config

logger = logging.getLogger("hermes.plugins.pi-workbench")

PLUGIN_ID = config.PLUGIN_ID
PLATFORM_NAME = "pi-workbench"
PLATFORM_LABEL = "Pi Workbench"

# Kept as module attributes so `adapter.py` and older imports keep working.
DEFAULT_API_BASE = config.DEFAULT_API_BASE
DEFAULT_DASHBOARD_BASE = config.DEFAULT_DASHBOARD_BASE
DEFAULT_HOST = config.DEFAULT_HOST
DEFAULT_PORT = config.DEFAULT_PORT
DEFAULT_RATE_LIMIT = config.DEFAULT_RATE_LIMIT


def _deps_ok() -> bool:
    """Passive probe: are the stdlib modules we need importable?

    Must never install anything — the gateway calls it freely for status
    displays.
    """
    try:
        import http.client  # noqa: F401
        import http.server  # noqa: F401
        import sqlite3  # noqa: F401
        import urllib.request  # noqa: F401
    except Exception:  # pragma: no cover - stdlib, but never break the gateway
        logger.warning("[hub] stdlib probe failed", exc_info=True)
        return False
    return True


def _data_dir():
    """Durable state root, resolved through Hermes so it follows the profile."""
    from plugins.plugin_storage import plugin_data_dir

    return plugin_data_dir(PLUGIN_ID)


def _make_adapter(platform_config):
    from .adapter import PiWorkbenchAdapter

    return PiWorkbenchAdapter(platform_config, _data_dir=_data_dir())


def register(ctx) -> None:
    """Called once per process by the Hermes plugin loader."""
    cfg = config.load()
    if not cfg.admin_enabled:
        logger.warning(
            "[hub] PI_HUB_ADMIN_KEY is not set: device registration/revocation is disabled. "
            "Set it in the gateway systemd unit (not in .env: the agent can read that)."
        )

    ctx.register_platform(
        name=PLATFORM_NAME,
        label=PLATFORM_LABEL,
        adapter_factory=_make_adapter,
        check_fn=_deps_ok,
        required_env=["PI_HUB_ADMIN_KEY"],
        install_hint="set PI_HUB_ADMIN_KEY in the gateway service environment",
    )
    logger.info(
        "[hub] platform registered (port=%s admin_key=%s)",
        cfg.port,
        "set" if cfg.admin_enabled else "MISSING",
    )
