"""Thin ``BasePlatformAdapter`` implementation.

The hub is a *web* entry, not a chat surface: we never receive inbound chat
messages, so ``send()`` is unsupported and no session is created by us. What we
need from the gateway is the lifecycle — ``connect()`` starts the loopback HTTP
server, ``disconnect()`` stops it and closes the SQLite handles.

This module is imported lazily (only when the gateway actually builds the
adapter), so importing ``gateway.*`` at module level is safe here and keeps the
code obvious.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from gateway.config import Platform
from gateway.platforms.base import BasePlatformAdapter, SendResult

from . import config

logger = logging.getLogger("hermes.plugins.pi-workbench")

PLATFORM_NAME = "pi-workbench"
# Enum member names are upper snake case upstream; try it as a fallback in case
# a future release stops accepting arbitrary values in `Platform("...")`.
PLATFORM_ENUM_ATTR = "PI_WORKBENCH"
_LOG_PREFIX = "[hub]"


def _resolve_platform():
    """Best-effort mapping from our platform id to the gateway's enum member.

    ``Platform("pi-workbench")`` works on 0.22.6 (plain value lookup). If a later
    release tightens ``Platform`` into a strict enum, we fall back to a symbol
    lookup and, failing that, to the bare string so the adapter can still be
    constructed instead of taking the gateway's startup down.
    """
    for build in (lambda: Platform(PLATFORM_NAME), lambda: getattr(Platform, PLATFORM_ENUM_ATTR)):
        try:
            return build()
        except Exception:
            continue
    logger.warning(
        "%s gateway Platform has no member for %r: falling back to the raw id. "
        "This is expected to keep working but is worth reporting upstream.",
        _LOG_PREFIX,
        PLATFORM_NAME,
    )
    return PLATFORM_NAME


class PiWorkbenchAdapter(BasePlatformAdapter):
    def __init__(self, platform_config, *, _data_dir=None):
        super().__init__(platform_config, _resolve_platform())
        self._data_dir = _data_dir
        self._hub = None

    # -- lifecycle ---------------------------------------------------------

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        if self._hub is not None and self._hub.is_running:
            logger.info("%s already listening on %s", _LOG_PREFIX, self._hub.address)
            return True

        from .core import fsguard
        from .core.server import HubServer

        cfg = config.load()
        if not cfg.api_key:
            logger.error(
                "%s API_SERVER_KEY is not visible to the gateway process: "
                "proxied calls to api_server will fail with 401",
                _LOG_PREFIX,
            )
        try:
            hub = HubServer(
                data_dir=self._data_dir,
                upstream_base=cfg.api_base,
                upstream_key=cfg.api_key,
                admin_key=cfg.admin_key,
                host=cfg.host,
                port=cfg.port,
                rate_limit=cfg.rate_limit,
                dashboard_base=cfg.dashboard_base,
                dashboard_key=cfg.dashboard_key,
                fs_roots=fsguard.resolve_roots(cfg.fs_roots, cfg.profile_home),
            )
            hub.start()
        except OSError as exc:
            # A taken port must never take the gateway down: report "not
            # connected" and let the gateway retry like any other platform.
            logger.error("%s failed to listen: %s", _LOG_PREFIX, exc)
            return False
        except Exception:
            # Anything else (bad config value, unreadable data dir, sqlite
            # failure) is still *our* problem: log it and let the gateway treat
            # us as an unavailable platform instead of crashing the process.
            logger.error("%s failed to start", _LOG_PREFIX, exc_info=True)
            return False
        self._hub = hub
        logger.info("%s listening on %s -> %s", _LOG_PREFIX, hub.address, hub.upstream_base)
        return True

    async def disconnect(self) -> None:
        hub, self._hub = self._hub, None
        if hub is None:
            return
        hub.stop()
        logger.info("%s stopped", _LOG_PREFIX)

    # -- chat surface (intentionally unsupported) --------------------------

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[dict] = None,
    ) -> SendResult:
        return SendResult(
            success=False,
            error="pi-workbench hub does not deliver chat messages; talk to it over HTTP",
        )

    async def get_chat_info(self, chat_id: str) -> dict[str, Any]:
        return {"name": PLATFORM_NAME, "type": "channel"}
