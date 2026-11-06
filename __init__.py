"""Pi Workbench hub plugin (Hermes ``kind: platform``).

``register()`` is the only entry point Hermes calls. All the interesting code
lives in ``core/``, which deliberately knows nothing about Hermes: it is a plain
stdlib HTTP server that talks to the local api_server over loopback and keeps
its state in SQLite.
"""

from __future__ import annotations

from .shim import register

__all__ = ["register"]
