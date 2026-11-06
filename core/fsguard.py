"""Path guard for dashboard-hosted file reads (defence in depth).

The dashboard already validates these reads itself; the hub refuses anything
outside the profile's staged-uploads root so a compromised device token cannot
turn ``/api/fs/read-data-url`` into an arbitrary host file reader.
"""

from __future__ import annotations

import os
from pathlib import Path


# Media dirs the dashboard/agent writes into, relative to the profile home.
# `cache/browser*` is deliberately absent: those hold cookies and login data.
_MEDIA_DIRS = (
    "uploads",
    "image_cache",
    "audio_cache",
    os.path.join("cache", "images"),
    os.path.join("cache", "audio"),
    os.path.join("cache", "vision"),
    os.path.join("cache", "screenshots"),
    os.path.join("cache", "videos"),
    os.path.join("cache", "documents"),
    os.path.join("cache", "scratch"),
)


def default_roots(profile_home: str | os.PathLike[str] | None) -> list[Path]:
    """Where a device token is allowed to read images/documents from.

    Chat messages carry *paths* (`cache/images/dashboard_….png`), and the UI
    reads them back through `/api/fs/read-data-url` — so these roots have to
    match where the dashboard actually writes, or every thumbnail breaks.
    """
    if not profile_home:
        return []
    home = Path(profile_home)
    return [home / part for part in _MEDIA_DIRS]


def resolve_roots(raw: str | None, profile_home: str | os.PathLike[str] | None) -> list[Path]:
    """``PI_HUB_FS_ROOTS`` (``:``-separated) overrides the defaults."""
    if raw:
        roots = [Path(part).expanduser() for part in raw.split(os.pathsep) if part.strip()]
    else:
        roots = default_roots(profile_home)
    resolved = []
    for root in roots:
        try:
            resolved.append(root.resolve())
        except OSError:
            continue
    return resolved


def ensure_allowed(path: str, roots: list[Path]) -> Path:
    """Return the resolved path, or raise ``path_not_allowed``."""
    from .errors import HubError

    if not path:
        raise HubError("bad_request", "path is required")
    candidate = Path(path)
    if not candidate.is_absolute():
        raise HubError("path_not_allowed", "path must be absolute")
    try:
        real = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HubError("path_not_allowed", f"cannot resolve path: {exc}") from exc
    for root in roots:
        try:
            real.relative_to(root)
        except ValueError:
            continue
        return real
    raise HubError("path_not_allowed", "path is outside the allowed roots")
