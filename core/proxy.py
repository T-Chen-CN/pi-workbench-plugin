"""Reverse proxy to the local api_server.

Rules that matter
-----------------
* **Loopback HTTP only.** We never import Hermes internals; the documented REST
  surface is the contract. One local hop (~0.2 ms) buys us a stable interface.
* **Auth is rewritten, never forwarded.** The client's ``Authorization`` header
  is dropped; the upstream key is injected. Device identity travels as
  ``X-Pi-Device`` and client-supplied values for it are stripped first.
* **No buffering on streams.** ``Accept-Encoding`` is forced to ``identity`` so
  nothing downstream can decide to gzip an event stream, and chunks are handed
  to the caller as they arrive.
* **Read-only GETs are cached briefly** (30 s) because the local UI polls
  capabilities/toolsets/models on every panel switch.
"""

from __future__ import annotations

import http.client
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Iterable, Mapping

from .errors import HubError

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailers",
        "transfer-encoding",
        "upgrade",
        "host",
        "content-length",
        "authorization",
        "accept-encoding",
        "cookie",
    }
)

# Headers we must pass through even though they look hop-by-hop to some proxies.
PASS_HEADERS = frozenset({"last-event-id", "idempotency-key", "x-request-id"})

CACHEABLE_PREFIXES = (
    "/health",
    "/v1/capabilities",
    "/v1/toolsets",
    "/v1/skills",
    "/v1/models",
)

CACHE_TTL_SECONDS = 30.0


@dataclass
class Response:
    status: int
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""


@dataclass
class StreamResponse:
    status: int
    headers: dict[str, str]
    chunks: Iterable[bytes]


def _filter_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in (headers or {}).items():
        low = key.lower()
        if low in PASS_HEADERS or low not in HOP_BY_HOP:
            out[key] = value
    out.pop("X-Pi-Device", None)
    out.pop("x-pi-device", None)
    return out


class Upstream:
    def __init__(self, base_url: str, key: str, *, cache_ttl: float = CACHE_TTL_SECONDS):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError(f"invalid upstream base URL: {base_url!r}")
        self.base_url = base_url.rstrip("/")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.prefix = parsed.path.rstrip("/")
        self.key = key
        self.cache_ttl = cache_ttl
        self._cache: dict[str, tuple[float, Response]] = {}
        self._cache_lock = threading.Lock()

    # -- helpers -----------------------------------------------------------

    def _conn(self, timeout: float) -> http.client.HTTPConnection:
        cls = http.client.HTTPSConnection if self.scheme == "https" else http.client.HTTPConnection
        return cls(self.host, self.port, timeout=timeout)

    def _upstream_headers(self, headers: Mapping[str, str] | None, device_id: str | None) -> dict[str, str]:
        out = _filter_headers(headers)
        out["Accept-Encoding"] = "identity"
        if self.key:
            out["Authorization"] = f"Bearer {self.key}"
        if device_id:
            out["X-Pi-Device"] = device_id
        return out

    def _target(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.prefix}{path}"

    @staticmethod
    def _response_headers(raw) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, value in raw.getheaders():
            low = key.lower()
            if low in ("connection", "transfer-encoding", "content-length", "keep-alive"):
                continue
            out[key] = value
        return out

    # -- public API --------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        device_id: str | None = None,
        timeout: float = 120.0,
        cacheable: bool | None = None,
    ) -> Response:
        if cacheable is None:
            cacheable = method == "GET" and path.startswith(CACHEABLE_PREFIXES)
        if cacheable:
            hit = self._cache_get(path)
            if hit is not None:
                return hit

        conn = self._conn(timeout)
        try:
            conn.request(method, self._target(path), body=body, headers=self._upstream_headers(headers, device_id))
            raw = conn.getresponse()
            payload = raw.read()
        except TimeoutError as exc:
            raise HubError("upstream_timeout") from exc
        except OSError as exc:
            raise HubError("upstream_unavailable", str(exc)) from exc
        finally:
            conn.close()

        response = Response(raw.status, self._response_headers(raw), payload)
        if cacheable and response.status == 200:
            self._cache_put(path, response)
        return response

    def stream(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        body: bytes | None = None,
        device_id: str | None = None,
        timeout: float = 900.0,
    ) -> StreamResponse:
        """Open an upstream response and hand back a chunk iterator.

        The caller owns the connection: it is closed when the iterator is
        exhausted or garbage-collected (``GeneratorExit`` closes it).
        """
        conn = self._conn(timeout)
        try:
            conn.request(method, self._target(path), body=body, headers=self._upstream_headers(headers, device_id))
            raw = conn.getresponse()
        except TimeoutError as exc:
            conn.close()
            raise HubError("upstream_timeout") from exc
        except OSError as exc:
            conn.close()
            raise HubError("upstream_unavailable", str(exc)) from exc

        def chunks():
            try:
                while True:
                    chunk = raw.read1(65536)
                    if not chunk:
                        break
                    yield chunk
            finally:
                try:
                    raw.close()
                finally:
                    conn.close()

        return StreamResponse(raw.status, self._response_headers(raw), chunks())

    # -- cache -------------------------------------------------------------

    def _cache_get(self, path: str) -> Response | None:
        with self._cache_lock:
            entry = self._cache.get(path)
            if entry is None:
                return None
            expires, response = entry
            if expires < time.time():
                self._cache.pop(path, None)
                return None
            return response

    def _cache_put(self, path: str, response: Response) -> None:
        with self._cache_lock:
            self._cache[path] = (time.time() + self.cache_ttl, response)

    def flush_cache(self) -> None:
        with self._cache_lock:
            self._cache.clear()
