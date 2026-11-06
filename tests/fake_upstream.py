"""A canned stand-in for the local api_server.

Records every request so tests can assert on what the hub forwarded (auth
header rewritten, ``X-Pi-Device`` injected, hop-by-hop headers dropped).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeUpstream:
    def __init__(self, *, api_key: str = "upstream-secret"):
        self.api_key = api_key
        self.requests: list[dict] = []
        self.routes: dict[str, tuple[int, dict, bytes]] = {}
        self.stream_chunks: dict[str, list[bytes]] = {}
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = 0

    # -- configuration -----------------------------------------------------

    def route(self, path: str, *, status: int = 200, body=None, headers: dict | None = None) -> None:
        payload = body if isinstance(body, bytes) else json.dumps(body if body is not None else {}).encode()
        self.routes[path] = (status, headers or {"Content-Type": "application/json"}, payload)

    def stream(self, path: str, chunks: list[bytes]) -> None:
        self.stream_chunks[path] = chunks
        self.routes[path] = (200, {"Content-Type": "text/event-stream"}, b"")

    # -- lifecycle ---------------------------------------------------------

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "FakeUpstream":
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # silence
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "body": body,
                    }
                )
                key = self.path.split("?")[0]
                if key in outer.stream_chunks:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    for chunk in outer.stream_chunks[key]:
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    self.close_connection = True
                    return
                status, headers, payload = outer.routes.get(
                    key, (404, {"Content-Type": "application/json"}, b'{"error":{"code":"not_found"}}')
                )
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                if payload:
                    self.wfile.write(payload)

            do_GET = _handle
            do_POST = _handle
            do_PUT = _handle
            do_DELETE = _handle

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=lambda: self._httpd.serve_forever(poll_interval=0.1), daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    def last(self) -> dict:
        return self.requests[-1]
