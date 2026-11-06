"""Uniform error surface.

Every error the hub produces itself goes through :class:`HubError` so the client
can branch on a small, stable set of codes. Upstream errors are passed through
byte-for-byte and never rewritten into these codes.
"""

from __future__ import annotations

# code -> (http status, default message)
ERRORS: dict[str, tuple[int, str]] = {
    "unauthorized": (401, "missing or invalid device token"),
    "device_revoked": (401, "this device has been revoked"),
    "admin_required": (403, "missing or invalid admin key"),
    "scope_required": (403, "this device token lacks the required scope"),
    "rate_limited": (429, "too many requests from this device"),
    "upstream_unavailable": (502, "the hub could not reach Hermes api_server"),
    "upstream_timeout": (504, "Hermes api_server did not answer in time"),
    "path_not_allowed": (403, "path is outside the allowed roots"),
    "not_found": (404, "no such hub route"),
    "method_not_allowed": (405, "method not allowed for this route"),
    "bad_request": (400, "malformed request"),
    "payload_too_large": (413, "request body too large"),
    "hub_disabled": (503, "hub is not configured (PI_HUB_ADMIN_KEY missing)"),
    "internal_error": (500, "internal hub error"),
}


class HubError(Exception):
    def __init__(self, code: str, message: str | None = None, *, retry_after: int | None = None):
        status, default = ERRORS.get(code, (500, "internal hub error"))
        super().__init__(message or default)
        self.code = code
        self.status = status
        self.message = message or default
        self.retry_after = retry_after

    def payload(self) -> dict:
        body = {"error": {"code": self.code, "message": self.message, "type": "hub_error"}}
        if self.retry_after is not None:
            body["error"]["retry_after"] = self.retry_after
        return body

    def headers(self) -> dict[str, str]:
        return {"Retry-After": str(self.retry_after)} if self.retry_after is not None else {}
