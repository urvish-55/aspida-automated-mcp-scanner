"""API middleware: simple in-memory rate limiting (per client IP).

This is a dev/small-deployment limiter to stop accidental request floods;
a production multi-worker deployment should front the API with a real gateway
limiter (documented in ARCHITECTURE.md). Never logs request bodies (they may
contain customer config data).
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from backend.core.config import get_settings
from backend.security.auth import extract_presented_key, is_valid_key

# Reachable without a key: liveness/version (no scan data) and the OpenAPI docs (schema only).
PUBLIC_API_PATHS = frozenset({"/api/health", "/api/version", "/api/docs", "/api/openapi.json"})


class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """Require an API key on every /api/* route except PUBLIC_API_PATHS.

    - CORS preflight (OPTIONS) and non-API paths (the static dashboard bundle) pass through.
    - Repeated failures from one IP are throttled (429) so the key cannot be guessed online.
    - Responses never reveal whether a key was malformed or merely wrong.
    """

    def __init__(self, app) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        settings = get_settings()
        path = request.url.path
        if (
            not settings.auth_required
            or request.method == "OPTIONS"
            or not path.startswith("/api/")
            or path in PUBLIC_API_PATHS
        ):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        failures = self._failures[client_ip]
        while failures and now - failures[0] > 60.0:
            failures.popleft()
        if len(failures) >= settings.auth_max_failures_per_minute:
            return JSONResponse(
                status_code=429,
                content={"detail": "too many failed authentication attempts; try again later"},
                headers={"Retry-After": "60"},
            )

        presented = extract_presented_key(request.headers.get("authorization"), request.headers.get("x-api-key"))
        if not is_valid_key(presented):
            failures.append(now)
            return JSONResponse(
                status_code=401,
                content={"detail": "authentication required: send 'Authorization: Bearer <API key>' or 'X-API-Key'"},
                headers={"WWW-Authenticate": 'Bearer realm="mcp-pentester"'},
            )
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app) -> None:  # type: ignore[no-untyped-def]
        super().__init__(app)
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        settings = get_settings()
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window = self._hits[client_ip]
        while window and now - window[0] > 60.0:
            window.popleft()
        if len(window) >= settings.rate_limit_per_minute:
            retry_after = 60 - int(now - window[0]) + 1
            return JSONResponse(
                status_code=429,
                content={"detail": f"rate limit exceeded ({settings.rate_limit_per_minute}/min)"},
                headers={"Retry-After": str(retry_after)},
            )
        window.append(now)
        return await call_next(request)
