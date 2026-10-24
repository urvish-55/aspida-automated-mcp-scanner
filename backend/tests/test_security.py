"""Security tests for the scanner itself.

Covers: SSRF egress policy, upload validation, authorization enforcement,
rate limiting, malformed input handling, and 'never execute uploaded content'.
"""

import pytest

from backend.api.uploads import UploadValidationError, validate_upload, resolve_upload_path
from backend.security.network import SSRFBlockedError, validate_target_url
from backend.scanners.dynamic.safety import SafetyController, SafetyViolation
from backend.schemas.api import ScanCreate
from backend.core.config import get_settings


# --------------------------- SSRF ---------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8000/mcp",
    "http://localhost:8000/mcp",
    "http://10.0.0.5/mcp",
    "http://192.168.1.10/mcp",
    "http://172.16.0.9/mcp",
    "http://169.254.169.254/latest/meta-data",  # cloud metadata
    "http://[::1]/mcp",
    "http://0.0.0.0/mcp",
])
def test_ssrf_private_targets_blocked(url):
    with pytest.raises(SSRFBlockedError):
        validate_target_url(url, allow_local=False)


def test_ssrf_local_allowed_only_when_explicit():
    v = validate_target_url("http://127.0.0.1:8101/mcp", allow_local=True)
    assert v.host == "127.0.0.1"


def test_ssrf_public_hostname_resolves():
    import socket

    try:
        socket.getaddrinfo("example.com", 443)
    except socket.gaierror:
        pytest.skip("no DNS available in this environment")
    v = validate_target_url("https://example.com/mcp", allow_local=False)
    assert v.resolved_ips, "public host should resolve"


@pytest.mark.parametrize("url", ["ftp://example.com", "file:///etc/passwd", "gopher://x"])
def test_ssrf_scheme_allowlist(url):
    with pytest.raises(SSRFBlockedError):
        validate_target_url(url, allow_local=True)


def test_ssrf_credentials_in_url_rejected():
    with pytest.raises(SSRFBlockedError):
        validate_target_url("http://user:pass@example.com/mcp", allow_local=True)


def test_ssrf_unresolvable_host_rejected():
    with pytest.raises(SSRFBlockedError):
        validate_target_url("http://this-host-does-not-exist-9x7wq.example/mcp", allow_local=False)


# --------------------------- uploads ---------------------------

def test_upload_rejects_oversized():
    settings = get_settings()
    big = b"x" * (settings.max_upload_size_bytes + 1)
    with pytest.raises(UploadValidationError):
        validate_upload("cfg.json", big)


def test_upload_rejects_bad_extension():
    with pytest.raises(UploadValidationError):
        validate_upload("evil.sh", b'{"mcpServers": {}}')


def test_upload_rejects_non_json():
    with pytest.raises(UploadValidationError):
        validate_upload("cfg.json", b"this is not json")


def test_upload_rejects_empty():
    with pytest.raises(UploadValidationError):
        validate_upload("cfg.json", b"   ")


def test_upload_stores_with_safe_random_name():
    import json as _json

    path = validate_upload("../../very evil name.json", _json.dumps({"mcpServers": {}}).encode())
    import re

    assert re.fullmatch(r"[0-9a-f]{24}\.json", path.name), "stored name must be generated"
    path.unlink()


def test_resolve_upload_path_blocks_traversal():
    with pytest.raises(UploadValidationError):
        resolve_upload_path("../../../etc/passwd")
    with pytest.raises(UploadValidationError):
        resolve_upload_path("not-a-valid-name.json")


# --------------------- authorization gate ---------------------

def test_dynamic_requires_authorization():
    with pytest.raises(Exception) as exc:
        ScanCreate(target_type="url", server_url="https://example.com/mcp", dynamic_enabled=True, authorization_confirmed=False)
    assert "authoriz" in str(exc.value).lower()


def test_dynamic_with_authorization_accepted():
    m = ScanCreate(target_type="url", server_url="https://example.com/mcp", dynamic_enabled=True, authorization_confirmed=True)
    assert m.authorization_confirmed is True


def test_url_required_for_url_mode():
    with pytest.raises(Exception):
        ScanCreate(target_type="url", server_url=None)


# --------------------- safety controller ---------------------

@pytest.mark.asyncio
async def test_safety_budget_enforced():
    s = SafetyController(max_requests=2, max_payload_bytes=1000, per_test_timeout=1.0, min_interval=0.0, safe_mode=True)
    await s.check_and_reserve(test_id="t", tool="x", payload_size=10)
    await s.check_and_reserve(test_id="t", tool="x", payload_size=10)
    with pytest.raises(SafetyViolation):
        await s.check_and_reserve(test_id="t", tool="x", payload_size=10)
    assert s.audit, "refusals must be audited"


@pytest.mark.asyncio
async def test_safety_payload_cap():
    s = SafetyController(max_requests=10, max_payload_bytes=100, per_test_timeout=1.0, min_interval=0.0, safe_mode=True)
    with pytest.raises(SafetyViolation):
        await s.check_and_reserve(test_id="t", tool="x", payload_size=101)


@pytest.mark.asyncio
async def test_safety_cancellation():
    s = SafetyController(max_requests=10, max_payload_bytes=1000, per_test_timeout=1.0, min_interval=0.0, safe_mode=True)
    s.cancel()
    with pytest.raises(Exception):  # ScanCancelled
        await s.check_and_reserve(test_id="t", tool="x", payload_size=10)


# --------------------- rate limiting ---------------------

@pytest.mark.asyncio
async def test_rate_limit_middleware_blocks_flood():
    from backend.api.middleware import RateLimitMiddleware

    mw = RateLimitMiddleware(app=None)
    from starlette.requests import Request

    scope = {"type": "http", "client": ("1.2.3.4", 1234), "method": "GET", "path": "/api/health", "headers": []}
    request = Request(scope)

    async def call_next(_req):
        from starlette.responses import JSONResponse

        return JSONResponse({"ok": True})

    settings = get_settings()
    last_resp = None
    for _ in range(settings.rate_limit_per_minute + 5):
        last_resp = await mw.dispatch(request, call_next)
    assert last_resp.status_code == 429


# --- DNS pinning (closes the rebinding window between validation and connect) --------

class _FakeBackend:
    def __init__(self):
        self.connected: list[tuple[str, int]] = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.connected.append((host, port))
        return object()

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):  # pragma: no cover
        raise AssertionError("must never be reached")

    async def sleep(self, seconds):
        return None


def _pinned(pins, allow_local=False):
    from backend.security.network import PinnedNetworkBackend

    inner = _FakeBackend()
    return PinnedNetworkBackend(inner, pins, allow_local), inner


async def test_pinned_backend_connects_to_validated_ip_not_hostname(monkeypatch):
    import socket

    from backend.security.network import register_pins, validate_target_url

    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))])
    v = validate_target_url("https://scan-target.example/mcp", allow_local=False)
    pins: dict[str, list[str]] = {}
    register_pins(pins, v)
    backend, inner = _pinned(pins)

    # Attacker flips DNS to an internal address AFTER validation (rebinding). Any lookup would now be fatal.
    def evil_lookup(*a, **k):
        raise AssertionError("pinned connect must not resolve the hostname again")

    monkeypatch.setattr(socket, "getaddrinfo", evil_lookup)
    await backend.connect_tcp("scan-target.example", 443)
    assert inner.connected == [("93.184.216.34", 443)]


async def test_pinned_backend_refuses_unvalidated_host_and_unix_sockets():
    import httpcore

    backend, inner = _pinned({"ok.example": ["93.184.216.34"]})
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("redirected.example", 443)  # e.g. an unvalidated redirect target
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_unix_socket("/var/run/docker.sock")
    assert inner.connected == []


async def test_pinned_backend_rechecks_policy_at_connect_time():
    import httpcore

    for bad in ("127.0.0.1", "10.0.0.5", "169.254.169.254"):
        backend, inner = _pinned({"h.example": [bad]}, allow_local=False)
        with pytest.raises(httpcore.ConnectError):
            await backend.connect_tcp("h.example", 80)
        assert inner.connected == []
    # metadata endpoints stay blocked even when local targets are allowed
    backend, inner = _pinned({"h.example": ["169.254.169.254"]}, allow_local=True)
    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("h.example", 80)
    backend, inner = _pinned({"h.example": ["127.0.0.1"]}, allow_local=True)
    await backend.connect_tcp("h.example", 80)
    assert inner.connected == [("127.0.0.1", 80)]


def test_safe_client_with_pins_uses_pinned_transport_and_ignores_env_proxy(monkeypatch):
    from backend.security.network import PinnedNetworkBackend, safe_client

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    client = safe_client(timeout=5, pins={"a.example": ["93.184.216.34"]})
    pool = client._transport._pool  # type: ignore[attr-defined]
    assert isinstance(pool._network_backend, PinnedNetworkBackend)
    assert not client._mounts  # no proxy transport mounted: a proxy would resolve the name itself
