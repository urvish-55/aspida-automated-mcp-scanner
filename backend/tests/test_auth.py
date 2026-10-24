"""API-key authentication: enforcement, constant-time verification, throttling, key handling."""

import httpx
import pytest

from backend.api.app import create_app
from backend.core import config
from backend.security import auth

KEY = "test-api-key-0123456789abcdef"


@pytest.fixture
async def client(monkeypatch, tmp_path):
    monkeypatch.setenv("AUTH_REQUIRED", "true")
    monkeypatch.setenv("API_KEY", KEY)
    monkeypatch.setenv("AUTH_MAX_FAILURES_PER_MINUTE", "5")
    monkeypatch.setenv("RATE_LIMIT_PER_MINUTE", "10000")
    config.get_settings.cache_clear()
    auth.reset_auth_cache()
    app = create_app()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c
    config.get_settings.cache_clear()
    auth.reset_auth_cache()


async def test_protected_routes_reject_missing_and_wrong_key(client):
    for path in ("/api/scans", "/api/dashboard", "/api/auth/check"):
        r = await client.get(path)
        assert r.status_code == 401, path
        assert r.headers["www-authenticate"].startswith("Bearer")
    r = await client.get("/api/scans", headers={"Authorization": "Bearer wrong-key-wrong-key-wrong"})
    assert r.status_code == 401
    r = await client.post("/api/scans", json={"target_type": "config", "target_config": {"tools": []}})
    assert r.status_code == 401  # mutating routes are protected too


async def test_valid_key_via_bearer_and_x_api_key(client):
    assert (await client.get("/api/auth/check", headers={"Authorization": f"Bearer {KEY}"})).status_code == 200
    assert (await client.get("/api/auth/check", headers={"X-API-Key": KEY})).status_code == 200
    assert (await client.get("/api/auth/check", headers={"Authorization": f"bearer {KEY}"})).status_code == 200


async def test_public_endpoints_and_preflight_need_no_key(client):
    r = await client.get("/api/health")
    assert r.status_code == 200 and r.json()["auth_required"] is True
    assert (await client.get("/api/version")).status_code == 200
    pre = await client.options("/api/scans", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert pre.status_code in (200, 204)


async def test_failed_attempts_are_throttled_even_for_correct_key(client):
    for _ in range(5):
        assert (await client.get("/api/scans", headers={"X-API-Key": "nope-nope-nope-nope"})).status_code == 401
    blocked = await client.get("/api/scans", headers={"X-API-Key": KEY})
    assert blocked.status_code == 429 and blocked.headers["retry-after"] == "60"


async def test_error_response_does_not_leak_key_material(client):
    r = await client.get("/api/scans", headers={"X-API-Key": "x" * 600})
    assert r.status_code == 401 and KEY not in r.text


def test_short_env_key_is_rejected(monkeypatch):
    monkeypatch.setenv("API_KEY", "short")
    config.get_settings.cache_clear()
    auth.reset_auth_cache()
    try:
        with pytest.raises(auth.AuthConfigError):
            auth.expected_digest()
    finally:
        monkeypatch.delenv("API_KEY")
        config.get_settings.cache_clear()
        auth.reset_auth_cache()


def test_generated_key_is_random_persisted_and_private(tmp_path, monkeypatch):
    path = tmp_path / "api_key"
    first = auth._load_or_create_key("", path)
    assert len(first) >= 40 and path.read_text().strip() == first
    assert auth._load_or_create_key("", path) == first  # stable across restarts
    assert (path.stat().st_mode & 0o077) == 0  # owner-only permissions (POSIX)


def test_extract_and_verify_helpers(monkeypatch):
    monkeypatch.setenv("API_KEY", KEY)
    config.get_settings.cache_clear()
    auth.reset_auth_cache()
    try:
        assert auth.extract_presented_key("Bearer abc", None) == "abc"
        assert auth.extract_presented_key("Basic abc", "hdr") == "hdr"
        assert auth.extract_presented_key(None, None) is None
        assert auth.is_valid_key(KEY) and not auth.is_valid_key(KEY + "x") and not auth.is_valid_key("")
    finally:
        monkeypatch.delenv("API_KEY")
        config.get_settings.cache_clear()
        auth.reset_auth_cache()
