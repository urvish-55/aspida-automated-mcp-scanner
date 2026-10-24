"""Regression: the findings `since` filter must not crash on naive vs aware database timestamps (seen on Windows)."""

import httpx
import pytest

from backend.api.app import app
from backend.api.routes_v2 import _as_utc
from backend.database.session import init_db
from datetime import datetime, timezone


@pytest.fixture
async def client():
    await init_db()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


def test_as_utc_handles_naive_and_aware():
    naive = datetime(2026, 1, 1, 12, 0)
    aware = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    assert _as_utc(naive) == aware and _as_utc(aware) == aware
    assert _as_utc(naive) < datetime(2027, 1, 1, tzinfo=timezone.utc)


async def test_since_filter_returns_200(client):
    r = await client.get("/api/findings", params={"since": "2020-01-01", "limit": 5})
    assert r.status_code == 200
    r = await client.get("/api/findings", params={"since": "2999-01-01", "limit": 5})
    assert r.status_code == 200 and r.json()["total"] == 0
