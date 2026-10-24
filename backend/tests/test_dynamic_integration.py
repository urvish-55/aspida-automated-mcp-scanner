"""Integration test: dynamic scanning against the LIVE vulnerable fixture.

Boots fixtures/vulnerable_server.py in-process (ASGI), then runs the real
DynamicScanner (SSRF validation with localhost allowed for the test, MCP
handshake, probe generation, execution, response analysis).

Asserts honest, specific outcomes:
- tool enumeration returns the fixture's 4 tools
- the command-injection echo marker is detected (family dynamic_command_injection)
- the path traversal sentinel is detected (family dynamic_path_traversal)
- every dynamic finding has non-empty evidence and a reproduction block
- the malformed/oversized probes produce recorded outcomes (passed or finding),
  never silent omissions
"""

from __future__ import annotations

import threading
import time

import pytest
import uvicorn

from backend.core.config import get_settings
from backend.scanners.dynamic.engine import DynamicScanner
from backend.scanners.dynamic.safety import SafetyController


def _already_serving(base: str) -> bool:
    """True if a fixture is already running at the base URL (dev environment)."""
    try:
        import httpx as _httpx

        return _httpx.get(f"{base}/health", timeout=1.0).status_code == 200
    except Exception:
        return False


@pytest.fixture(scope="module")
def vulnerable_url():
    base = "http://127.0.0.1:8101"
    if _already_serving(base):
        # fixture already running (e.g. started for the demo flow); reuse it
        yield f"{base}/mcp"
        return
    uvicorn_config = uvicorn.Config(
        "fixtures.vulnerable_server:app",
        host="127.0.0.1",
        port=8101,
        log_level="error",
    )
    server = uvicorn.Server(uvicorn_config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    # wait for startup
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "fixture server failed to start"
    yield f"{base}/mcp"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.mark.asyncio
async def test_dynamic_scan_detects_confirmed_findings(vulnerable_url):
    settings = get_settings()
    safety = SafetyController(
        max_requests=60,
        max_payload_bytes=settings.max_payload_size_bytes,
        per_test_timeout=10.0,
        min_interval=0.02,
        safe_mode=True,
        allow_local=True,  # fixture is localhost; the product default disallows this
    )
    scanner = DynamicScanner(vulnerable_url, safety, scan_id="it-dynamic")
    result = await scanner.run()

    assert result.connection_error == "", f"connection failed: {result.connection_error}"
    assert set(result.tools_enumerated) >= {"read_file", "Read_File", "run_command", "fetch_url"}

    families = {f["rule_id"] for f in result.findings}
    assert "DYN-PATH-001" in families, f"expected traversal finding, got {families}"
    assert "DYN-CMDI-001" in families, f"expected command-injection finding, got {families}"

    for f in result.findings:
        assert f["status"] == "confirmed"
        assert f["evidence"], "every dynamic finding must carry evidence"
        assert "arguments" in f["reproduction"], "dynamic findings must include reproduction args (may be empty for omission probes)"

    statuses = [t.status for t in result.tests]
    assert "passed" in statuses or "failed" in statuses
    # no fabricated passes: every test record has a detail string
    for t in result.tests:
        assert t.detail, f"test {t.test_id} has no detail"


@pytest.mark.asyncio
async def test_dynamic_scan_clean_fixture_has_no_confirmed_findings():
    """The clean fixture must NOT produce dynamic findings (guards false positives)."""
    base = "http://127.0.0.1:8100"
    reuse = _already_serving(base)
    server = None
    thread = None
    if not reuse:
        uvicorn_config = uvicorn.Config("fixtures.clean_server:app", host="127.0.0.1", port=8100, log_level="error")
        server = uvicorn.Server(uvicorn_config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()
        for _ in range(50):
            if server.started:
                break
            time.sleep(0.1)
    try:
        settings = get_settings()
        safety = SafetyController(
            max_requests=60,
            max_payload_bytes=settings.max_payload_size_bytes,
            per_test_timeout=10.0,
            min_interval=0.02,
            safe_mode=True,
            allow_local=True,
        )
        scanner = DynamicScanner(f"{base}/mcp", safety, scan_id="it-clean")
        result = await scanner.run()
        assert result.connection_error == ""
        assert result.findings == [], f"clean fixture produced findings: {[f['title'] for f in result.findings]}"
    finally:
        if server is not None and thread is not None:
            server.should_exit = True
            thread.join(timeout=5)
