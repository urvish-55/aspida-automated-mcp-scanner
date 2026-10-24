"""MCPConnector: talks to a real MCP server over Streamable HTTP for dynamic
scanning, with SSRF validation on every hop and no shell-outs.

What it does:
- validate the target URL (scheme, resolution, private-range policy)
- initialize the MCP session (handshake) and keep the session id
- tools/list to enumerate tools
- tools/call with explicit arguments (used only by the probe generators)

What it never does:
- spawn processes, run shell commands, load config 'command' entries
- follow redirects automatically (each hop is validated)
- exceed the limits handed to it by the SafetyController
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from backend.security.network import (
    SSRFBlockedError,
    register_pins,
    safe_client,
    validate_redirect,
    validate_target_url,
)

JSONRPC_PARSE_ERROR = "Unable to establish a session"


@dataclass
class MCPTool:
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)


@dataclass
class CallResult:
    ok: bool  # transport-level success (got a well-formed JSON-RPC response)
    is_error: bool  # server reported a tool-level error
    content_text: str = ""
    structured: dict[str, Any] | list | None = None
    raw_status: int | None = None
    error: str = ""
    duration_ms: int = 0


class MCPConnectionError(Exception):
    pass


class MCPConnector:
    def __init__(self, url: str, *, timeout: float, allow_local: bool) -> None:
        self._url = url
        self._timeout = timeout
        self._allow_local = allow_local
        self._client: httpx.AsyncClient | None = None
        self._pins: dict[str, list[str]] = {}
        self._session_id: str | None = None
        self._protocol_version: str | None = None
        self._request_id = 0

    async def __aenter__(self) -> "MCPConnector":
        self.validation = validate_target_url(self._url, allow_local=self._allow_local)
        register_pins(self._pins, self.validation)  # DNS pinning: connect only to the validated addresses
        self._client = safe_client(timeout=self._timeout, pins=self._pins, allow_local=self._allow_local)
        await self._client.__aenter__()
        return self

    async def __aexit__(self, *exc) -> None:
        if self._client is not None:
            await self._client.__aexit__(*exc)
            self._client = None

    # ------------------------------------------------------------------
    async def _post(self, payload: dict[str, Any]) -> httpx.Response:
        assert self._client is not None
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return await self._client.post(self._url, json=payload, headers=headers)

    def _extract_sse_data(self, text: str) -> dict[str, Any] | None:
        for line in text.splitlines():
            if line.startswith("data:"):
                try:
                    return json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
        return None

    async def initialize(self) -> dict[str, Any]:
        """MCP initialize handshake; stores session id if the server issues one."""
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "mcp-pentester", "version": "0.1.0"},
            },
        }
        resp = await self._post(payload)
        # manual redirect validation (never auto-follow)
        if resp.is_redirect:
            loc = resp.headers.get("location", "")
            self.validation = validate_redirect(self.validation, loc)
            register_pins(self._pins, self.validation)
            self._url = urllib_parse_urljoin(self._url, loc)
            resp = await self._post(payload)
        if resp.status_code != 200:
            raise MCPConnectionError(f"initialize failed: HTTP {resp.status_code}")
        sid = resp.headers.get("mcp-session-id")
        if sid:
            self._session_id = sid
        data = self._extract_sse_data(resp.text) if "text/event-stream" in resp.headers.get("content-type", "") else None
        body: dict[str, Any]
        if data is not None:
            body = data
        else:
            try:
                body = resp.json()
            except json.JSONDecodeError as exc:
                raise MCPConnectionError(f"initialize returned non-JSON body: {exc}") from exc
        if "error" in body:
            raise MCPConnectionError(f"initialize error: {body['error']}")
        result = body.get("result") or {}
        self._protocol_version = result.get("protocolVersion")
        # notifications/initialized (server may require it before tools/list)
        self._request_id += 1
        await self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        return result

    async def list_tools(self) -> list[MCPTool]:
        self._request_id += 1
        resp = await self._post({"jsonrpc": "2.0", "id": self._request_id, "method": "tools/list", "params": {}})
        if resp.status_code != 200:
            raise MCPConnectionError(f"tools/list failed: HTTP {resp.status_code}")
        body = self._extract_sse_data(resp.text) if "text/event-stream" in resp.headers.get("content-type", "") else None
        if body is None:
            try:
                body = resp.json()
            except json.JSONDecodeError as exc:
                raise MCPConnectionError(f"tools/list returned non-JSON body: {exc}") from exc
        if "error" in body:
            raise MCPConnectionError(f"tools/list error: {body['error']}")
        tools_raw = (body.get("result") or {}).get("tools") or []
        tools: list[MCPTool] = []
        for i, t in enumerate(tools_raw):
            if not isinstance(t, dict) or not isinstance(t.get("name"), str):
                continue
            tools.append(
                MCPTool(
                    name=t["name"],
                    description=t.get("description") or "",
                    input_schema=dict(t["inputSchema"]) if isinstance(t.get("inputSchema"), dict) else {},
                    annotations=dict(t["annotations"]) if isinstance(t.get("annotations"), dict) else {},
                )
            )
        return tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> CallResult:
        """Invoke a tool. The caller (probe generator) is responsible for the
        arguments being inert/safe; connector enforces transport limits only."""
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        try:
            resp = await self._post(payload)
        except httpx.HTTPError as exc:
            return CallResult(ok=False, is_error=False, error=f"transport error: {exc}")
        if resp.is_redirect:
            try:
                self.validation = validate_redirect(self.validation, resp.headers.get("location", ""))
                register_pins(self._pins, self.validation)
                self._url = urllib_parse_urljoin(self._url, resp.headers.get("location", ""))
                resp = await self._post(payload)
            except SSRFBlockedError as exc:
                return CallResult(ok=False, is_error=False, error=f"redirect blocked by SSRF policy: {exc}")
        if resp.status_code == 404 and self._session_id:
            # session expired; re-initialize once and retry
            try:
                self._session_id = None
                await self.initialize()
                resp = await self._post(payload)
            except MCPConnectionError as exc:
                return CallResult(ok=False, is_error=False, error=f"session re-establish failed: {exc}")
        if resp.status_code != 200:
            return CallResult(ok=False, is_error=False, raw_status=resp.status_code, error=f"HTTP {resp.status_code}")

        body = self._extract_sse_data(resp.text) if "text/event-stream" in resp.headers.get("content-type", "") else None
        if body is None:
            try:
                body = resp.json()
            except json.JSONDecodeError as exc:
                return CallResult(ok=False, is_error=False, error=f"non-JSON response: {exc}")
        if "error" in body and body["error"]:
            err = body["error"]
            return CallResult(ok=True, is_error=True, error=str(err.get("message", err)), raw_status=resp.status_code)
        result = body.get("result") or {}
        content_text = ""
        for item in result.get("content") or []:
            if isinstance(item, dict) and item.get("type") == "text":
                content_text += (item.get("text") or "") + "\n"
        structured = result.get("structuredContent")
        return CallResult(
            ok=True,
            is_error=bool(result.get("isError", False)),
            content_text=content_text.strip()[:10_000],
            structured=structured if isinstance(structured, (dict, list)) else None,
            raw_status=resp.status_code,
        )


def urllib_parse_urljoin(base: str, location: str) -> str:
    import urllib.parse

    return urllib.parse.urljoin(base, location)
