"""TEST FIXTURE — clean MCP server (synthetic, for scanner validation only).

A deliberately well-behaved MCP server implementing Streamable HTTP:
- honest, descriptive tool descriptions (no instructions to the agent)
- constrained input schemas (types, maxLength, enums)
- server-side validation on every parameter
- no hidden Unicode, no dangerous capability combinations

Used by integration tests and the demo flow to show the scanner producing
"no findings from enabled tests" WITHOUT claiming the target is secure.
Run:  python fixtures/clean_server.py  (listens on 127.0.0.1:8100)
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, Request, Response
from pydantic import BaseModel, Field

PROTOCOL_VERSION = "2025-03-26"
SERVER_NAME = "clean-fixture"
# TEST FIXTURE marker that appears in server responses and tool metadata.
FIXTURE_NOTICE = "TEST FIXTURE - synthetic MCP server for scanner validation"

app = FastAPI(title=SERVER_NAME)


class InitializeParams(BaseModel):
    protocolVersion: str = ""
    capabilities: dict[str, Any] = Field(default_factory=dict)
    clientInfo: dict[str, Any] = Field(default_factory=dict)


def _rpc(id_: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "result": result}


def _rpc_error(id_: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


TOOLS: list[dict[str, Any]] = [
    {
        "name": "get_weather",
        "description": "Returns the current temperature and conditions for a city name.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "maxLength": 80, "description": "City name"},
                "units": {"type": "string", "enum": ["metric", "imperial"]},
            },
            "required": ["city"],
        },
    },
    {
        "name": "list_projects",
        "description": "Lists the project names stored in the fixture's demo workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 50},
            },
        },
    },
    {
        "name": "echo_text",
        "description": "Returns the provided text unchanged, for connectivity checks.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "maxLength": 500},
            },
            "required": ["text"],
        },
    },
]

_PROJECTS = ["alpha", "beta", "gamma"]
_WEATHER = {"metric": (21, "partly cloudy"), "imperial": (70, "partly cloudy")}


def _validate(name: str, args: dict[str, Any]) -> str | None:
    """Server-side validation mirroring the published schemas."""
    if name == "get_weather":
        city = args.get("city")
        if not isinstance(city, str) or not (1 <= len(city) <= 80):
            return "city must be a string of 1-80 characters"
        units = args.get("units", "metric")
        if units not in ("metric", "imperial"):
            return "units must be 'metric' or 'imperial'"
    elif name == "list_projects":
        limit = args.get("limit", 10)
        if not isinstance(limit, int) or isinstance(limit, bool) or not (1 <= limit <= 50):
            return "limit must be an integer between 1 and 50"
    elif name == "echo_text":
        text = args.get("text")
        if not isinstance(text, str) or len(text) > 500:
            return "text must be a string of at most 500 characters"
    else:
        return f"unknown tool '{name}'"
    return None


@app.post("/mcp")
async def mcp_endpoint(request: Request) -> Response:
    try:
        body = await request.json()
    except Exception:
        return Response(json.dumps(_rpc_error(None, -32700, "parse error")), media_type="application/json", status_code=400)

    method = body.get("method")
    id_ = body.get("id")

    if method == "initialize":
        return Response(
            json.dumps(_rpc(id_, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}}, "serverInfo": {"name": SERVER_NAME, "version": "0.1.0", "notice": FIXTURE_NOTICE}})),
            media_type="application/json",
        )
    if method == "notifications/initialized":
        return Response(status_code=202)
    if method == "tools/list":
        return Response(json.dumps(_rpc(id_, {"tools": TOOLS})), media_type="application/json")
    if method == "tools/call":
        params = body.get("params") or {}
        name = params.get("name", "")
        args = params.get("arguments") or {}
        err = _validate(name, args)
        if err:
            return Response(json.dumps(_rpc_error(id_, -32602, err)), media_type="application/json")
        if name == "get_weather":
            units = args.get("units", "metric")
            temp, cond = _WEATHER[units]
            content = {"content": [{"type": "text", "text": f"{args['city']}: {temp}° ({cond}), {units}"}]}
        elif name == "list_projects":
            limit = int(args.get("limit", 10))
            content = {"content": [{"type": "text", "text": ", ".join(_PROJECTS[:limit])}]}
        else:  # echo_text
            content = {"content": [{"type": "text", "text": args["text"]}]}
        return Response(json.dumps(_rpc(id_, content)), media_type="application/json")

    return Response(json.dumps(_rpc_error(id_, -32601, f"unknown method {method}")), media_type="application/json")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "fixture": FIXTURE_NOTICE}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8100, log_level="warning")
