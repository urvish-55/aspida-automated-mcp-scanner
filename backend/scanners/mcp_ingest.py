"""MCP ingestion: parse and normalize many shapes of MCP metadata into one
internal representation (`NormalizedTarget`) that all analyzers consume.

Accepted inputs (best-effort, tolerant but explicit about what was parsed):
- ``{"mcpServers": {"name": {"command": ..., "args": [...], "env": {...}}}}``
  (Claude Desktop / MCP config style)
- ``{"servers": {"name": {"url": ..., "tools": [...]}}}`` (manifest style)
- a bare list of serialized tool definitions
- ``{"tools": [...]}`` (serialized ``tools/list`` response)
- ``{"tool": {...}}`` or a single tool dict

The parser NEVER executes anything and never fetches URLs. It only reads
metadata it was handed. Parse problems are collected as issues, never raised,
so a partially valid target can still be analyzed with an honest report of
what could not be understood.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

MAX_TOOL_NAME_LENGTH = 256
MAX_DESCRIPTION_LENGTH = 100_000  # defensive cap; real descriptions are far smaller


@dataclass
class ToolDef:
    """A normalized tool definition (metadata only — never executed here)."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    annotations: dict[str, Any] = field(default_factory=dict)
    server_name: str = ""
    raw_index: int = 0
    source: str = ""  # which input section it came from


@dataclass
class ServerMeta:
    name: str
    transport: str = "unknown"  # stdio|http|sse|unknown
    command: str = ""  # local command configured for stdio servers (string only)
    args: list[str] = field(default_factory=list)
    env_keys: list[str] = field(default_factory=list)  # keys only; never values
    url: str = ""
    explicit_capabilities: list[str] = field(default_factory=list)


@dataclass
class IngestIssue:
    code: str
    message: str
    severity: str = "warning"  # warning|error


@dataclass
class NormalizedTarget:
    servers: list[ServerMeta] = field(default_factory=list)
    tools: list[ToolDef] = field(default_factory=list)
    issues: list[IngestIssue] = field(default_factory=list)
    raw: Any = None

    @property
    def server_names(self) -> list[str]:
        return [s.name for s in self.servers]


def _as_json(value: Any) -> Any:
    """Accept already-parsed JSON or a JSON/JSON5-ish string (strict JSON only)."""
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty input")
        return json.loads(text)
    raise ValueError(f"unsupported input type: {type(value).__name__}")


def _clean_str(value: Any, limit: int = MAX_DESCRIPTION_LENGTH) -> str:
    if isinstance(value, str):
        return value[:limit]
    return ""


def _parse_tool_dict(obj: dict[str, Any], server: str, idx: int) -> ToolDef | None:
    name = obj.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    name = name.strip()[:MAX_TOOL_NAME_LENGTH]
    schema = obj.get("inputSchema") or obj.get("input_schema") or obj.get("parameters")
    if not isinstance(schema, dict):
        schema = {}
    annotations = obj.get("annotations")
    if not isinstance(annotations, dict):
        annotations = {}
    return ToolDef(
        name=name,
        description=_clean_str(obj.get("description", "")),
        input_schema=schema,
        annotations=annotations,
        server_name=server,
        raw_index=idx,
    )


def _parse_tools_list(items: Any, server: str) -> list[ToolDef]:
    tools: list[ToolDef] = []
    if not isinstance(items, list):
        return tools
    for i, item in enumerate(items):
        if isinstance(item, dict):
            tool = _parse_tool_dict(item, server, i)
            if tool:
                tool.source = "tools_list"
                tools.append(tool)
    return tools


def _parse_server_entry(name: str, entry: Any) -> tuple[ServerMeta, list[ToolDef]]:
    meta = ServerMeta(name=name)
    tools: list[ToolDef] = []
    if isinstance(entry, str):
        # e.g. "mcpServers": {"x": "http://host:port/sse"} or a bare command
        if entry.lower().startswith(("http://", "https://")):
            meta.transport, meta.url = "http", entry
        else:
            meta.transport, meta.command = "stdio", entry
        return meta, tools
    if not isinstance(entry, dict):
        return meta, tools

    meta.url = _clean_str(entry.get("url", ""), 512)
    if meta.url:
        meta.transport = "http"
    if entry.get("command"):
        meta.transport = "stdio"
        meta.command = _clean_str(entry.get("command"), 512)
        args = entry.get("args", [])
        if isinstance(args, list):
            meta.args = [_clean_str(a, 512) for a in args[:100]]
    env = entry.get("env", {})
    if isinstance(env, dict):
        # Keys only: values may be secrets and must not be copied anywhere.
        meta.env_keys = [str(k) for k in list(env.keys())[:100]]

    for cap_key in ("capabilities", "grants", "permissions"):
        caps = entry.get(cap_key)
        if isinstance(caps, list):
            meta.explicit_capabilities.extend(str(c) for c in caps[:100])
        elif isinstance(caps, dict):
            meta.explicit_capabilities.extend(str(k) for k in list(caps.keys())[:100])

    for tools_key in ("tools", "toolDefinitions", "functions"):
        parsed = _parse_tools_list(entry.get(tools_key), name)
        for t in parsed:
            t.source = tools_key
        tools.extend(parsed)
    return meta, tools


def normalize_target(raw_input: Any) -> NormalizedTarget:
    """Parse any supported input shape. Collects issues instead of raising."""
    target = NormalizedTarget()
    try:
        data = _as_json(raw_input)
    except (ValueError, TypeError) as exc:
        target.issues.append(IngestIssue("PARSE_ERROR", f"input is not valid JSON: {exc}", "error"))
        return target
    target.raw = data

    if isinstance(data, list):
        tools = _parse_tools_list(data, server="")
        if tools:
            target.tools = tools
            return target
        target.issues.append(
            IngestIssue("EMPTY_TOOLS_LIST", "array input contained no recognizable tool definitions")
        )
        return target

    if not isinstance(data, dict):
        target.issues.append(
            IngestIssue("UNSUPPORTED_SHAPE", "top-level JSON must be an object or array", "error")
        )
        return target

    if "mcpServers" in data and isinstance(data["mcpServers"], dict):
        sections = [("mcpServers", data["mcpServers"])]
    elif "servers" in data and isinstance(data["servers"], dict):
        sections = [("servers", data["servers"])]
    else:
        sections = []

    for section_name, section in sections:
        for server_name, entry in list(section.items())[:200]:
            if not isinstance(server_name, str) or not server_name.strip():
                target.issues.append(
                    IngestIssue("SERVER_NAME_MISSING", f"a {section_name} entry has no name")
                )
                continue
            meta, tools = _parse_server_entry(server_name.strip(), entry)
            target.servers.append(meta)
            target.tools.extend(tools)

    if "tools" in data and isinstance(data["tools"], list):
        target.tools.extend(_parse_tools_list(data["tools"], server=""))
    elif isinstance(data.get("name"), str) and ("inputSchema" in data or "input_schema" in data):
        single = _parse_tool_dict(data, server="", idx=0)
        if single:
            single.source = "single_tool"
            target.tools.append(single)

    if not target.servers and not target.tools and not target.issues:
        target.issues.append(
            IngestIssue(
                "NOTHING_RECOGNIZED",
                "no servers or tools recognized; expected mcpServers/servers/tools or tool definitions",
            )
        )
    return target


def target_fingerprint(target: NormalizedTarget) -> str:
    """Stable short fingerprint of the analyzed content (for reproducibility)."""
    import hashlib

    payload = {
        "servers": [
            {"name": s.name, "transport": s.transport, "command": s.command, "url": s.url}
            for s in target.servers
        ],
        "tools": [
            {"name": t.name, "description": t.description, "schema": t.input_schema}
            for t in target.tools
        ],
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]
