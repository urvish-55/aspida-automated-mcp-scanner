"""Unit tests: MCP ingestion normalizer + inert probe generator."""

import json

import pytest

from backend.scanners.mcp_ingest import normalize_target, target_fingerprint
from backend.scanners.dynamic.probes import ProbeGenerator
from backend.scanners.dynamic.connector import MCPTool


def test_parse_mcp_servers_config():
    cfg = {"mcpServers": {"a": {"command": "python", "args": ["s.py"], "env": {"K": "v"}}}}
    t = normalize_target(cfg)
    assert t.servers[0].name == "a"
    assert t.servers[0].transport == "stdio"
    assert t.servers[0].env_keys == ["K"]  # keys only
    assert not hasattr(t.servers[0], "env_values")


def test_parse_tools_list_response():
    t = normalize_target({"tools": [{"name": "x", "description": "d", "inputSchema": {"type": "object"}}]})
    assert t.tools[0].name == "x"
    assert t.issues == []


def test_parse_bare_array():
    t = normalize_target([{"name": "x", "description": "d", "inputSchema": {}}])
    assert t.tools[0].name == "x"


def test_parse_single_tool():
    t = normalize_target({"name": "solo", "description": "d", "inputSchema": {"type": "object"}})
    assert t.tools[0].name == "solo"


def test_invalid_json_collects_issue_not_raise():
    t = normalize_target("{not json")
    assert any(i.code == "PARSE_ERROR" for i in t.issues)
    assert t.tools == []


def test_unrecognized_shape():
    t = normalize_target({"foo": 1})
    assert any(i.code == "NOTHING_RECOGNIZED" for i in t.issues)


def test_env_values_never_captured():
    cfg = {"mcpServers": {"a": {"env": {"API_KEY": "SHOULD-NOT-APPEAR"}}}}
    blob = json.dumps(vars(normalize_target(cfg).servers[0]))
    assert "SHOULD-NOT-APPEAR" not in blob


def test_fingerprint_stable():
    a = normalize_target({"tools": [{"name": "x", "description": "d", "inputSchema": {}}]})
    b = normalize_target({"tools": [{"name": "x", "description": "d", "inputSchema": {}}]})
    assert target_fingerprint(a) == target_fingerprint(b)
    c = normalize_target({"tools": [{"name": "y", "description": "d", "inputSchema": {}}]})
    assert target_fingerprint(a) != target_fingerprint(c)


# ----------------------------- probes -----------------------------

@pytest.fixture
def gen():
    return ProbeGenerator(marker_secret="fixed-for-test")


def _tool(schema):
    return MCPTool(name="t", description="d", input_schema=schema)


def test_traversal_probes_generated_for_path_param(gen):
    probes = gen.traversal_probes(_tool({"type": "object", "properties": {"path": {"type": "string"}}}))
    assert len(probes) >= 3
    assert all(p.family == "path_traversal" for p in probes)

    def is_traversalish(v: str) -> bool:
        v = v.lower().replace("%2f", "/")
        return "../" in v or "..\\" in v or v.startswith("/etc")

    assert all(is_traversalish(p.arguments["path"]) for p in probes)


def test_no_probes_without_relevant_param(gen):
    assert gen.traversal_probes(_tool({"type": "object", "properties": {"city": {"type": "string"}}})) == []
    assert gen.command_injection_probes(_tool({"type": "object", "properties": {"city": {"type": "string"}}})) == []


def test_command_probes_use_only_echo_marker(gen):
    probes = gen.command_injection_probes(_tool({"type": "object", "properties": {"command": {"type": "string"}}}))
    assert probes
    forbidden = ("rm ", "del ", "format", "shutdown", "kill ", "mkfs", "curl ", "wget ")
    for p in probes:
        payload = str(p.arguments["command"]).lower()
        assert not any(f in payload for f in forbidden), f"destructive token in payload: {payload}"
        assert gen.marker in p.arguments["command"]
        assert "echo" in p.arguments["command"]


def test_markers_unique_per_scanner(gen):
    from backend.scanners.dynamic.probes import ProbeGenerator

    other = ProbeGenerator()
    assert other.marker != gen.marker


def test_oversized_probe_bounded(gen):
    probes = gen.oversized_probes(_tool({"type": "object", "properties": {"x": {"type": "string"}}}), max_payload_bytes=8192)
    assert len(probes) == 1
    assert len(probes[0].arguments["x"]) <= 4096


def test_missing_required_probe_omits_param(gen):
    schema = {"type": "object", "properties": {"a": {"type": "string"}, "b": {"type": "integer"}}, "required": ["a", "b"]}
    probes = gen.malformed_probes(_tool(schema))
    missing = next(p for p in probes if p.test_name.startswith("Missing required"))
    assert "a" not in missing.arguments, "the targeted required param must be omitted"
    assert missing.arguments.get("b") == 1


def test_payload_size_computable(gen):
    probes = gen.traversal_probes(_tool({"type": "object", "properties": {"path": {"type": "string"}}}))
    assert all(p.payload_size > 0 for p in probes)
