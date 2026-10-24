"""Unit tests: SchemaAnalyzer, CapabilityAnalyzer, CollisionAnalyzer."""

from backend.scanners.mcp_ingest import normalize_target
from backend.scanners.static.schema_analyzer import SchemaAnalyzer
from backend.scanners.static.capability_analyzer import CapabilityAnalyzer, infer_tool_capabilities
from backend.scanners.static.collision_analyzer import CollisionAnalyzer, find_collisions


def _tools(*tools):
    return normalize_target({"tools": list(tools)})


# ------------------------- SchemaAnalyzer -------------------------

def test_missing_schema_flagged():
    findings = SchemaAnalyzer().analyze(_tools({"name": "t", "description": "d", "inputSchema": {}}))
    assert any(f.rule_id == "SCHEMA-000" and f.status == "confirmed" for f in findings)


def test_unconstrained_string_flagged_with_recommendation():
    schema = {"type": "object", "properties": {"q": {"type": "string"}}}
    findings = SchemaAnalyzer().analyze(_tools({"name": "t", "description": "d", "inputSchema": schema}))
    f = next(f for f in findings if f.rule_id == "SCHEMA-001")
    assert "maxLength" in f.remediation or "constraints" in f.remediation
    assert f.evidence[0].detail["recommendation"]


def test_path_like_param_flagged_as_suspected_not_confirmed():
    schema = {"type": "object", "properties": {"path": {"type": "string"}}}
    findings = SchemaAnalyzer().analyze(_tools({"name": "t", "description": "d", "inputSchema": schema}))
    f = next(f for f in findings if f.rule_id == "SCHEMA-010")
    assert f.status == "suspected"
    assert "allowlist" in f.remediation.lower()


def test_command_like_param_high_severity():
    schema = {"type": "object", "properties": {"command": {"type": "string"}}}
    findings = SchemaAnalyzer().analyze(_tools({"name": "t", "description": "d", "inputSchema": schema}))
    f = next(f for f in findings if f.rule_id == "SCHEMA-011")
    assert f.severity == "high"


def test_constrained_schema_not_flagged():
    schema = {
        "type": "object",
        "properties": {"city": {"type": "string", "maxLength": 80}, "units": {"type": "string", "enum": ["m", "i"]}},
        "required": ["city"],
    }
    findings = SchemaAnalyzer().analyze(_tools({"name": "t", "description": "d", "inputSchema": schema}))
    assert not [f for f in findings if f.rule_id in ("SCHEMA-000", "SCHEMA-001")]


# ------------------------- CapabilityAnalyzer -------------------------

def test_dangerous_combination_reported_as_suspected():
    schema = {"type": "object", "properties": {"path": {"type": "string"}, "url": {"type": "string"}}}
    findings = CapabilityAnalyzer().analyze(
        _tools({"name": "read_and_send", "description": "Reads a file and posts it to a URL.", "inputSchema": schema})
    )
    combos = [f for f in findings if f.rule_id == "CAP-010"]
    assert combos, "expected capability combination finding"
    f = combos[0]
    assert f.status == "suspected", "combinations must not be claimed as confirmed without dynamic evidence"
    assert "required_evidence_for_exploitability" in f.evidence[0].detail


def test_capability_inference_from_name_and_params():
    caps = infer_tool_capabilities(
        normalize_target({"tools": [{"name": "fetch_url", "description": "", "inputSchema": {}}]}).tools[0]
    )
    assert "network_access" in caps


def test_shell_plus_network_is_critical():
    schema = {"type": "object", "properties": {"command": {"type": "string"}, "url": {"type": "string"}}}
    findings = CapabilityAnalyzer().analyze(
        _tools({"name": "run_and_fetch", "description": "Runs commands and fetches URLs.", "inputSchema": schema})
    )
    combo = next(f for f in findings if f.rule_id == "CAP-010")
    assert combo.severity == "critical"


def test_env_keys_never_include_values():
    target = normalize_target({"mcpServers": {"s": {"command": "x", "env": {"SECRET_KEY": "super-secret-value"}}}})
    findings = CapabilityAnalyzer().analyze(target)
    env_findings = [f for f in findings if f.rule_id == "CAP-020"]
    assert env_findings
    blob = str(env_findings[0].evidence[0].detail)
    assert "super-secret-value" not in blob, "secret values must never appear in findings"
    assert "SECRET_KEY" in blob, "key names are fine"


# ------------------------- CollisionAnalyzer -------------------------

def test_exact_duplicate_confirmed():
    collisions = find_collisions(["read_file", "read_file", "other"])
    assert any(c.kind == "exact" for c in collisions)


def test_case_insensitive_collision_confirmed():
    collisions = find_collisions(["read_file", "Read_File"])
    assert any(c.kind == "case_insensitive" for c in collisions)


def test_near_duplicate_suspected():
    collisions = find_collisions(["read_file", "readfile"])
    kinds = {c.kind for c in collisions}
    assert "near_duplicate" in kinds or "case_insensitive" in kinds or "normalized" in kinds


def test_different_names_not_flagged():
    assert find_collisions(["get_weather", "list_files", "send_email"]) == []


def test_collision_finding_levels():
    target = _tools(
        {"name": "read_file", "description": "Reads a file", "inputSchema": {}},
        {"name": "Read_File", "description": "Reads a file", "inputSchema": {}},
        {"name": "readfile", "description": "Reads a file", "inputSchema": {}},
    )
    findings = CollisionAnalyzer().analyze(target)
    confirmed = [f for f in findings if f.status == "confirmed"]
    assert confirmed, "case-insensitive collisions must be confirmed"
    assert all(f.severity in ("medium", "high") for f in confirmed)
