"""Input-schema analysis: weak validation on tool parameters.

A wide-open schema is not a vulnerability by itself, but it defines the attack
surface a caller (or an attacker steering an agent) can reach. This analyzer
flags *specific* schema weaknesses with per-parameter evidence and concrete
recommendations, and never claims exploitability it cannot show.
"""

from __future__ import annotations

from typing import Any

from backend.scanners.mcp_ingest import NormalizedTarget, ToolDef
from backend.scanners.static.base import (
    Evidence,
    StaticAnalyzer,
    StaticFinding,
    path_like_name,
    shell_like_name,
    sql_like_name,
    url_like_name,
)

MAX_DEPTH = 6


def _iter_params(schema: dict[str, Any], prefix: str = "", depth: int = 0):
    """Yield (json_path, prop_dict, required) over object properties."""
    if not isinstance(schema, dict) or depth > MAX_DEPTH:
        return
    props = schema.get("properties")
    if isinstance(props, dict):
        raw_required = schema.get("required")
        required: list[Any] = raw_required if isinstance(raw_required, list) else []
        for name, prop in props.items():
            path = f"{prefix}.{name}" if prefix else name
            yield path, prop if isinstance(prop, dict) else {}, name in required
            yield from _iter_params(prop if isinstance(prop, dict) else {}, path, depth + 1)
    items = schema.get("items")
    if isinstance(items, dict):
        yield from _iter_params(items, f"{prefix}[]", depth + 1)


def _unconstrained_string(prop: dict[str, Any]) -> bool:
    if prop.get("type") not in ("string", None) and "anyOf" not in prop and "oneOf" not in prop:
        return False
    has_constraint = any(
        k in prop
        for k in ("enum", "const", "maxLength", "minLength", "pattern", "format", "anyOf", "oneOf")
    )
    return not has_constraint


def _restricted(prop: dict[str, Any]) -> bool:
    """True when the value domain is genuinely narrowed (enum/const/pattern)."""
    return any(k in prop for k in ("enum", "const", "pattern"))


def _weakly_typed(prop: dict[str, Any]) -> str | None:
    """Describe why a parameter is weakly typed / arbitrary, or None if it is fine."""
    if any(k in prop for k in ("enum", "const", "anyOf", "oneOf", "allOf", "$ref")):
        return None
    t = prop.get("type")
    if t is None:
        return "no declared type (accepts any JSON value)"
    if t == "object" and not prop.get("properties") and prop.get("additionalProperties", True) is not False:
        return "free-form object with no declared properties"
    if t == "array" and not isinstance(prop.get("items"), dict):
        return "array with no declared item schema"
    return None


class SchemaAnalyzer(StaticAnalyzer):
    rule_id_prefix = "SCHEMA"

    def analyze(self, target: NormalizedTarget) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for tool in target.tools:
            findings.extend(self._analyze_tool(tool))
        return findings

    def _analyze_tool(self, tool: ToolDef) -> list[StaticFinding]:
        schema = tool.input_schema
        if not schema:
            return [
                StaticFinding(
                    rule_id="SCHEMA-000",
                    category="schema",
                    severity="medium",
                    title=f"Tool '{tool.name}' declares no input schema",
                    description=(
                        f"Tool '{tool.name}' has an empty or missing input schema. The caller "
                        f"cannot know what inputs are valid, and the server cannot rely on any "
                        f"validation contract."
                    ),
                    status="confirmed",
                    confidence="high",
                    evidence=[
                        Evidence(
                            kind="schema_field",
                            summary="inputSchema is empty or absent",
                            detail={"tool": tool.name, "field": "inputSchema"},
                        )
                    ],
                    affected_tools=[tool.name],
                    impact=(
                        "Without a schema, every argument is arbitrary: no max lengths, no types, "
                        "no enums. This maximizes the chance that malformed or malicious input "
                        "reaches server-side handling code."
                    ),
                    remediation=(
                        "Publish a JSON Schema for every parameter with explicit types and "
                        "constraints (maxLength, enum, pattern, format)."
                    ),
                    reproduction={"type": "static", "steps": [f"Inspect tool '{tool.name}' definition"]},
                    references=["MCP specification - tool inputSchema"],
                )
            ]

        findings: list[StaticFinding] = []
        unconstrained: list[tuple[str, dict]] = []
        path_like: list[tuple[str, dict]] = []
        url_like: list[tuple[str, dict]] = []
        shell_like: list[tuple[str, dict]] = []
        sql_like: list[tuple[str, dict]] = []
        no_max_len: list[str] = []
        weak: list[tuple[str, dict, str]] = []

        for path, prop, _required in _iter_params(schema):
            name = path.split(".")[-1]
            if isinstance(prop.get("type"), str) and prop["type"] == "string" and "maxLength" not in prop:
                no_max_len.append(path)
            reason = _weakly_typed(prop)
            if reason:
                weak.append((path, prop, reason))
            special = False
            if not _restricted(prop):
                if path_like_name(name):
                    path_like.append((path, prop))
                    special = True
                if url_like_name(name):
                    url_like.append((path, prop))
                    special = True
                if shell_like_name(name):
                    shell_like.append((path, prop))
                    special = True
                if sql_like_name(name):
                    sql_like.append((path, prop))
                    special = True
            # Parameters already reported by a specific rule are not repeated as generic noise.
            if _unconstrained_string(prop) and not special:
                unconstrained.append((path, prop))

        def ev(path: str, prop: dict[str, Any], observed: str, risk: str, recommendation: str) -> Evidence:
            return Evidence(
                kind="schema_field",
                summary=f"parameter '{path}': {observed}",
                detail={
                    "parameter": path,
                    "observed": observed,
                    "risk": risk,
                    "recommendation": recommendation,
                    "declared_type": prop.get("type", "(none)"),
                    "constraints": {
                        k: prop[k]
                        for k in ("enum", "maxLength", "pattern", "format")
                        if k in prop
                    },
                },
            )

        if unconstrained:
            findings.append(
                StaticFinding(
                    rule_id="SCHEMA-001",
                    category="schema",
                    severity="low",
                    title=f"Unconstrained string parameters in tool '{tool.name}'",
                    description=(
                        f"{len(unconstrained)} parameter(s) accept arbitrary strings with no type, "
                        f"length, pattern or enum restriction: "
                        f"{', '.join(p for p, _ in unconstrained[:8])}."
                    ),
                    status="confirmed",
                    confidence="high",
                    evidence=[
                        ev(
                            p,
                            prop,
                            "string with no restrictions",
                            "Unvalidated free-form input reaches server logic unbounded",
                            "Add explicit type, maxLength and pattern/enum constraints to the schema.",
                        )
                        for p, prop in unconstrained[:12]
                    ],
                    affected_tools=[tool.name],
                    impact=(
                        "Unbounded input is the root cause of oversized-payload DoS, parser abuse "
                        "and downstream injection when the value reaches interpreters (shell, SQL, "
                        "paths, URLs)."
                    ),
                    remediation=(
                        "Constrain every parameter: type, maxLength, and pattern/enum where the "
                        "value domain is known."
                    ),
                    reproduction={"type": "static", "steps": [f"Read inputSchema of tool '{tool.name}'"]},
                    references=["CWE-20 Improper Input Validation"],
                )
            )

        if weak:
            findings.append(
                StaticFinding(
                    rule_id="SCHEMA-020",
                    category="schema",
                    severity="low",
                    title=f"Weakly typed or free-form parameters in tool '{tool.name}'",
                    description=(
                        f"{len(weak)} parameter(s) accept arbitrary JSON structure: "
                        f"{', '.join(p for p, _, _ in weak[:8])}."
                    ),
                    status="confirmed",
                    confidence="high",
                    evidence=[
                        ev(p, prop, reason, "Arbitrary structure reaches server logic unvalidated",
                           "Declare an explicit type and, for objects, 'properties' with "
                           "'additionalProperties': false; for arrays declare 'items'.")
                        for p, prop, reason in weak[:12]
                    ],
                    affected_tools=[tool.name],
                    impact="Free-form JSON enlarges the input surface (mass assignment, deserialization and parser abuse).",
                    remediation="Give every parameter an explicit type and closed object shape.",
                    reproduction={"type": "static", "steps": [f"Read inputSchema of tool '{tool.name}'"]},
                    references=["CWE-20 Improper Input Validation"],
                )
            )

        if path_like:
            findings.append(
                StaticFinding(
                    rule_id="SCHEMA-010",
                    category="schema",
                    severity="medium",
                    title=f"Path-like parameters without declared constraints in tool '{tool.name}'",
                    description=(
                        f"Parameter(s) {', '.join(p for p, _ in path_like[:8])} look like filesystem "
                        f"paths. The schema does not restrict them to an allowlisted root."
                    ),
                    status="suspected",
                    confidence="medium",
                    evidence=[
                        ev(
                            p,
                            prop,
                            "path-like name accepted as a plain string",
                            "Potential path traversal exposure if the server opens files by this value",
                            "Restrict filesystem paths to an allowlisted directory, canonicalize "
                            "before access, and reject '..' and absolute paths server-side.",
                        )
                        for p, prop in path_like[:8]
                    ],
                    affected_tools=[tool.name],
                    impact="Path-traversal class exposure (e.g. '../../../etc/passwd') depends on server-side handling, which static analysis cannot observe.",
                    remediation=(
                        "Canonicalize with realpath, require the resolved path to start with the "
                        "allowlisted root, and document the restriction in the schema description."
                    ),
                    references=["CWE-22 Path Traversal"],
                )
            )

        if shell_like:
            findings.append(
                StaticFinding(
                    rule_id="SCHEMA-011",
                    category="schema",
                    severity="high",
                    title=f"Command-like parameters in tool '{tool.name}'",
                    description=(
                        f"Parameter(s) {', '.join(p for p, _ in shell_like[:8])} appear to carry "
                        f"shell/command input. Schema-level constraints cannot make command "
                        f"execution safe."
                    ),
                    status="suspected",
                    confidence="medium",
                    evidence=[
                        ev(
                            p,
                            prop,
                            "command-like name accepted as free-form string",
                            "Potential command injection exposure if the value reaches a shell",
                            "Avoid shell invocation entirely; if unavoidable, use argument arrays "
                            "(no shell), allowlist the program, and reject metacharacters.",
                        )
                        for p, prop in shell_like[:8]
                    ],
                    affected_tools=[tool.name],
                    impact="Command-injection class exposure (e.g. '; rm -rf /' or backticks) depends on server-side handling.",
                    remediation="Never interpolate user input into a shell string. Prefer structured APIs.",
                    references=["CWE-78 OS Command Injection"],
                )
            )

        if url_like:
            findings.append(
                StaticFinding(
                    rule_id="SCHEMA-012",
                    category="schema",
                    severity="medium",
                    title=f"URL-like parameters without scheme/host restrictions in tool '{tool.name}'",
                    description=(
                        f"Parameter(s) {', '.join(p for p, _ in url_like[:8])} look like URLs. If the "
                        f"server fetches them, this is a server-side-request-forgery surface."
                    ),
                    status="suspected",
                    confidence="medium",
                    evidence=[
                        ev(
                            p,
                            prop,
                            "URL-like name accepted as free-form string",
                            "Potential SSRF exposure if the server fetches the value",
                            "Allowlist schemes (https only) and destination hosts; block private/"
                            "link-local/metadata IP ranges server-side.",
                        )
                        for p, prop in url_like[:8]
                    ],
                    affected_tools=[tool.name],
                    impact="SSRF class exposure (internal services, cloud metadata endpoints) depends on server-side handling.",
                    remediation="Validate destinations server-side against an allowlist; resolve DNS and re-check after redirects.",
                    references=["CWE-918 Server-Side Request Forgery"],
                )
            )

        if sql_like:
            findings.append(
                StaticFinding(
                    rule_id="SCHEMA-013",
                    category="schema",
                    severity="low",
                    title=f"SQL-like parameters in tool '{tool.name}'",
                    description=(
                        f"Parameter(s) {', '.join(p for p, _ in sql_like[:8])} appear to carry SQL/"
                        f"query text."
                    ),
                    status="suspected",
                    confidence="low",
                    evidence=[
                        ev(
                            p,
                            prop,
                            "SQL/query-like name accepted as free-form string",
                            "Potential SQL injection exposure if interpolated into a query",
                            "Use parameterized queries; if ad-hoc queries are the feature, run "
                            "read-only against a sandboxed replica.",
                        )
                        for p, prop in sql_like[:8]
                    ],
                    affected_tools=[tool.name],
                    impact="SQL-injection class exposure depends on server-side handling.",
                    remediation="Parameterized statements; least-privilege DB account.",
                    references=["CWE-89 SQL Injection"],
                )
            )

        return findings
