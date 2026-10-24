"""Capability/permission analysis: builds a capability graph per tool and
reports dangerous *combinations* honestly.

A capability (filesystem read, network egress, shell…) is not a vulnerability.
A combination raises what an attacker could do IF they steer the agent or the
tool misbehaves. The analyzer therefore reports:
- capability presence (informational)
- dangerous combinations (suspected, with required-evidence statement)
and never claims confirmed exploitability — that requires dynamic evidence.
"""

from __future__ import annotations

import re
from typing import Any

from backend.scanners.mcp_ingest import NormalizedTarget, ServerMeta, ToolDef
from backend.scanners.static.base import Evidence, StaticAnalyzer, StaticFinding

# --- Capability inference ---------------------------------------------------
# Ordered: first match wins. Sources: tool name, description, schema param names.
CAPABILITY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("shell_execution", ("shell", "command", "exec", "terminal", "bash", "process", "powershell", "cmd", "run_")),
    ("filesystem_write", ("write_file", "write", "create_file", "delete_file", "move_file", "rename", "mkdir", "upload_to_disk", "save_file", "replace")),
    ("filesystem_read", ("read_file", "read", "list_dir", "ls", "glob", "grep", "find_files", "open_file", "cat", "tail", "head", "walk", "stat")),
    ("network_access", ("fetch", "http", "url", "request", "curl", "download", "web", "browse", "api_call", "get_url", "post_", "webhook", "scrape", "search_web")),
    ("credential_access", ("credential", "secret", "password", "api_key", "token", "keychain", "vault", "keystore", "ssh_key")),
    ("database_access", ("sql", "query", "database", "db_", "sqlite", "postgres", "mysql", "mongo")),
    ("email_access", ("mail", "smtp", "send_email", "inbox")),
)

# Name-based signals are stronger than description-based ones.
_NAME_WEIGHT = 2
_DESC_WEIGHT = 1


def _infer_capabilities(tool: ToolDef) -> dict[str, list[str]]:
    """Return capability -> evidence strings that triggered it."""
    caps: dict[str, list[str]] = {}
    name_l = tool.name.lower()
    desc_l = (tool.description or "").lower()
    param_names: list[str] = []

    def walk(schema: dict[str, Any]) -> None:
        props = schema.get("properties")
        if isinstance(props, dict):
            param_names.extend(str(k).lower() for k in props.keys())
            for v in props.values():
                if isinstance(v, dict):
                    walk(v)
        items = schema.get("items")
        if isinstance(items, dict):
            walk(items)

    walk(tool.input_schema if isinstance(tool.input_schema, dict) else {})

    def hit(cap: str, evidence: str, weight: int) -> None:
        caps.setdefault(cap, []).append(evidence)

    for cap, signals in CAPABILITY_RULES:
        for sig in signals:
            if re.search(rf"(^|[_\-\b]){re.escape(sig)}([_\-\b]|$)", name_l):
                hit(cap, f"tool name contains '{sig}'", _NAME_WEIGHT)
                break
        for sig in signals:
            if re.search(rf"(^|[^a-z]){re.escape(sig)}([^a-z]|$)", desc_l):
                hit(cap, f"description mentions '{sig}'", _DESC_WEIGHT)
                break
        for sig in signals:
            for pn in param_names:
                if sig in pn:
                    hit(cap, f"parameter '{pn}' matches '{sig}'", _NAME_WEIGHT)
                    break

    return caps


def infer_tool_capabilities(tool: ToolDef) -> list[str]:
    return sorted(_infer_capabilities(tool).keys())


DANGEROUS_COMBINATIONS: tuple[dict, ...] = (
    {
        "caps": frozenset({"filesystem_read", "network_access"}),
        "risk": "Files readable by the tool can be encoded into outbound network requests; a "
                "compromised or poisoned tool becomes an exfiltration channel.",
        "required_evidence": "Dynamic evidence of reading a sensitive file AND issuing an outbound request in one invocation chain.",
        "base_severity": "high",
    },
    {
        "caps": frozenset({"filesystem_write", "network_access"}),
        "risk": "Content fetched from the network can be written to disk (or local files uploaded): "
                "remote code landing on disk, or data leaving the machine.",
        "required_evidence": "Dynamic evidence of downloaded content being persisted.",
        "base_severity": "high",
    },
    {
        "caps": frozenset({"credential_access", "network_access"}),
        "risk": "Credentials readable in this context can be transmitted off-machine; the classic "
                "exfiltration endgame.",
        "required_evidence": "Dynamic evidence of secret material reaching an outbound request.",
        "base_severity": "critical",
    },
    {
        "caps": frozenset({"shell_execution", "filesystem_write"}),
        "risk": "Arbitrary commands plus file writes enable persistence (profile scripts, cron, "
                "autostart entries).",
        "required_evidence": "Dynamic evidence of a command writing outside the working directory.",
        "base_severity": "high",
    },
    {
        "caps": frozenset({"shell_execution", "network_access"}),
        "risk": "Command execution plus network access enables downloading and running payloads "
                "(reverse shells, droppers).",
        "required_evidence": "Dynamic evidence of an outbound connection initiated from executed commands.",
        "base_severity": "critical",
    },
    {
        "caps": frozenset({"shell_execution", "credential_access"}),
        "risk": "Commands can read any secret the process user can read (env vars, ~/.ssh, "
                "browser cookies).",
        "required_evidence": "Dynamic evidence of secret material appearing in command output.",
        "base_severity": "critical",
    },
)


class CapabilityAnalyzer(StaticAnalyzer):
    rule_id_prefix = "CAP"

    def analyze(self, target: NormalizedTarget) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        tool_caps: dict[str, dict[str, list[str]]] = {}

        for tool in target.tools:
            caps = _infer_capabilities(tool)
            if caps:
                tool_caps[tool.name] = caps

        # server-level explicit grants feed per-server findings
        for server in target.servers:
            findings.extend(self._server_findings(server))

        # per-tool combinations
        for tool_name, caps in sorted(tool_caps.items()):
            cap_set = set(caps.keys())
            if len(cap_set) >= 2:
                findings.append(
                    StaticFinding(
                        rule_id="CAP-001",
                        category="capability",
                        severity="info",
                        title=f"Capability profile for tool '{tool_name}'",
                        description=(
                            f"Static analysis inferred capabilities: {', '.join(sorted(cap_set))}. "
                            f"Cap: {sum(len(v) for v in caps.values())} evidence signal(s)."
                        ),
                        status="informational",
                        confidence="medium",
                        evidence=[
                            Evidence(
                                kind="capability_signal",
                                summary=f"{cap}: {'; '.join(evs[:3])}",
                                detail={"capability": cap, "signals": evs[:6]},
                            )
                            for cap, evs in sorted(caps.items())
                        ],
                        affected_tools=[tool_name],
                        impact=(
                            "Capability inference is heuristic (based on names/descriptions/parameter "
                            "names) and can produce false positives. Treat as prioritization input, "
                            "not proof."
                        ),
                        remediation="Review whether each inferred capability is genuinely required (least privilege).",
                        references=["MCP specification - tool annotations"],
                    )
                )
            for combo in DANGEROUS_COMBINATIONS:
                if combo["caps"].issubset(cap_set):
                    c1, c2 = sorted(combo["caps"])
                    findings.append(
                        StaticFinding(
                            rule_id="CAP-010",
                            category="capability",
                            severity=combo["base_severity"],  # type: ignore[arg-type]
                            title=f"Dangerous capability combination in tool '{tool_name}' ({c1} + {c2})",
                            description=(
                                f"Tool '{tool.name if False else tool_name}' exposes {c1} and {c2} "
                                f"together. {combo['risk']}"
                            ),
                            status="suspected",
                            confidence="medium",
                            evidence=[
                                Evidence(
                                    kind="capability_combination",
                                    summary=f"{c1} + {c2} inferred from: "
                                            + " | ".join(
                                                f"{cap}: {'; '.join(evs[:2])}"
                                                for cap, evs in sorted(caps.items())
                                                if cap in combo["caps"]
                                            ),
                                    detail={
                                        "capabilities": sorted(combo["caps"]),
                                        "signals": {cap: evs[:4] for cap, evs in caps.items() if cap in combo["caps"]},
                                        "required_evidence_for_exploitability": combo["required_evidence"],
                                    },
                                )
                            ],
                            affected_tools=[tool_name],
                            impact=combo["risk"]
                            + " NOTE: a capability combination is attack surface, not a confirmed "
                              "vulnerability. Exploitability requires the dynamic evidence stated "
                              "in this finding.",
                            remediation=(
                                "Split capabilities across tools/roles where feasible; apply "
                                "least privilege; add server-side controls (path allowlists, egress "
                                "filters, command allowlists)."
                            ),
                            reproduction={
                                "type": "static",
                                "steps": [
                                    f"List capabilities of '{tool_name}'",
                                    "Compare against the documented dangerous-combination table",
                                ],
                            },
                            references=[
                                "OWASP Agentic AI - Excessive Agency",
                                "CWE-250 Execution with Unnecessary Privileges",
                            ],
                        )
                    )
        return findings

    def _server_findings(self, server: ServerMeta) -> list[StaticFinding]:
        out: list[StaticFinding] = []
        if server.env_keys:
            out.append(
                StaticFinding(
                    rule_id="CAP-020",
                    category="permission",
                    severity="info",
                    title=f"Server '{server.name}' receives environment variables ({len(server.env_keys)} keys)",
                    description=(
                        f"The MCP client injects environment variables into server '{server.name}': "
                        f"{', '.join(server.env_keys[:20])}. Values were NOT read or stored."
                    ),
                    status="informational",
                    confidence="high",
                    evidence=[
                        Evidence(
                            kind="config_field",
                            summary=f"env keys: {', '.join(server.env_keys[:20])}",
                            detail={"env_keys": server.env_keys, "values": "(not collected)"},
                        )
                    ],
                    affected_tools=[],
                    impact="Injected secrets are visible to the server process; a compromised server can read them all.",
                    remediation="Pass only the variables the server needs; prefer a secret manager over .env injection.",
                    references=["CWE-214 Invocation of Process Using Visible Sensitive Information"],
                )
            )
        if server.command:
            out.append(
                StaticFinding(
                    rule_id="CAP-021",
                    category="permission",
                    severity="info",
                    title=f"Server '{server.name}' is launched via a local command",
                    description=(
                        f"Configured command: {server.command} "
                        f"{' '.join(server.args[:20])}. Running a local MCP server grants it the "
                        f"privileges of your user account."
                    ),
                    status="informational",
                    confidence="high",
                    evidence=[
                        Evidence(
                            kind="config_field",
                            summary=f"command: {server.command}",
                            detail={"command": server.command, "args": server.args[:20]},
                        )
                    ],
                    affected_tools=[],
                    impact="Any code the server runs executes with your user privileges; treat installation as code review.",
                    remediation="Pin the server version, review its source, and run it under a least-privilege account when possible.",
                    references=["MCP specification - stdio transport"],
                )
            )
        return out
