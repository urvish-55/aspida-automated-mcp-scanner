"""Tool-name analysis: suspicious naming that needs no description to be risky."""

from __future__ import annotations

import re

from backend.scanners.mcp_ingest import NormalizedTarget
from backend.scanners.static.base import Evidence, StaticAnalyzer, StaticFinding

SUSPICIOUS_NAME_RE = re.compile(
    r"(exfiltrat\w*|keylog\w*|backdoor|rootkit|stealth|covert|bypass|"
    r"credential_?dump\w*|password_?sniff\w*|shadow_?tool|token_?grab\w*|"
    r"reverse_?shell|silent_?exec|priv_?esc\w*|hidden)",
    re.IGNORECASE,
)

WHY = (
    "The tool name itself contains terminology associated with covert or malicious "
    "operation. A name is not proof of malicious behavior, but it changes the review "
    "priority: the tool should be treated as untrusted until its origin is verified."
)


class ToolNameAnalyzer(StaticAnalyzer):
    rule_id_prefix = "NAME"

    def analyze(self, target: NormalizedTarget) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        for tool in target.tools:
            m = SUSPICIOUS_NAME_RE.search(tool.name)
            if not m:
                continue
            findings.append(
                StaticFinding(
                    rule_id="NAME-001",
                    category="naming",
                    severity="medium",
                    title=f"Suspicious tool name: '{tool.name}'",
                    description=(
                        f"Tool name '{tool.name}' matches suspicious naming patterns "
                        f"(matched: '{m.group(0)}')."
                    ),
                    status="suspected",
                    confidence="medium",
                    evidence=[
                        Evidence(
                            kind="name_match",
                            summary=f"tool name '{tool.name}' contains '{m.group(0)}'",
                            detail={
                                "tool_name": tool.name,
                                "matched_term": m.group(0),
                                "field": "tool name",
                                "why": WHY,
                            },
                        )
                    ],
                    affected_tools=[tool.name],
                    impact=WHY,
                    remediation=(
                        "Verify the tool's publisher and provenance. If the name does not match "
                        "the tool's documented purpose, disable it pending review."
                    ),
                    reproduction={
                        "type": "static",
                        "steps": [f"Compare tool name '{tool.name}' against its advertised purpose"],
                    },
                    references=["OWASP Agentic AI - Tool Poisoning"],
                )
            )
        return findings
