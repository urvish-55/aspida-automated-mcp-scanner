"""Static analyzer base: finding dataclass, analyzer protocol, shared helpers.

Contract for every analyzer:
- Pure functions over the normalized target. No I/O, no execution, no network.
- Deterministic: same input → same findings, same order.
- Errors are caught by the engine, never allowed to abort the scan.
- Every finding carries concrete evidence and an explanation of WHY it is
  flagged; keyword-only verdicts are not acceptable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

from backend.scanners.mcp_ingest import NormalizedTarget, ToolDef

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
FindingStatus = Literal["confirmed", "suspected", "informational", "not_tested", "not_applicable", "error"]

SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


@dataclass
class Evidence:
    kind: str  # e.g. "unicode_char", "text_match", "schema_field", "collision"
    summary: str  # one-line human-readable summary
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class StaticFinding:
    rule_id: str
    category: str
    severity: Severity
    title: str
    description: str
    status: FindingStatus
    confidence: Confidence
    evidence: list[Evidence]
    affected_tools: list[str] = field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    reproduction: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict:
        """Canonical dict form consumed by fusion, risk, persistence, reports."""
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "title": self.title,
            "description": self.description,
            "evidence": [
                {"kind": e.kind, "summary": e.summary, "detail": e.detail} for e in self.evidence
            ],
            "affected_tools": list(self.affected_tools),
            "reproduction": dict(self.reproduction),
            "impact": self.impact,
            "remediation": self.remediation,
            "references": list(self.references),
            "detector_sources": [self.rule_id],
        }

    def dedup_key(self) -> tuple:
        """Findings with the same key describe the same underlying issue and
        are merged (see fusion.py) rather than counted twice."""
        return (self.rule_id, self.category, tuple(sorted(set(self.affected_tools))))


class StaticAnalyzer(Protocol):
    rule_id_prefix: str

    def analyze(self, target: NormalizedTarget) -> list[StaticFinding]: ...


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

# Tool-facing text fields that should be scanned for hidden content.
TEXT_FIELDS: tuple[tuple[str, str], ...] = (
    ("description", "tool description"),
    ("name", "tool name"),
)


def iter_tool_text(tool: ToolDef) -> list[tuple[str, str, str]]:
    """Yield (field_name, human_field_label, text) for text fields of a tool."""
    out: list[tuple[str, str, str]] = []
    if tool.name:
        out.append(("name", "tool name", tool.name))
    if tool.description:
        out.append(("description", "tool description", tool.description))
    return out


def path_like_name(param_name: str) -> bool:
    lowered = param_name.lower()
    return bool(
        re.search(r"(path|file|filepath|filename|dir|directory|folder|location|location|target)$", lowered)
        or lowered in {"path", "file", "filename", "filepath", "dir", "cwd", "root"}
    )


def url_like_name(param_name: str) -> bool:
    lowered = param_name.lower()
    return "url" in lowered or "uri" in lowered or lowered.endswith("endpoint") or lowered.endswith("host")


def shell_like_name(param_name: str) -> bool:
    lowered = param_name.lower()
    return bool(
        re.search(r"(command|cmd|exec|shell|bash|script|args|arguments|argv|interpreter)$", lowered)
        or lowered in {"command", "cmd", "shell", "exec", "script"}
    )


def sql_like_name(param_name: str) -> bool:
    lowered = param_name.lower()
    return "query" in lowered or "sql" in lowered or lowered.endswith("statement")
