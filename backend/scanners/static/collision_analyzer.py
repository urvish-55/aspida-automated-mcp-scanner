"""Tool-name collision / shadowing analysis.

Detects exact duplicates, case-insensitive collisions, normalized-name
collisions, and near-duplicate names (Levenshtein ratio), plus suspiciously
similar descriptions between differently-named tools.

Classification is honest:
- exact duplicate  -> confirmed collision
- case/normalized  -> confirmed collision (they normalize to the same key)
- near-duplicate   -> potential collision (suspected)
- similar names only -> informational similarity (not necessarily malicious:
  'get_user' vs 'get_users' is normal)
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from backend.scanners.mcp_ingest import NormalizedTarget
from backend.scanners.static.base import Evidence, StaticAnalyzer, StaticFinding


def _normalize(name: str) -> str:
    lowered = name.lower()
    stripped = re.sub(r"[^a-z0-9]", "", lowered)
    return stripped


@dataclass
class Collision:
    kind: str  # exact | case_insensitive | normalized | near_duplicate
    a: str
    b: str
    ratio: float = 1.0
    why: str = ""


def find_collisions(names: list[str]) -> list[Collision]:
    collisions: list[Collision] = []
    seen: dict[str, str] = {}
    normalized_seen: dict[str, str] = {}

    for name in names:
        if name in seen:
            collisions.append(
                Collision(
                    "exact", seen[name], name, 1.0,
                    "Two tools expose the identical name; agent tool selection becomes ambiguous.",
                )
            )
        else:
            seen[name] = name
        key = name.lower()
        if key in normalized_seen and normalized_seen[key] != name:
            collisions.append(
                Collision(
                    "case_insensitive", normalized_seen[key], name, 0.999,
                    "Names differ only by case; on case-insensitive lookups (and to an LLM) they are near-identical.",
                )
            )
        else:
            normalized_seen[key] = name

    names_sorted = sorted(set(names))
    for i, a in enumerate(names_sorted):
        for b in names_sorted[i + 1:]:
            if a.lower() == b.lower():
                continue
            ratio = difflib.SequenceMatcher(None, _normalize(a), _normalize(b)).ratio()
            if ratio >= 0.9:
                collisions.append(
                    Collision(
                        "near_duplicate", a, b, ratio,
                        "Names collapse to nearly the same string; one can be mistaken for (or "
                        "deliberately shadow) the other in agent tool selection.",
                    )
                )
    return collisions


def _desc_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a.lower(), b.lower()).ratio()


class CollisionAnalyzer(StaticAnalyzer):
    rule_id_prefix = "COLLISION"

    def analyze(self, target: NormalizedTarget) -> list[StaticFinding]:
        findings: list[StaticFinding] = []
        names = [t.name for t in target.tools]
        collisions = find_collisions(names)

        for c in collisions:
            if c.kind == "exact":
                rule_id, severity, status, conf = "COLLISION-001", "high", "confirmed", "high"
            elif c.kind == "case_insensitive":
                rule_id, severity, status, conf = "COLLISION-002", "medium", "confirmed", "high"
            elif c.kind == "normalized":
                rule_id, severity, status, conf = "COLLISION-002", "medium", "confirmed", "high"
            else:  # near_duplicate
                rule_id, severity, status, conf = "COLLISION-003", "medium", "suspected", "medium"

            title = (
                f"Duplicate tool name: '{c.a}' / '{c.b}'"
                if c.kind == "exact"
                else f"Tool name collision ({c.kind}): '{c.a}' vs '{c.b}'"
            )
            findings.append(
                StaticFinding(
                    rule_id=rule_id,
                    category="collision",
                    severity=severity,  # type: ignore[arg-type]
                    title=title,
                    description=(
                        f"{c.why} Similarity ratio: {c.ratio:.2f}."
                        if c.kind == "near_duplicate"
                        else c.why
                    ),
                    status=status,  # type: ignore[arg-type]
                    confidence=conf,  # type: ignore[arg-type]
                    evidence=[
                        Evidence(
                            kind="collision",
                            summary=f"'{c.a}' vs '{c.b}' ({c.kind}, ratio {c.ratio:.3f})",
                            detail={
                                "collision_kind": c.kind,
                                "tool_a": c.a,
                                "tool_b": c.b,
                                "similarity_ratio": round(c.ratio, 4),
                                "why": c.why,
                            },
                        )
                    ],
                    affected_tools=[c.a, c.b],
                    impact=(
                        "Ambiguous tool identity breaks the assumption that one name maps to one "
                        "behavior. A malicious tool can shadow a trusted one and inherit its calls."
                    ),
                    remediation=(
                        "Ensure tool names are unique per server (and per client registry). If "
                        "shadowing is suspected, compare descriptions/schemas and disable the "
                        "unverified tool."
                    ),
                    reproduction={
                        "type": "static",
                        "steps": ["List tool names", f"Compare '{c.a}' and '{c.b}' case-insensitively"],
                    },
                    references=["OWASP Agentic AI - Tool Shadowing / Name Collision"],
                )
            )

        # suspiciously similar descriptions between different tools (potential shadowing)
        tools = [t for t in target.tools if t.description]
        reported_pairs: set[tuple[str, str]] = set()
        for i, ta in enumerate(tools):
            for tb in tools[i + 1:]:
                if ta.name == tb.name:
                    continue
                if (ta.name, tb.name) in reported_pairs or _desc_similarity(ta.description, tb.description) < 0.85:
                    continue
                reported_pairs.add((ta.name, tb.name))
                findings.append(
                    StaticFinding(
                        rule_id="COLLISION-004",
                        category="collision",
                        severity="low",
                        title=f"Near-identical descriptions for '{ta.name}' and '{tb.name}'",
                        description=(
                            "Two differently-named tools share almost the same description text. "
                            "This can be legitimate (wrapper tools) or a shadowing attempt where "
                            "one tool is designed to be chosen instead of the other."
                        ),
                        status="suspected",
                        confidence="low",
                        evidence=[
                            Evidence(
                                kind="description_similarity",
                                summary=f"descriptions of '{ta.name}' and '{tb.name}' are highly similar",
                                detail={
                                    "tool_a": ta.name,
                                    "tool_b": tb.name,
                                    "description_similarity": round(_desc_similarity(ta.description, tb.description), 4),
                                    "description_a_excerpt": ta.description[:200],
                                    "description_b_excerpt": tb.description[:200],
                                },
                            )
                        ],
                        affected_tools=[ta.name, tb.name],
                        impact="Descriptions are a major input to agent tool choice; identical text can funnel calls to the wrong tool.",
                        remediation="Confirm both tools are expected; diff their behaviors; keep one authoritative description per capability.",
                        references=["OWASP Agentic AI - Tool Shadowing"],
                    )
                )
        return findings
