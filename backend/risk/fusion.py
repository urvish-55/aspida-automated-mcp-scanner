"""Evidence fusion & finding deduplication.

Multiple detectors observing the SAME underlying issue on the same tools are
merged into one finding carrying all evidence sources. This prevents risk
inflation purely because three analyzers noticed one problem.

Merging policy (documented for the report):
- Two findings merge iff they map to the same issue TOPIC and the same set of
  affected tools. Topics are a conservative mapping (e.g. static SCHEMA-010
  "path-like parameter" and a dynamic path-traversal probe finding on the same
  tool both map to topic path_traversal).
- Merged severity = max severity; merged status upgrades to confirmed only if
  any source dynamically confirmed it; confidence = max confidence.
- detector_sources lists contributing rule_ids; nothing is discarded.
- Engine/internal findings (category "engine") are never merged.
"""

from __future__ import annotations

from typing import Any

from backend.scanners.static.base import SEVERITY_RANK

# rule_id prefix -> issue topic (conservative; distinct issues stay distinct)
_RULE_TOPIC: dict[str, str] = {
    "UNICODE-001": "hidden_unicode",
    "UNICODE-002": "hidden_unicode",
    "UNICODE-003": "unicode_homoglyph",
    "POISON-001": "prompt_injection",
    "POISON-002": "prompt_injection",
    "POISON-003": "prompt_injection",
    "POISON-004": "prompt_injection",
    "POISON-005": "prompt_injection",
    "POISON-006": "prompt_injection",
    "NAME-001": "suspicious_naming",
    "SCHEMA-000": "input_validation",
    "SCHEMA-001": "input_validation",
    "SCHEMA-010": "path_traversal",
    "SCHEMA-011": "command_injection",
    "SCHEMA-012": "ssrf_surface",
    "SCHEMA-013": "sql_injection",
    "CAP-001": "capability_profile",
    "CAP-010": "capability_combination",
    "CAP-020": "capability_profile",
    "CAP-021": "capability_profile",
    "COLLISION-001": "collision",
    "COLLISION-002": "collision",
    "COLLISION-003": "collision",
    "COLLISION-004": "collision",
    "DYN-PATH-001": "path_traversal",
    "DYN-CMDI-001": "command_injection",
    "DYN-OVER-001": "input_validation",
    "DYN-MALF-001": "input_validation",
    "DYN-VIOL-001": "input_validation",
}


def topic_of(rule_id: str) -> str:
    return _RULE_TOPIC.get(rule_id, f"unmapped:{rule_id}")


def _is_dynamic(rule_id: str) -> bool:
    return rule_id.startswith("DYN-")


def fuse_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge dict-shaped findings (StaticFinding.to_dict() / dynamic dicts)."""
    merged: dict[tuple[str, tuple[str, ...]], dict[str, Any]] = {}
    passthrough: list[dict[str, Any]] = []

    for f in findings:
        rule_id = str(f.get("rule_id", ""))
        tools_key = tuple(sorted(set(f.get("affected_tools") or [])))
        if f.get("category") == "engine" or not tools_key and rule_id.startswith("ENGINE"):
            passthrough.append(f)
            continue
        key = (topic_of(rule_id), tools_key)
        if key not in merged:
            merged[key] = _deep_copy(f)
            continue
        merged[key] = _merge_two(merged[key], f)

    out = passthrough + list(merged.values())
    # deterministic order: highest severity first, then rule_id, then title
    out.sort(key=lambda f: (-SEVERITY_RANK.get(f.get("severity", "info"), 0), str(f.get("rule_id")), str(f.get("title"))))
    return out


def _deep_copy(f: dict[str, Any]) -> dict[str, Any]:
    g = dict(f)
    g["evidence"] = list(f.get("evidence") or [])
    g["affected_tools"] = sorted(set(f.get("affected_tools") or []))
    g["detector_sources"] = [rule_id for rule_id in [f.get("rule_id")] if rule_id]
    return g


def _merge_two(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    sev_a, sev_b = a.get("severity", "info"), b.get("severity", "info")
    winner = a if SEVERITY_RANK.get(sev_a, 0) >= SEVERITY_RANK.get(sev_b, 0) else b

    merged = dict(winner)
    merged["severity"] = sev_a if SEVERITY_RANK.get(sev_a, 0) >= SEVERITY_RANK.get(sev_b, 0) else sev_b

    # status: dynamic confirmation wins; otherwise keep the stronger of the two
    status_order = {"confirmed": 4, "suspected": 3, "informational": 2, "not_tested": 1, "not_applicable": 1, "error": 1}
    statuses = [a.get("status", "suspected"), b.get("status", "suspected")]
    merged["status"] = max(statuses, key=lambda s: status_order.get(s, 0))

    conf_order = {"high": 3, "medium": 2, "low": 1}
    merged["confidence"] = max(
        (a.get("confidence", "medium"), b.get("confidence", "medium")), key=lambda c: conf_order.get(c, 0)
    )

    merged["evidence"] = list(a.get("evidence") or []) + list(b.get("evidence") or [])
    merged["affected_tools"] = sorted(set(a.get("affected_tools") or []) | set(b.get("affected_tools") or []))
    merged["detector_sources"] = sorted(
        set((a.get("detector_sources") or []) + (b.get("detector_sources") or []))
    )
    merged["references"] = sorted(set((a.get("references") or []) + (b.get("references") or [])))

    sources_text = ", ".join(merged["detector_sources"])
    merged["fusion_note"] = (
        f"Merged finding: {sources_text} independently observed the same underlying issue "
        f"('{topic_of(str(merged.get('rule_id')))}') on the same tool(s)."
    )
    # keep reproduction from the most actionable (dynamic) source when present
    if _is_dynamic(str(b.get("rule_id", ""))) and not _is_dynamic(str(a.get("rule_id", ""))):
        merged["reproduction"] = b.get("reproduction") or merged.get("reproduction", {})
    return merged
