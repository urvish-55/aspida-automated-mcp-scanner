"""Builds the canonical scan report structure shared by JSON export and PDF.

The report must NEVER overstate: coverage gaps, skipped tests, unavailable
analyzers and empty results are all reported as such, and the mandatory
limitations language is always included.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from backend.core.version import (
    APP_VERSION,
    RULESET_VERSION,
    SCANNER_NAME,
    SCANNER_SCHEMA_VERSION,
)

MANDATORY_DISCLAIMER = "A scan cannot prove the absence of all vulnerabilities."
NO_FINDINGS_LANGUAGE = "No vulnerabilities were detected by the enabled tests."


def build_report(
    *,
    scan: dict[str, Any],
    tools: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    tests: list[dict[str, Any]],
    events: list[dict[str, Any]],
    risk_breakdown: dict[str, Any],
    analyzer_statuses: list[dict[str, Any]],
    semantic_result: dict[str, Any],
    ml_result: dict[str, Any],
    target_fingerprint: str,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc).isoformat()

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    status_counts = {"confirmed": 0, "suspected": 0, "informational": 0, "not_tested": 0, "not_applicable": 0, "error": 0}
    for f in findings:
        severity_counts[f.get("severity", "info")] = severity_counts.get(f.get("severity", "info"), 0) + 1
        status_counts[f.get("status", "suspected")] = status_counts.get(f.get("status", "suspected"), 0) + 1

    tests_executed = sum(1 for t in tests if t.get("status") in ("passed", "failed"))
    tests_skipped = sum(1 for t in tests if t.get("status") == "skipped")
    tests_errored = sum(1 for t in tests if t.get("status") == "error")

    limitations: list[str] = [
        MANDATORY_DISCLAIMER,
        "Static analysis inspects metadata only; it cannot observe server-side behavior.",
        "Capability findings describe attack surface, not proven exploitability.",
        "Dynamic probes used inert payloads and may exercise only a fraction of each tool's input space.",
        "Capability inference is heuristic and can mislabel tools (false positives and false negatives).",
        "Findings merge deduplication maps rule families to topics conservatively; distinct issues are never merged.",
        "The risk score is a prioritization aid, not a measure of real-world exploitability.",
    ]
    if analyzer_error := [a for a in analyzer_statuses if a.get("status") == "error"]:
        limitations.append(
            "Partial coverage: " + ", ".join(a["analyzer"] for a in analyzer_error) + " did not complete in this scan."
        )
    if semantic_result.get("status") != "completed":
        limitations.append(
            f"Semantic analysis {semantic_result.get('status', 'not run')}"
            + (f": {semantic_result.get('reason')}" if semantic_result.get("reason") else "")
        )
    if not findings:
        limitations.insert(0, NO_FINDINGS_LANGUAGE)

    return {
        "report_meta": {
            "scanner_name": SCANNER_NAME,
            "scanner_version": APP_VERSION,
            "ruleset_version": RULESET_VERSION,
            "scanner_schema_version": SCANNER_SCHEMA_VERSION,
            "generated_at": generated_at,
            "format_versions": {"risk_formula": risk_breakdown.get("formula_version", "unknown")},
        },
        "scan": {
            "id": scan.get("id"),
            "status": scan.get("status"),
            "target_type": scan.get("target_type"),
            "target_identifier": scan.get("target_identifier"),
            "target_label": scan.get("target_label"),
            "target_fingerprint": target_fingerprint,
            "created_at": scan.get("created_at"),
            "started_at": scan.get("started_at"),
            "completed_at": scan.get("completed_at"),
            "duration_seconds": _duration(scan),
        },
        "configuration": {
            "safe_mode": scan.get("safe_mode"),
            "dynamic_enabled": scan.get("dynamic_enabled"),
            "semantic_enabled": scan.get("semantic_enabled"),
            "authorization_confirmed": scan.get("authorization_confirmed"),
            "config_snapshot": scan.get("config_snapshot") or {},
        },
        "risk": {
            "score": (scan.get("risk_score") if scan.get("risk_score") is not None else risk_breakdown.get("total")),
            "band": risk_breakdown.get("band"),
            "breakdown": risk_breakdown,
        },
        "severity_breakdown": severity_counts,
        "status_breakdown": status_counts,
        "tool_inventory": [
            {
                "name": t.get("name"),
                "description": (t.get("description") or "")[:500],
                "capabilities": t.get("capabilities") or [],
                "has_schema": bool(t.get("input_schema")),
            }
            for t in tools
        ],
        "findings": findings,
        "dynamic_tests": {
            "summary": {
                "executed": tests_executed,
                "skipped": tests_skipped,
                "errored": tests_errored,
                "total": len(tests),
            },
            "tests": tests,
        },
        "static_analysis": {"analyzer_statuses": analyzer_statuses},
        "semantic_analysis": semantic_result,
        "ml_analysis": ml_result,
        "recommendations": _recommendations(findings),
        "limitations": limitations,
        "events": [
            {k: e.get(k) for k in ("seq", "timestamp", "stage", "event", "message", "level", "progress")}
            for e in events
        ],
    }


def _duration(scan: dict[str, Any]) -> float | None:
    try:
        from datetime import datetime as dt

        started = scan.get("started_at")
        completed = scan.get("completed_at")
        if isinstance(started, str) and isinstance(completed, str):
            s = dt.fromisoformat(started.replace("Z", "+00:00"))
            c = dt.fromisoformat(completed.replace("Z", "+00:00"))
            return round((c - s).total_seconds(), 3)
        if isinstance(started, dt) and isinstance(completed, dt):
            return round((completed - started).total_seconds(), 3)
    except (ValueError, TypeError):
        return None
    return None


def _recommendations(findings: list[dict[str, Any]]) -> list[str]:
    """Deduplicated, prioritized remediation steps derived from actual findings."""
    seen: set[str] = set()
    recs: list[str] = []
    for f in findings:
        for r in [f.get("remediation", "")] if isinstance(f.get("remediation"), str) else []:
            r = r.strip()
            if r and r not in seen:
                seen.add(r)
                recs.append(r)
    return recs
