"""Deterministic, transparent risk scoring.

FORMULA (version RISK-1, shown in the report):

  Section A  Static findings (post-dedup), per finding:
             critical 20 / high 12 / medium 6 / low 2 / info 0
             -> subtotal A capped at 40
  Section B  Dynamic CONFIRMED findings, per finding:
             critical 30 / high 20 / medium 10 / low 4
             -> subtotal B capped at 35
  Section C  Capability exposure: strongest dangerous capability combination
             (critical 15 / high 10 / medium 5) + 2 per additional combination
             (max +5) -> subtotal C capped at 20
  Section D  Evidence-confidence adjustment for non-informational findings:
             average confidence weight (high 1.0 / medium 0.7 / low 0.4),
             adjustment = round(5 * (avg - 0.7)) -> range -2 .. +2

  TOTAL = clamp(A + B + C + D, 0, 100)

Bands: 0-24 low, 25-49 moderate, 50-74 high, 75-100 critical.

Every intermediate value is stored in risk_breakdown and rendered in the
report, so the score is never an unexplained number. Findings with status
error/not_tested contribute 0 (they are coverage gaps, not risk evidence).
"""

from __future__ import annotations

from typing import Any

from backend.scanners.static.base import SEVERITY_RANK

RISK_FORMULA_VERSION = "RISK-1"

STATIC_POINTS = {"critical": 20, "high": 12, "medium": 6, "low": 2, "info": 0}
DYNAMIC_POINTS = {"critical": 30, "high": 20, "medium": 10, "low": 4, "info": 0}
COMBO_POINTS = {"critical": 15, "high": 10, "medium": 5, "low": 2, "info": 0}
CONFIDENCE_WEIGHT = {"high": 1.0, "medium": 0.7, "low": 0.4}

CAPS = {"static": 40, "dynamic": 35, "capability": 20}
CONFIDENCE_NEUTRAL = 0.7
CONFIDENCE_SCALE = 5

BANDS = [(75, "critical"), (50, "high"), (25, "moderate"), (0, "low")]


def band_for(score: float) -> str:
    for threshold, name in BANDS:
        if score >= threshold:
            return name
    return "low"


def compute_risk(findings: list[dict[str, Any]], safety_summary: dict[str, Any] | None = None) -> dict[str, Any]:
    static_pts = 0
    dynamic_pts = 0
    capability_pts = 0

    static_count = 0
    dynamic_count = 0
    scored_severities: list[tuple[str, str]] = []  # (severity, confidence)

    combo_severities: list[str] = []

    for f in findings:
        severity = f.get("severity", "info")
        status = f.get("status", "suspected")
        confidence = f.get("confidence", "medium")
        rule_id = str(f.get("rule_id", ""))
        sources = f.get("detector_sources") or [rule_id]
        has_dynamic = any(str(s).startswith("DYN-") for s in sources)

        if f.get("category") == "engine" or status in ("error", "not_tested", "not_applicable"):
            continue  # coverage gaps and errors are not risk evidence

        if f.get("rule_id") == "CAP-010" or (f.get("category") == "capability" and status == "suspected"):
            combo_severities.append(severity)
            continue

        if status == "informational":
            continue

        if has_dynamic and status == "confirmed":
            dynamic_pts += DYNAMIC_POINTS.get(severity, 0)
            dynamic_count += 1
            scored_severities.append((severity, confidence))
        else:
            static_pts += STATIC_POINTS.get(severity, 0)
            static_count += 1
            scored_severities.append((severity, confidence))

    static_subtotal = min(static_pts, CAPS["static"])
    dynamic_subtotal = min(dynamic_pts, CAPS["dynamic"])

    if combo_severities:
        strongest = max(combo_severities, key=lambda s: SEVERITY_RANK.get(s, 0))
        capability_pts = COMBO_POINTS.get(strongest, 0) + min(2 * (len(combo_severities) - 1), 5)
    capability_subtotal = min(capability_pts, CAPS["capability"])

    non_info = [(s, c) for (s, c) in scored_severities if s != "info"]
    if non_info:
        avg_conf = sum(CONFIDENCE_WEIGHT.get(c, 0.7) for _, c in non_info) / len(non_info)
        # Threshold table (deterministic, no floating-point edge cases):
        #   avg weight >= 0.90 -> +2   (predominantly high-confidence evidence)
        #   avg >= 0.75        -> +1
        #   avg >  0.65        ->  0   (neutral zone around the 0.7 midpoint)
        #   avg >  0.50        -> -1
        #   otherwise          -> -2   (predominantly low-confidence evidence)
        if avg_conf >= 0.90:
            adjustment = 2
        elif avg_conf >= 0.75:
            adjustment = 1
        elif avg_conf > 0.65:
            adjustment = 0
        elif avg_conf > 0.50:
            adjustment = -1
        else:
            adjustment = -2
    else:
        avg_conf = 0.0
        adjustment = 0

    total = max(0, min(100, static_subtotal + dynamic_subtotal + capability_subtotal + adjustment))

    breakdown: dict[str, Any] = {
        "formula_version": RISK_FORMULA_VERSION,
        "formula": (
            "TOTAL = clamp(static_subtotal + dynamic_subtotal + capability_subtotal + "
            "confidence_adjustment, 0, 100); see backend/risk/engine.py for per-finding points"
        ),
        "static": {
            "points_per_finding": STATIC_POINTS,
            "findings_scored": static_count,
            "raw_points": static_pts,
            "cap": CAPS["static"],
            "subtotal": static_subtotal,
        },
        "dynamic": {
            "points_per_finding": DYNAMIC_POINTS,
            "findings_scored": dynamic_count,
            "raw_points": dynamic_pts,
            "cap": CAPS["dynamic"],
            "subtotal": dynamic_subtotal,
        },
        "capability": {
            "dangerous_combinations_seen": len(combo_severities),
            "strongest_severity": max(combo_severities, key=lambda s: SEVERITY_RANK.get(s, 0)) if combo_severities else None,
            "raw_points": capability_pts,
            "cap": CAPS["capability"],
            "subtotal": capability_subtotal,
        },
        "confidence_adjustment": {
            "average_confidence_weight": round(avg_conf, 3) if non_info else None,
            "adjustment_points": adjustment,
            "rule": "threshold table: >=0.90->+2, >=0.75->+1, >0.65->0, >0.50->-1, else -2 (weights: high 1.0, medium 0.7, low 0.4)",
        },
        "total_before_clamp": static_subtotal + dynamic_subtotal + capability_subtotal + adjustment,
        "total": total,
        "band": band_for(total),
    }
    if safety_summary:
        breakdown["dynamic_context"] = {
            "requests_sent": safety_summary.get("requests_sent"),
            "note": "Low request counts reduce dynamic coverage; a low score is NOT proof of safety.",
        }
    return breakdown
