"""Unit tests: risk engine + evidence fusion (deduplication)."""

from backend.risk.engine import compute_risk, band_for
from backend.risk.fusion import fuse_findings, topic_of


def _f(**kw):
    base = {
        "rule_id": "X-001", "category": "test", "severity": "medium", "confidence": "medium",
        "status": "suspected", "title": "t", "description": "d", "evidence": [],
        "affected_tools": ["tool_a"], "reproduction": {}, "impact": "", "remediation": "",
        "references": [], "detector_sources": ["X-001"],
    }
    base.update(kw)
    return base


def test_empty_findings_score_zero():
    r = compute_risk([])
    assert r["total"] == 0 and r["band"] == "low"


def test_static_points_and_cap():
    findings = [_f(severity="critical") for _ in range(4)]  # 4*20 = 80 raw
    r = compute_risk(findings)
    assert r["static"]["raw_points"] == 80
    assert r["static"]["subtotal"] == 40  # capped
    assert r["total"] == 40


def test_dynamic_confirmation_scores_higher():
    static_only = compute_risk([_f(severity="high")])
    dyn = compute_risk([
        _f(rule_id="DYN-PATH-001", detector_sources=["DYN-PATH-001"], severity="high", status="confirmed")
    ])
    assert dyn["dynamic"]["subtotal"] == 20
    assert dyn["total"] > static_only["total"]


def test_error_and_not_tested_do_not_add_risk():
    findings = [_f(status="error"), _f(status="not_tested"), _f(status="not_applicable")]
    assert compute_risk(findings)["total"] == 0


def test_capability_combination_uses_capability_section():
    r = compute_risk([_f(rule_id="CAP-010", severity="critical", status="suspected")])
    assert r["capability"]["subtotal"] == 15
    assert r["static"]["subtotal"] == 0


def test_informational_ignored():
    assert compute_risk([_f(status="informational")])["total"] == 0


def test_confidence_adjustment_range():
    high = compute_risk([_f(confidence="high", severity="high")])
    low = compute_risk([_f(confidence="low", severity="high")])
    assert high["confidence_adjustment"]["adjustment_points"] == 2
    assert low["confidence_adjustment"]["adjustment_points"] == -2
    assert high["total"] == low["total"] + 4


def test_bands():
    assert band_for(0) == "low"
    assert band_for(24.9) == "low"
    assert band_for(25) == "moderate"
    assert band_for(50) == "high"
    assert band_for(75) == "critical"
    assert band_for(100) == "critical"


# ----------------------------- fusion -----------------------------

def test_same_topic_same_tools_merge():
    a = _f(rule_id="SCHEMA-010", detector_sources=["SCHEMA-010"], evidence=[{"kind": "schema_field", "summary": "s", "detail": {}}])
    b = _f(rule_id="DYN-PATH-001", detector_sources=["DYN-PATH-001"], status="confirmed", severity="critical",
           evidence=[{"kind": "dynamic_probe", "summary": "d", "detail": {}}],
           reproduction={"type": "dynamic", "arguments": {"path": "../../etc/passwd"}})
    fused = fuse_findings([a, b])
    assert len(fused) == 1
    f = fused[0]
    assert set(f["detector_sources"]) == {"SCHEMA-010", "DYN-PATH-001"}
    assert f["severity"] == "critical"
    assert f["status"] == "confirmed"  # dynamic confirmation upgrades
    assert f["reproduction"]["type"] == "dynamic"  # most actionable reproduction kept
    assert len(f["evidence"]) == 2


def test_different_tools_do_not_merge():
    a = _f(rule_id="SCHEMA-010", affected_tools=["tool_a"])
    b = _f(rule_id="SCHEMA-010", affected_tools=["tool_b"])
    assert len(fuse_findings([a, b])) == 2


def test_distinct_topics_do_not_merge():
    a = _f(rule_id="SCHEMA-010")
    b = _f(rule_id="SCHEMA-011")
    assert len(fuse_findings([a, b])) == 2


def test_engine_findings_never_merged():
    a = _f(rule_id="ENGINE-001", category="engine", affected_tools=[])
    b = _f(rule_id="ENGINE-001", category="engine", affected_tools=[])
    assert len(fuse_findings([a, b])) == 2


def test_topic_mapping_is_conservative():
    assert topic_of("SCHEMA-010") == "path_traversal"
    assert topic_of("DYN-PATH-001") == "path_traversal"
    assert topic_of("POISON-001") == "prompt_injection"
    assert topic_of("UNKNOWN-999").startswith("unmapped:")


def test_fusion_does_not_inflate_score():
    # one path-traversal issue seen by two detectors must score once
    a = _f(rule_id="SCHEMA-010", severity="medium", detector_sources=["SCHEMA-010"])
    b = _f(rule_id="DYN-PATH-001", severity="critical", status="confirmed", detector_sources=["DYN-PATH-001"])
    single = compute_risk([b])
    both = compute_risk(fuse_findings([a, b]))
    assert both["total"] == single["total"]
