"""Unit tests: UnicodeAnalyzer (hidden Unicode / bidi / homoglyph detection)."""

from backend.scanners.mcp_ingest import normalize_target
from backend.scanners.static.unicode_analyzer import UnicodeAnalyzer, scan_text


def _tools(*tools):
    return normalize_target({"tools": list(tools)})


def test_detects_zero_width_space_in_description():
    target = _tools({"name": "t", "description": "hello\u200bworld", "inputSchema": {"type": "object"}})
    findings = UnicodeAnalyzer().analyze(target)
    assert any(f.rule_id == "UNICODE-001" and f.status == "confirmed" for f in findings)
    f = next(f for f in findings if f.rule_id == "UNICODE-001")
    ev = f.evidence[0].detail
    assert ev["codepoint"] == "U+200B"
    assert ev["escaped"] == "\\u200b"
    assert ev["original"] == "\u200b"  # original data preserved, not rewritten
    assert "position" in ev and "context_escaped" in ev


def test_detects_bidi_override_as_high_severity():
    target = _tools({"name": "t", "description": "abc\u202edef", "inputSchema": {}})
    findings = UnicodeAnalyzer().analyze(target)
    f = next(f for f in findings if f.rule_id == "UNICODE-002")
    assert f.severity == "high"
    assert f.status == "confirmed"
    assert f.evidence[0].detail["codepoint"] == "U+202E"


def test_clean_text_produces_no_findings():
    target = _tools({"name": "clean_tool", "description": "Completely normal description.", "inputSchema": {}})
    assert UnicodeAnalyzer().analyze(target) == []


def test_homoglyph_flagged_as_suspected_not_confirmed():
    # Cyrillic 'а' (U+0430) inside otherwise-ASCII name
    target = _tools({"name": "re\u0430d_file", "description": "Reads files", "inputSchema": {}})
    findings = UnicodeAnalyzer().analyze(target)
    homoglyphs = [f for f in findings if f.rule_id == "UNICODE-003"]
    assert homoglyphs, "homoglyph not detected"
    assert all(f.status == "suspected" for f in homoglyphs)
    assert homoglyphs[0].evidence[0].detail["ascii_equivalent"] == "a"


def test_scan_text_reports_position_and_category():
    hits = scan_text("a\u200bb", "description", "tool description")
    assert len(hits) == 1
    h = hits[0]
    assert h.position == 1
    assert h.category == "Cf"  # format category
    assert h.klass == "invisible"


def test_all_invisible_chars_documented_are_detected():
    text = "".join("\u200b\u200c\u200d\u2060\ufeff\u00ad")
    hits = scan_text(text, "description", "tool description")
    assert len(hits) == 6
