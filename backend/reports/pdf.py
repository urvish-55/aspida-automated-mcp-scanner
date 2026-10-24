"""PDF report generation (ReportLab, free/open-source).

Renders the canonical report structure into the 14-section professional layout.
All dynamic text is XML-escaped (ReportLab paragraphs parse mini-HTML). PDF
failure raises PdfReportError; the API layer catches it and reports HTTP 500
with a clear message — a report bug must never corrupt a stored scan.
"""

from __future__ import annotations

import html
import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class PdfReportError(Exception):
    pass


SEVERITY_COLORS = {
    "critical": colors.HexColor("#7f1d1d"),
    "high": colors.HexColor("#c2410c"),
    "medium": colors.HexColor("#b45309"),
    "low": colors.HexColor("#1d4ed8"),
    "info": colors.HexColor("#475569"),
}

SEVERITY_HEX = {"critical": "#7f1d1d", "high": "#c2410c", "medium": "#b45309", "low": "#1d4ed8", "info": "#475569"}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def generate_pdf(report: dict[str, Any]) -> bytes:
    try:
        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            title=f"MCP Pentest Report {report['scan']['id']}",
            author=report["report_meta"]["scanner_name"],
        )
        styles = getSampleStyleSheet()
        h1 = ParagraphStyle("H1", parent=styles["Heading1"], fontSize=16, spaceAfter=6)
        h2 = ParagraphStyle("H2", parent=styles["Heading2"], fontSize=13, spaceBefore=10, spaceAfter=4)
        body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9, leading=12)
        small = ParagraphStyle("Small", parent=body, fontSize=8, textColor=colors.HexColor("#334155"))
        mono = ParagraphStyle("Mono", parent=body, fontName="Courier", fontSize=7.5, leading=9.5)

        story: list = []

        # ---- 1. Executive summary -------------------------------------
        meta = report["report_meta"]
        scan = report["scan"]
        risk = report["risk"]
        story.append(Paragraph(_esc(meta["scanner_name"]), ParagraphStyle("T", parent=h1, alignment=TA_CENTER, fontSize=20)))
        story.append(Paragraph(
            f"Security Assessment Report — Scan {_esc(scan['id'])}",
            ParagraphStyle("ST", parent=body, alignment=TA_CENTER, fontSize=11, spaceAfter=14),
        ))
        story.append(Paragraph("1. Executive Summary", h1))
        total = risk.get("score", 0)
        band = risk.get("band", "unknown")
        sev = report["severity_breakdown"]
        summary_text = (
            f"The scan of target <b>{_esc(scan.get('target_identifier') or scan.get('target_label') or 'unnamed target')}</b> "
            f"completed with status <b>{_esc(scan.get('status'))}</b> on "
            f"{_esc(str(scan.get('completed_at') or 'n/a'))}. "
            f"The aggregated risk score is <b>{total}/100 ({_esc(band)} band)</b>. "
            f"Findings: {_esc(sev.get('critical', 0))} critical, {_esc(sev.get('high', 0))} high, "
            f"{_esc(sev.get('medium', 0))} medium, {_esc(sev.get('low', 0))} low, {_esc(sev.get('info', 0))} informational."
        )
        if not any(sev.values()):
            summary_text += " " + _esc("No vulnerabilities were detected by the enabled tests. This is not a guarantee of security.")
        story.append(Paragraph(summary_text, body))
        story.append(Spacer(1, 4))
        story.append(Paragraph(
            "<b>" + _esc("A scan cannot prove the absence of all vulnerabilities.") + "</b> "
            "This report states what was tested, what was found, and what could not be tested.",
            body,
        ))

        # ---- 2. Target information ------------------------------------
        story.append(Paragraph("2. Target Information", h2))
        story.append(_kv_table([
            ("Target identifier", scan.get("target_identifier") or "(static config scan)"),
            ("Target label", scan.get("target_label")),
            ("Target type", scan.get("target_type")),
            ("Fingerprint", scan.get("target_fingerprint")),
            ("Scan ID", scan.get("id")),
        ], body))
        story.append(Paragraph("3. Scan Configuration", h2))
        cfg = report["configuration"]
        story.append(_kv_table([
            ("Safe mode", cfg.get("safe_mode")),
            ("Dynamic testing", "enabled" if cfg.get("dynamic_enabled") else "disabled"),
            ("Semantic analysis", "enabled" if cfg.get("semantic_enabled") else "disabled"),
            ("Authorization confirmed", cfg.get("authorization_confirmed")),
            ("Scanner version", meta["scanner_version"]),
            ("Ruleset version", meta["ruleset_version"]),
            ("Generated at", meta["generated_at"]),
        ], body))

        # ---- 4. Risk score ---------------------------------------------
        story.append(Paragraph("4. Risk Score", h2))
        b = risk.get("breakdown", {})
        story.append(_kv_table([
            ("Total score", f"{total}/100 ({band})"),
            ("Static findings subtotal", f"{b.get('static', {}).get('subtotal', 0)} (cap {b.get('static', {}).get('cap')})"),
            ("Dynamic findings subtotal", f"{b.get('dynamic', {}).get('subtotal', 0)} (cap {b.get('dynamic', {}).get('cap')})"),
            ("Capability exposure subtotal", f"{b.get('capability', {}).get('subtotal', 0)} (cap {b.get('capability', {}).get('cap')})"),
            ("Confidence adjustment", f"{b.get('confidence_adjustment', {}).get('adjustment_points', 0)} points"),
            ("Formula", b.get("formula_version", "unknown") + " — documented in backend/risk/engine.py"),
        ], body))

        # ---- 5. Severity breakdown table --------------------------------
        story.append(Paragraph("5. Severity Breakdown", h2))
        rows = [[Paragraph(f"<b>{s.capitalize()}</b>", body), str(sev.get(s, 0))] for s in ("critical", "high", "medium", "low", "info")]
        story.append(_table([["Severity", "Count"], *rows]))

        # ---- 6. Tool inventory -------------------------------------------
        story.append(Paragraph("6. Tool Inventory", h2))
        inv = report.get("tool_inventory", [])
        if not inv:
            story.append(Paragraph("No tools were part of this scan.", body))
        else:
            rows = [["Tool", "Inferred capabilities", "Schema?"]]
            for t in inv[:80]:
                rows.append([
                    Paragraph(_esc(t.get("name")), mono),
                    Paragraph(_esc(", ".join(t.get("capabilities") or []) or "(none inferred)"), small),
                    "yes" if t.get("has_schema") else "NO",
                ])
            story.append(_table(rows))

        # ---- 7 & 8. Findings + evidence ----------------------------------
        story.append(PageBreak())
        story.append(Paragraph("7. Findings", h1))
        findings = report.get("findings", [])
        if not findings:
            story.append(Paragraph(_esc("No vulnerabilities were detected by the enabled tests."), body))
        for i, f in enumerate(findings[:60], 1):
            sev = f.get("severity", "info")
            block = [
                Paragraph(
                    f"{i}. {_esc(f.get('title'))} "
                    f"[<font color='{SEVERITY_HEX.get(sev, SEVERITY_HEX['info'])}'>{sev.upper()}</font>"
                    f", status: {_esc(f.get('status'))}, confidence: {_esc(f.get('confidence'))}]",
                    h2,
                ),
                Paragraph(_esc(f.get("description")), body),
                Paragraph(f"<b>Affected tools:</b> {_esc(', '.join(f.get('affected_tools') or ['(none)']))}", small),
                Paragraph(f"<b>Why it matters:</b> {_esc(f.get('impact'))}", body),
                Paragraph(f"<b>How to fix:</b> {_esc(f.get('remediation'))}", body),
                Paragraph(f"<b>Detectors:</b> {_esc(', '.join(f.get('detector_sources') or [f.get('rule_id')]))}", small),
                Paragraph("Evidence:", ParagraphStyle("el", parent=body, spaceBefore=3)),
            ]
            for e in (f.get("evidence") or [])[:8]:
                block.append(Paragraph(f"• {_esc(e.get('summary', ''))}", mono))
                detail = e.get("detail") or {}
                if detail:
                    import json as _json

                    block.append(Paragraph(_esc(_json.dumps(detail, ensure_ascii=False, default=str)[:600]), small))
            if f.get("fusion_note"):
                block.append(Paragraph(f"<i>{_esc(f['fusion_note'])}</i>", small))
            story.append(KeepTogether(block[:6]))
            story.extend(block[6:])
            story.append(Spacer(1, 6))

        # ---- 9. Dynamic test results --------------------------------------
        story.append(PageBreak())
        story.append(Paragraph("9. Dynamic Test Results", h1))
        dt = report.get("dynamic_tests", {})
        s = dt.get("summary", {})
        story.append(Paragraph(
            f"Executed: {s.get('executed', 0)} — Skipped: {s.get('skipped', 0)} — Errored: {s.get('errored', 0)} — "
            f"Total: {s.get('total', 0)}. Skipped and errored tests are coverage gaps, not passes.",
            body,
        ))
        tests = dt.get("tests", [])
        if tests:
            rows = [["Test", "Tool", "Status", "Detail"]]
            for t in tests[:100]:
                rows.append([
                    Paragraph(_esc(t.get("test_name")), small),
                    Paragraph(_esc(t.get("tool_name") or "-"), small),
                    t.get("status", "?"),
                    Paragraph(_esc((t.get("detail") or "")[:200]), small),
                ])
            story.append(_table(rows))

        # ---- 10. Semantic analysis ----------------------------------------
        story.append(Paragraph("10. Semantic Analysis", h2))
        sem = report.get("semantic_analysis", {})
        story.append(Paragraph(
            f"Status: <b>{_esc(sem.get('status', 'not run'))}</b>"
            + (f" — provider: {_esc(sem.get('provider'))}" if sem.get("provider") else "")
            + (f" — {_esc(sem.get('reason'))}" if sem.get("reason") else ""),
            body,
        ))

        # ---- 11. ML analysis -----------------------------------------------
        story.append(Paragraph("11. ML Analysis", h2))
        ml = report.get("ml_analysis", {})
        story.append(Paragraph(
            f"Status: <b>{_esc(ml.get('status', 'not available'))}</b> — {_esc(ml.get('note', ''))}",
            body,
        ))
        for ft in (ml.get("flagged_tools") or [])[:10]:
            story.append(Paragraph(f"• {_esc(str(ft.get('tool', '')))} — score {_esc(str(ft.get('score', '')))} ({_esc(str(ft.get('level', '')))})", body))

        # ---- 12. Recommendations --------------------------------------------
        story.append(Paragraph("12. Recommendations", h1))
        recs = report.get("recommendations", [])
        if not recs:
            story.append(Paragraph("No remediation steps derived — no findings were reported.", body))
        for i, r in enumerate(recs[:20], 1):
            story.append(Paragraph(f"{i}. {_esc(r)}", body))

        # ---- 13. Limitations -------------------------------------------------
        story.append(Paragraph("13. Limitations", h1))
        for lim in report.get("limitations", []):
            story.append(Paragraph(f"• {_esc(lim)}", small))

        # ---- 14. Appendix -----------------------------------------------------
        story.append(Paragraph("14. Appendix", h1))
        story.append(Paragraph("Analyzer execution status:", body))
        for a in report.get("static_analysis", {}).get("analyzer_statuses", []):
            story.append(Paragraph(
                f"• {_esc(a.get('analyzer'))}: {_esc(a.get('status'))}"
                + (f" ({a.get('findings')} findings)" if a.get("status") == "executed" else "")
                + (f" — {_esc(a.get('error', ''))[:200]}" if a.get("error") else ""),
                mono,
            ))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            "This report was generated by an automated scanner. It reflects only the checks that "
            "ran, against the metadata provided, at the time of the scan. Re-scan after changes; "
            "do not treat any result as a permanent security certification.",
            small,
        ))

        doc.build(story)
        return buf.getvalue()
    except Exception as exc:  # noqa: BLE001 - surfaced as PdfReportError
        raise PdfReportError(f"PDF generation failed: {type(exc).__name__}: {exc}") from exc


def _kv_table(pairs: list[tuple[str, Any]], style) -> Table:
    data = [[Paragraph(f"<b>{_esc(k)}</b>", style), Paragraph(_esc(v), style)] for k, v in pairs]
    t = Table(data, colWidths=[55 * mm, 115 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    return t


def _table(rows: list[list], col_widths: list[float] | None = None) -> Table:
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
    ]))
    return t
