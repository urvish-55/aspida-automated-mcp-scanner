"""Investigation-oriented endpoints that back the dashboard UI (spec #62).

Everything returned here is derived from stored scan data or live component checks.
Nothing is synthesized: when data does not exist the response says so (empty lists, ``available: false``).

    GET   /api/scans/{id}/analysis      per-tool exposure, heatmap, capability graph, attack paths
    GET   /api/compare?a=&b=            scan comparison
    GET   /api/findings                 cross-scan findings (filters + paging + facets)
    GET   /api/findings/{id}            one finding with scan context
    PATCH /api/findings/{id}/triage     remediation status (persisted)
    GET   /api/search?q=                tools / findings / scans / reports
    GET   /api/activity                 recent real scan events
    GET   /api/notifications            derived from real scan outcomes
    POST  /api/discover                 offline preview of a config target (servers, tools, capabilities)
    GET   /api/tools/history?name=      one tool across scans
    GET   /api/ml/info                  trained-model metadata or ``available: false``
    GET   /api/system/health            per-component health
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.analysis.investigate import build_analysis, compare_scans
from backend.api.routes import _get_session_with_factory, _scan_or_404, finding_out
from backend.core.config import get_settings
from backend.core.version import ML_MODEL_VERSION
from backend.database.persistence import ScanRepository, scan_to_dict
from backend.models.db import Finding, Scan, ScanEvent, ToolRecord
from backend.schemas.api import FindingOut
from backend.workers.runner import runner


def _as_utc(dt: datetime) -> datetime:
    """Database timestamps may come back naive (SQLite) or aware depending on platform; treat naive as UTC."""
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)

router_v2 = APIRouter(prefix="/api")

# --------------------------------------------------------------------------- unicode inspection
_CATEGORY_LABELS = {
    "Cc": "Control", "Cf": "Format (invisible)", "Co": "Private use", "Cn": "Unassigned", "Cs": "Surrogate",
    "Zs": "Space separator", "Zl": "Line separator", "Zp": "Paragraph separator", "Mn": "Combining mark",
    "Lu": "Uppercase letter", "Ll": "Lowercase letter", "Lt": "Titlecase letter", "Lm": "Modifier letter", "Lo": "Other letter",
    "Nd": "Decimal digit", "Nl": "Letter number", "No": "Other number", "Pc": "Connector punctuation", "Pd": "Dash",
    "Ps": "Open punctuation", "Pe": "Close punctuation", "Pi": "Initial quote", "Pf": "Final quote", "Po": "Other punctuation",
    "Sm": "Math symbol", "Sc": "Currency symbol", "Sk": "Modifier symbol", "So": "Other symbol", "Mc": "Spacing mark", "Me": "Enclosing mark",
}
_BIDI_CONTROLS = {"LRE", "RLE", "PDF", "LRO", "RLO", "LRI", "RLI", "FSI", "PDI"}
_WORD_RE = re.compile(r"[^\W\d_]+", re.UNICODE)


class UnicodeInspectIn(BaseModel):
    text: str = Field(min_length=1, max_length=5000)


def _script_of(ch: str) -> str | None:
    """Coarse script taken from the first word of the character's Unicode name (stdlib has no script table)."""
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    return name.split(" ")[0] if name else None


def inspect_unicode(text: str) -> dict[str, Any]:
    """Per-character facts from the Unicode database. Nothing here is guessed: names, categories and bidi classes come from unicodedata."""
    # mixed-script words: minority-script letters inside one word are classic homoglyph tricks
    mixed: dict[int, str] = {}
    for m in _WORD_RE.finditer(text):
        scripts = [(_script_of(c), i) for i, c in enumerate(m.group(0), m.start())]
        counts: dict[str, int] = {}
        for sc, _ in scripts:
            if sc:
                counts[sc] = counts.get(sc, 0) + 1
        if len(counts) > 1:
            main = max(counts, key=lambda k: counts[k])
            for sc, i in scripts:
                if sc and sc != main:
                    mixed[i] = f"{sc.title()} letter inside a mostly {main.title()} word (possible homoglyph)"
    chars: list[dict[str, Any]] = []
    summary: dict[str, int] = {}
    for i, ch in enumerate(text):
        cat = unicodedata.category(ch)
        bidi = unicodedata.bidirectional(ch)
        name = unicodedata.name(ch, "") or ("<control>" if cat == "Cc" else "<unnamed>")
        reason: str | None = None
        if bidi in _BIDI_CONTROLS:
            reason = "Bidirectional control: can visually reorder text"
        elif cat == "Cf":
            reason = "Invisible format character"
        elif cat == "Cc" and ch not in "\n\r\t":
            reason = "Control character"
        elif cat == "Zs" and ch != " ":
            reason = "Non-standard space character"
        elif cat in ("Co", "Cn", "Cs"):
            reason = "Private-use, unassigned or surrogate code point"
        elif 0xE0000 <= ord(ch) <= 0xE007F:
            reason = "Tag character (invisible, used to smuggle text)"
        elif i in mixed:
            reason = mixed[i]
        if reason:
            summary[reason.split(":")[0].split(" (")[0]] = summary.get(reason.split(":")[0].split(" (")[0], 0) + 1
        chars.append({
            "index": i, "char": ch, "codepoint": f"U+{ord(ch):04X}", "name": name, "category": cat,
            "category_label": _CATEGORY_LABELS.get(cat, cat), "bidi": bidi, "script": _script_of(ch),
            "utf8": ch.encode("utf-8", "surrogatepass").hex(" ").upper(),
            "invisible": cat in ("Cf", "Cc", "Zs", "Zl", "Zp") and ch not in "\n\r\t ",
            "suspicious": reason,
        })
    return {
        "length": len(text),
        "suspicious_count": sum(1 for c in chars if c["suspicious"]),
        "summary": summary,
        "chars": chars,
        "note": "Names, categories and bidi classes come from Python's unicodedata. Script is the first word of the Unicode name (coarse).",
    }



def _repo(session: AsyncSession) -> ScanRepository:
    return ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]


def _fdict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id, "rule_id": f.rule_id, "category": f.category, "severity": f.severity,
        "confidence": f.confidence, "status": f.status, "title": f.title,
        "evidence": f.evidence or [], "affected_tools": f.affected_tools or [],
    }


def _tdict(t: ToolRecord) -> dict[str, Any]:
    return {"name": t.name, "description": t.description, "input_schema": t.input_schema or {}, "capabilities": t.capabilities or []}


def _sdict(s: Scan) -> dict[str, Any]:
    d = scan_to_dict(s)
    d["created_at"] = s.created_at.isoformat() if s.created_at else None
    return d


# --------------------------------------------------------------------------- analysis / compare
@router_v2.get("/scans/{scan_id}/analysis")
async def scan_analysis(scan_id: str, session: AsyncSession = Depends(_get_session_with_factory)) -> dict[str, Any]:
    repo = _repo(session)
    scan = _scan_or_404(await repo.get_scan(scan_id))
    tools = [_tdict(t) for t in await repo.get_tools(scan_id)]
    findings = [_fdict(f) for f in await repo.get_findings(scan_id)]
    return build_analysis(_sdict(scan), tools, findings)


@router_v2.get("/compare")
async def compare(a: str, b: str, session: AsyncSession = Depends(_get_session_with_factory)) -> dict[str, Any]:
    repo = _repo(session)
    sa = _scan_or_404(await repo.get_scan(a))
    sb = _scan_or_404(await repo.get_scan(b))
    return compare_scans(
        _sdict(sa), [_tdict(t) for t in await repo.get_tools(a)], [_fdict(f) for f in await repo.get_findings(a)],
        _sdict(sb), [_tdict(t) for t in await repo.get_tools(b)], [_fdict(f) for f in await repo.get_findings(b)],
    )


# --------------------------------------------------------------------------- findings
class TriageUpdate(BaseModel):
    status: Literal["open", "acknowledged", "in_progress", "resolved", "false_positive", "accepted_risk"]
    note: str = Field(default="", max_length=2000)


@router_v2.patch("/findings/{finding_id}/triage", response_model=FindingOut)
async def update_triage(finding_id: str, body: TriageUpdate, session: AsyncSession = Depends(_get_session_with_factory)) -> FindingOut:
    repo = _repo(session)
    row = await repo.set_triage(finding_id, body.status, body.note)
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    f = await repo.get_finding(finding_id)
    assert f is not None
    return finding_out(f, {finding_id: row})


def _csv(v: str | None) -> set[str]:
    return {x for x in (v or "").split(",") if x}


@router_v2.get("/findings")
async def list_all_findings(
    scan_id: str | None = None,
    severity: str | None = Query(None, description="comma-separated"),
    category: str | None = None,
    status: str | None = None,
    triage: str | None = None,
    confidence: str | None = None,
    tool: str | None = None,
    q: str | None = Query(None, max_length=200),
    since: str | None = Query(None, description="ISO date; scans created on/after"),
    include_info: bool = True,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(_get_session_with_factory),
) -> dict[str, Any]:
    repo = _repo(session)
    rows = await repo.all_findings(scan_id)
    triage_map = await repo.get_triage_map(scan_id)
    since_dt: datetime | None = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since)
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="since must be an ISO date") from exc

    sev, cat, st, tr, conf = _csv(severity), _csv(category), _csv(status), _csv(triage), _csv(confidence)
    tools_f = {t.lower() for t in _csv(tool)}
    needle = (q or "").lower().strip()

    def triage_of(f: Finding) -> str:
        t = triage_map.get(f.id)
        return t.status if t else "open"

    def match(f: Finding, s: Scan) -> bool:
        if not include_info and (f.status == "informational" or f.severity == "info"):
            return False
        if f.category == "engine":
            return False
        if sev and f.severity not in sev:
            return False
        if cat and f.category not in cat:
            return False
        if st and f.status not in st:
            return False
        if tr and triage_of(f) not in tr:
            return False
        if conf and f.confidence not in conf:
            return False
        if tools_f and not (tools_f & {str(t).lower() for t in (f.affected_tools or [])}):
            return False
        if since_dt and s.created_at and _as_utc(s.created_at) < since_dt:
            return False
        if needle:
            hay = " ".join([f.title, f.rule_id, f.category, f.description or "", " ".join(f.affected_tools or [])]).lower()
            if needle not in hay:
                return False
        return True

    matched = [(f, s) for f, s in rows if match(f, s)]

    def facet(fn: Any) -> dict[str, int]:
        out: dict[str, int] = {}
        for f, s in matched:
            k = fn(f, s)
            for key in (k if isinstance(k, list) else [k]):
                out[str(key)] = out.get(str(key), 0) + 1
        return dict(sorted(out.items(), key=lambda kv: -kv[1]))

    facets = {
        "severity": facet(lambda f, s: f.severity),
        "category": facet(lambda f, s: f.category),
        "status": facet(lambda f, s: f.status),
        "triage": facet(lambda f, s: triage_of(f)),
        "confidence": facet(lambda f, s: f.confidence),
        "tool": facet(lambda f, s: list(f.affected_tools or [])),
        "scan": facet(lambda f, s: s.id),
    }
    page = matched[offset : offset + limit]
    items = []
    for f, s in page:
        o = finding_out(f, triage_map).model_dump(mode="json")
        o.update({"scan_id": s.id, "scan_label": s.target_label, "scan_created_at": s.created_at.isoformat() if s.created_at else None})
        items.append(o)
    return {"total": len(matched), "items": items, "facets": facets}


@router_v2.get("/findings/{finding_id}")
async def get_finding(finding_id: str, session: AsyncSession = Depends(_get_session_with_factory)) -> dict[str, Any]:
    repo = _repo(session)
    f = await repo.get_finding(finding_id)
    if f is None:
        raise HTTPException(status_code=404, detail="finding not found")
    s = await repo.get_scan(f.scan_id)
    triage = await repo.get_triage_map(f.scan_id)
    out = finding_out(f, triage).model_dump(mode="json")
    out.update({"scan_id": f.scan_id, "scan_label": s.target_label if s else "", "scan_created_at": s.created_at.isoformat() if s and s.created_at else None})
    return out


# --------------------------------------------------------------------------- search
@router_v2.get("/search")
async def search(q: str = Query(..., min_length=1, max_length=100), session: AsyncSession = Depends(_get_session_with_factory)) -> dict[str, Any]:
    needle = q.lower().strip()
    repo = _repo(session)
    factory = session.async_session_factory  # type: ignore[attr-defined]
    async with factory() as s:
        scans = (await s.execute(select(Scan).order_by(Scan.created_at.desc()).limit(500))).scalars().all()
        tool_rows = (await s.execute(select(ToolRecord))).scalars().all()
    scans_by_id = {x.id: x for x in scans}
    scan_hits = [
        {"id": x.id, "label": x.target_label, "status": x.status, "risk_score": x.risk_score, "created_at": x.created_at.isoformat()}
        for x in scans if needle in x.id.lower() or needle in (x.target_label or "").lower() or needle in (x.target_identifier or "").lower()
    ][:8]
    # tools: one hit per distinct name, pointing at the latest scan that contains it
    seen_tools: dict[str, dict[str, Any]] = {}
    for t in sorted(tool_rows, key=lambda r: _as_utc(scans_by_id[r.scan_id].created_at) if r.scan_id in scans_by_id and scans_by_id[r.scan_id].created_at else datetime.min.replace(tzinfo=timezone.utc), reverse=True):
        if t.scan_id not in scans_by_id:
            continue
        if needle in t.name.lower() or needle in (t.description or "").lower():
            seen_tools.setdefault(t.name, {"name": t.name, "scan_id": t.scan_id, "capabilities": t.capabilities or []})
    finding_hits = []
    for f, sc in await repo.all_findings():
        if f.category == "engine":
            continue
        if needle in f.title.lower() or needle in f.rule_id.lower() or any(needle in str(t).lower() for t in (f.affected_tools or [])):
            finding_hits.append({"id": f.id, "title": f.title, "severity": f.severity, "rule_id": f.rule_id, "scan_id": sc.id, "tools": f.affected_tools or []})
        if len(finding_hits) >= 50:
            break
    reports = [
        {"scan_id": x["id"], "label": x["label"], "created_at": x["created_at"]}
        for x in scan_hits if x["status"] in ("completed", "failed", "cancelled")
    ]
    return {
        "query": q,
        "tools": {"total": len(seen_tools), "items": list(seen_tools.values())[:8]},
        "findings": {"total": len(finding_hits), "items": finding_hits[:8]},
        "scans": {"total": len(scan_hits), "items": scan_hits},
        "reports": {"total": len(reports), "items": reports},
    }


# --------------------------------------------------------------------------- activity / notifications
@router_v2.get("/activity")
async def activity(limit: int = Query(30, ge=1, le=200), session: AsyncSession = Depends(_get_session_with_factory)) -> dict[str, Any]:
    factory = session.async_session_factory  # type: ignore[attr-defined]
    async with factory() as s:
        rows = (
            await s.execute(
                select(ScanEvent, Scan.target_label)
                .join(Scan, Scan.id == ScanEvent.scan_id)
                .where(ScanEvent.event.in_(["completed", "error", "warning", "progress"]))
                .order_by(ScanEvent.timestamp.desc())
                .limit(limit)
            )
        ).all()
    items = [
        {
            "timestamp": e.timestamp.isoformat(), "scan_id": e.scan_id, "scan_label": label,
            "stage": e.stage, "event": e.event, "level": e.level, "message": e.message,
        }
        for e, label in rows
    ]
    return {"items": items}


@router_v2.get("/notifications")
async def notifications(session: AsyncSession = Depends(_get_session_with_factory)) -> dict[str, Any]:
    repo = _repo(session)
    factory = session.async_session_factory  # type: ignore[attr-defined]
    items: list[dict[str, Any]] = []
    async with factory() as s:
        scans = (await s.execute(select(Scan).order_by(Scan.created_at.desc()).limit(30))).scalars().all()
    crit_by_scan: dict[str, int] = {}
    for f, sc in await repo.all_findings():
        if f.severity == "critical" and f.status in ("confirmed", "suspected"):
            crit_by_scan[sc.id] = crit_by_scan.get(sc.id, 0) + 1
    for sc in scans:
        ts = (sc.completed_at or sc.created_at).isoformat()
        if sc.status == "completed":
            items.append({"id": f"done-{sc.id}", "kind": "scan_completed", "level": "info", "title": "Scan completed", "message": f"{sc.target_label} - risk {sc.risk_score if sc.risk_score is not None else 'n/a'}", "scan_id": sc.id, "timestamp": ts})
            if crit_by_scan.get(sc.id):
                items.append({"id": f"crit-{sc.id}", "kind": "critical_finding", "level": "critical", "title": "Critical finding discovered", "message": f"{crit_by_scan[sc.id]} critical finding(s) in {sc.target_label}", "scan_id": sc.id, "timestamp": ts})
            if sc.ml_status in ("unavailable", "error"):
                items.append({"id": f"ml-{sc.id}", "kind": "ml_unavailable", "level": "warning", "title": "ML analysis unavailable", "message": f"ML status for this scan: {sc.ml_status}", "scan_id": sc.id, "timestamp": ts})
        elif sc.status == "failed":
            items.append({"id": f"fail-{sc.id}", "kind": "scan_failed", "level": "error", "title": "Scan failed", "message": (sc.error or "no detail")[:200], "scan_id": sc.id, "timestamp": ts})
        elif sc.status == "cancelled":
            items.append({"id": f"cancel-{sc.id}", "kind": "scan_cancelled", "level": "warning", "title": "Scan cancelled", "message": sc.target_label, "scan_id": sc.id, "timestamp": ts})
        for t in await repo.get_tests(sc.id):
            if t.status == "skipped" and ("refus" in (t.detail or "").lower() or "block" in (t.detail or "").lower()):
                items.append({"id": f"blk-{t.id}", "kind": "dynamic_blocked", "level": "warning", "title": "Dynamic test blocked", "message": f"{t.test_name}: {(t.detail or '')[:160]}", "scan_id": sc.id, "timestamp": ts})
    items.sort(key=lambda i: i["timestamp"], reverse=True)
    return {"items": items[:60]}


# --------------------------------------------------------------------------- discovery preview
class DiscoverRequest(BaseModel):
    target_config: dict[str, Any] | list[Any] | str | None = None
    uploaded_file: str | None = Field(default=None, pattern=r"^[0-9a-f]{24}\.json$")


@router_v2.post("/discover")
async def discover(body: DiscoverRequest) -> dict[str, Any]:
    """Offline preview of a configuration target. Nothing is executed or contacted."""
    from backend.api.uploads import UploadValidationError, read_upload
    from backend.scanners.mcp_ingest import normalize_target
    from backend.scanners.static.capability_analyzer import infer_tool_capabilities

    raw: Any = body.target_config
    if body.uploaded_file:
        if raw is not None:
            raise HTTPException(status_code=422, detail="provide either target_config or uploaded_file, not both")
        try:
            raw = json.loads(await read_upload(body.uploaded_file))
        except (UploadValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail=f"uploaded_file rejected: {exc}") from exc
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"target_config is not valid JSON: {exc}") from exc
    if raw is None:
        raise HTTPException(status_code=422, detail="target_config or uploaded_file is required")
    t = normalize_target(raw)
    caps: dict[str, int] = {}
    tools = []
    for tool in t.tools[:500]:
        c = infer_tool_capabilities(tool)
        for x in c:
            caps[x] = caps.get(x, 0) + 1
        tools.append({"name": tool.name, "server": tool.server_name, "capabilities": c})
    return {
        "servers": [{"name": s.name, "transport": s.transport, "url": s.url} for s in t.servers],
        "tools": tools,
        "tool_count": len(t.tools),
        "capabilities": caps,
        "issues": [{"code": i.code, "message": i.message, "severity": i.severity} for i in t.issues[:20]],
        "resources": None,
        "prompts": None,
        "note": "Resources and prompts are not analyzed by this scanner version. Nothing was executed or contacted.",
    }


# --------------------------------------------------------------------------- tool history
@router_v2.get("/tools/history")
async def tool_history(name: str = Query(..., min_length=1, max_length=256), session: AsyncSession = Depends(_get_session_with_factory)) -> dict[str, Any]:
    import hashlib

    repo = _repo(session)
    factory = session.async_session_factory  # type: ignore[attr-defined]
    async with factory() as s:
        rows = (
            await s.execute(
                select(ToolRecord, Scan).join(Scan, Scan.id == ToolRecord.scan_id).where(ToolRecord.name == name).order_by(Scan.created_at.desc()).limit(50)
            )
        ).all()
    items = []
    for t, sc in rows:
        fs = [f for f in await repo.get_findings(sc.id) if name in (f.affected_tools or []) and f.category != "engine" and f.status != "informational"]
        tests = [x for x in await repo.get_tests(sc.id) if x.tool_name == name]
        digest = hashlib.sha256(json.dumps([t.description, t.input_schema], sort_keys=True, default=str).encode()).hexdigest()[:12]
        order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        top = max((f.severity for f in fs), key=lambda v: order.get(v, 0), default="none")
        items.append({
            "scan_id": sc.id, "scan_label": sc.target_label, "created_at": sc.created_at.isoformat(),
            "finding_count": len(fs), "max_severity": top, "definition_hash": digest,
            "capabilities": t.capabilities or [], "tests": [{"test_id": x.test_id, "test_name": x.test_name, "status": x.status, "detail": x.detail} for x in tests],
        })
    return {"name": name, "items": items}


# --------------------------------------------------------------------------- ML info / system health
@router_v2.post("/unicode/inspect")
async def unicode_inspect(body: UnicodeInspectIn) -> dict[str, Any]:
    """Stateless: inspects the posted text and stores nothing."""
    return inspect_unicode(body.text)


@router_v2.get("/ml/info")
async def ml_info() -> dict[str, Any]:
    try:
        from backend.ml.predict import load_metadata, model_available

        if not model_available():
            return {"available": False, "reason": "No trained model artifacts found. Run: python -m backend.ml.train", "runtime_model_version": ML_MODEL_VERSION}
        meta = load_metadata()
    except Exception as exc:  # noqa: BLE001 - surface honestly, never fabricate
        return {"available": False, "reason": f"ML metadata could not be loaded ({type(exc).__name__})", "runtime_model_version": ML_MODEL_VERSION}
    metrics = meta.get("metrics") or {}
    dataset = metrics.get("dataset") or {}
    return {
        "available": True,
        "runtime_model_version": ML_MODEL_VERSION,
        "model_version": meta.get("model_version"),
        "model_type": meta.get("model_type"),
        "model_status": meta.get("model_status"),
        "usage": meta.get("usage"),
        "trained_at": meta.get("trained_at"),
        "feature_count": len(meta.get("features") or []),
        "features": meta.get("features") or [],
        "dataset": dataset,
        "real_world_training_samples": 0 if dataset.get("synthetic") else dataset.get("total"),
        "synthetic_share": 1.0 if dataset.get("synthetic") else 0.0,
        "test": metrics.get("test"),
        "cv_f1_train": metrics.get("cv_f1_train"),
        "confusion_matrix_test": metrics.get("confusion_matrix_test"),
        "cross_validation": metrics.get("cross_validation_grouped_by_server"),
        "leave_one_template_out_recall": metrics.get("leave_one_template_out_recall"),
        "independent_evaluation": metrics.get("independent_evaluation"),
        "thresholds": meta.get("thresholds"),
        "caveats": meta.get("caveats") or [],
        "input": meta.get("input"),
        "note": "All values are read from the trained model's metadata.json. The model is advisory only and never creates, upgrades or removes findings.",
    }


@router_v2.get("/system/health")
async def system_health() -> dict[str, Any]:
    settings = get_settings()
    comps: list[dict[str, str]] = [{"id": "backend", "label": "Backend API", "status": "healthy", "detail": "Responding to requests."}]

    try:
        from backend.database.session import get_session_factory

        async with get_session_factory()() as s:
            await s.execute(text("SELECT 1"))
        comps.append({"id": "database", "label": "Database", "status": "healthy", "detail": "Query succeeded."})
    except Exception as exc:  # noqa: BLE001
        comps.append({"id": "database", "label": "Database", "status": "unavailable", "detail": f"Query failed ({type(exc).__name__})."})

    try:
        import backend.scanners.dynamic.connector  # noqa: F401

        comps.append({"id": "connector", "label": "MCP connector", "status": "healthy", "detail": "Module loaded. Connections are made per scan, so no live check is possible here."})
    except Exception as exc:  # noqa: BLE001
        comps.append({"id": "connector", "label": "MCP connector", "status": "unavailable", "detail": f"Import failed ({type(exc).__name__})."})

    try:
        from backend.ml.predict import model_available

        ok = bool(model_available())
        comps.append({"id": "ml", "label": "ML service", "status": "healthy" if ok else "unavailable", "detail": "Model artifacts present (advisory only)." if ok else "No trained model artifacts."})
    except Exception as exc:  # noqa: BLE001
        comps.append({"id": "ml", "label": "ML service", "status": "unavailable", "detail": f"ML layer could not load ({type(exc).__name__})."})

    if settings.llm_provider == "disabled":
        comps.append({"id": "llm", "label": "LLM service", "status": "unavailable", "detail": "Disabled by configuration (LLM_PROVIDER=disabled). The scanner works without it."})
    else:
        comps.append({"id": "llm", "label": "LLM service", "status": "degraded", "detail": f"Provider '{settings.llm_provider}' is configured; availability is only known when a scan uses it."})

    running = runner.running_ids
    comps.append({"id": "worker", "label": "Scan worker", "status": "healthy", "detail": f"{len(running)} scan(s) running in-process."})

    try:
        import reportlab  # noqa: F401

        comps.append({"id": "reports", "label": "Report generator", "status": "healthy", "detail": "PDF library available."})
    except ImportError:
        comps.append({"id": "reports", "label": "Report generator", "status": "degraded", "detail": "PDF library missing; JSON reports still work."})

    order = {"unavailable": 2, "degraded": 1, "healthy": 0}
    # Optional components (ML, LLM) being off does not make the platform unhealthy.
    core = [c for c in comps if c["id"] not in ("ml", "llm")]
    overall = max((c["status"] for c in core), key=lambda s: order[s])
    return {
        "overall": overall,
        "components": comps,
        "running_scans": running,
        "time_utc": datetime.now(timezone.utc).isoformat(),
    }
