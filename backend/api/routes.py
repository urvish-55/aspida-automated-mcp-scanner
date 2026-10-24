"""REST API routes.

Endpoint map:
    GET    /api/health            liveness + component availability
    GET    /api/version           version info
    GET    /api/auth/check        200 if the supplied API key is valid (401 otherwise)
    POST   /api/scans             create scan (returns job id; async worker runs it)
    GET    /api/scans             list scans (paginated)
    GET    /api/scans/{id}        scan detail incl. progress events
    DELETE /api/scans/{id}        delete scan (cancels if running)
    POST   /api/scans/{id}/cancel cancel a running scan
    GET    /api/scans/{id}/findings   findings (filterable)
    GET    /api/scans/{id}/tools      tool inventory
    GET    /api/scans/{id}/report     JSON report (generated on demand, live structure)
    GET    /api/scans/{id}/report/pdf PDF report
    POST   /api/uploads           upload a config file -> stored filename
    GET    /api/dashboard         dashboard statistics (real aggregates only)

All validation is server-side via Pydantic models. Errors are honest; a scan
that cannot run fails visibly rather than returning fabricated results.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.uploads import UploadValidationError, validate_upload
from backend.core.config import get_settings
from backend.core.version import APP_VERSION, ML_MODEL_VERSION, RULESET_VERSION, SCANNER_NAME, SCANNER_SCHEMA_VERSION
from backend.database.persistence import ScanRepository, scan_to_dict
from backend.models.db import Scan
from backend.reports.builder import build_report
from backend.reports.pdf import PdfReportError, generate_pdf
from backend.schemas.api import (
    DashboardStats,
    FindingOut,
    FindingsPage,
    HealthInfo,
    PaginatedScans,
    ScanCreate,
    ScanDetailOut,
    ScanOut,
    ToolOut,
    VersionInfo,
    EventOut,
    DynamicTestOut,
)
from backend.workers.pipeline import ScanPipeline
from backend.workers.runner import runner

router = APIRouter(prefix="/api")


async def _get_session_with_factory() -> Any:
    from backend.database.session import get_session_factory

    factory = get_session_factory()
    async with factory() as session:
        session.async_session_factory = factory  # type: ignore[attr-defined]
        yield session


def finding_out(f: Any, triage: dict[str, Any]) -> FindingOut:
    out = FindingOut.model_validate(f)
    t = triage.get(f.id)
    if t is not None:
        out.triage_status = t.status
        out.triage_note = t.note
        out.triage_updated_at = t.updated_at
    return out


def _scan_or_404(scan: Scan | None) -> Scan:
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


# ---------------------------------------------------------------------------
# Meta
# ---------------------------------------------------------------------------

@router.get("/health", response_model=HealthInfo)
async def health() -> HealthInfo:
    settings = get_settings()
    db_status = "ok"
    try:
        from backend.database.session import get_session_factory

        factory = get_session_factory()
        async with factory() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        db_status = "error"
    ml_available = False
    try:
        from backend.ml.predict import model_available

        ml_available = bool(model_available())
    except ImportError:
        ml_available = False
    llm_available = settings.llm_provider != "disabled"
    return HealthInfo(
        status="ok" if db_status == "ok" else "degraded",
        database=db_status,
        llm_provider=settings.llm_provider,
        llm_available=llm_available,
        ml_available=ml_available,
        safe_mode_default=settings.safe_mode,
        auth_required=settings.auth_required,
        time_utc=datetime.now(timezone.utc).isoformat(),
    )


@router.get("/auth/check")
async def auth_check() -> dict[str, bool]:
    """Returns 200 only for a valid key (enforced by the auth middleware); used by the dashboard login."""
    return {"authenticated": True}


@router.get("/version", response_model=VersionInfo)
async def version() -> VersionInfo:
    return VersionInfo(
        app_name=SCANNER_NAME,
        version=APP_VERSION,
        ruleset_version=RULESET_VERSION,
        ml_model_version=ML_MODEL_VERSION,
        scanner_schema_version=SCANNER_SCHEMA_VERSION,
    )


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@router.post("/scans", response_model=ScanOut, status_code=201)
async def create_scan(payload: ScanCreate, session: AsyncSession = Depends(_get_session_with_factory)) -> ScanOut:
    settings = get_settings()
    repo = ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]

    if payload.dynamic_enabled and not payload.authorization_confirmed:
        raise HTTPException(
            status_code=422,
            detail="dynamic testing requires explicit authorization confirmation",
        )
    if payload.semantic_enabled and settings.llm_provider == "disabled":
        # allowed but honest: semantic layer will report unavailable
        pass

    target_identifier = ""
    source_kind: str = "inline"
    source_file: str | None = None
    inline_target: Any = payload.target_config

    if payload.target_type == "url":
        from backend.security.network import SSRFBlockedError, validate_target_url

        assert payload.server_url
        try:
            validate_target_url(payload.server_url, allow_local=settings.allow_local_targets)
        except SSRFBlockedError as exc:
            raise HTTPException(status_code=422, detail=f"target rejected by SSRF policy: {exc}") from exc
        target_identifier = payload.server_url
        inline_target = None
    elif payload.uploaded_file:
        if inline_target is not None:
            raise HTTPException(status_code=422, detail="provide either target_config or uploaded_file, not both")
        from backend.api.uploads import UploadValidationError, read_upload

        try:
            inline_target = json.loads(await read_upload(payload.uploaded_file))
        except (UploadValidationError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail=f"uploaded_file rejected: {exc}") from exc
        source_kind = "file"
        source_file = payload.uploaded_file
    else:
        if inline_target is None:
            raise HTTPException(status_code=422, detail="target_config (or uploaded_file) is required for target_type='config'")
        if isinstance(inline_target, str):
            try:
                inline_target = json.loads(inline_target)
            except json.JSONDecodeError as exc:
                raise HTTPException(status_code=422, detail=f"target_config is not valid JSON: {exc}") from exc

    label: str = payload.target_type
    if payload.target_type == "url":
        label = payload.server_url or "url target"
    elif isinstance(inline_target, dict) and isinstance(inline_target.get("mcpServers"), dict):
        label = f"config ({len(inline_target['mcpServers'])} server(s))"
    elif isinstance(inline_target, list):
        label = f"config ({len(inline_target)} tool(s))"

    scan = await repo.create_scan(
        status="queued",
        target_label=label[:256],
        target_type=payload.target_type,
        target_identifier=target_identifier[:512],
        source_kind=source_kind,
        source_file=source_file,
        safe_mode=payload.safe_mode or settings.safe_mode,
        dynamic_enabled=payload.dynamic_enabled and payload.authorization_confirmed,
        semantic_enabled=payload.semantic_enabled,
        allow_local_targets=settings.allow_local_targets,
        authorization_confirmed=payload.authorization_confirmed,
    )
    # keep the raw target for the worker without exposing it via API reads of scans list
    await repo.update_scan(scan.id, config_snapshot={"inline_target": inline_target})

    cancel_event = asyncio.Event()
    pipeline = ScanPipeline(repo, cancel_event)
    runner.start(scan.id, pipeline.run(scan.id), cancel_event)

    return ScanOut.model_validate(scan)


@router.get("/scans", response_model=PaginatedScans)
async def list_scans(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: Literal["queued", "running", "completed", "failed", "cancelled"] | None = None,
    session: AsyncSession = Depends(_get_session_with_factory),
) -> PaginatedScans:
    factory = session.async_session_factory  # type: ignore[attr-defined]
    async with factory() as s:
        from backend.models.db import Scan as ScanModel

        q = select(ScanModel).order_by(ScanModel.created_at.desc())
        if status:
            q = q.where(ScanModel.status == status)
        rows = (await s.execute(q.limit(limit).offset(offset))).scalars().all()
        total = int((await s.execute(select(func.count(ScanModel.id)))).scalar_one())
    return PaginatedScans(total=total, items=[ScanOut.model_validate(r) for r in rows])


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
async def get_scan(scan_id: str, session: AsyncSession = Depends(_get_session_with_factory)) -> ScanDetailOut:
    repo = ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]
    scan = _scan_or_404(await repo.get_scan(scan_id))
    events = await repo.list_events(scan_id)
    findings = await repo.get_findings(scan_id)
    tools = await repo.get_tools(scan_id)
    tests = await repo.get_tests(scan_id)
    triage = await repo.get_triage_map(scan_id)
    detail = ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        events=[EventOut.model_validate(e) for e in events],
        findings=[finding_out(f, triage) for f in findings],
        tools=[ToolOut.model_validate(t) for t in tools],
        tests=[DynamicTestOut.model_validate(t) for t in tests],
    )
    return detail


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str, session: AsyncSession = Depends(_get_session_with_factory)) -> Response:
    repo = ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]
    _scan_or_404(await repo.get_scan(scan_id))
    runner.cancel(scan_id)
    # give a running task a brief moment to acknowledge cancellation
    for _ in range(10):
        if not runner.is_running(scan_id):
            break
        await asyncio.sleep(0.1)
    deleted = await repo.delete_scan(scan_id)
    if not deleted:
        raise HTTPException(status_code=409, detail="scan could not be deleted while running; try again")
    return Response(status_code=204)


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(scan_id: str, session: AsyncSession = Depends(_get_session_with_factory)) -> ScanOut:
    repo = ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]
    scan = _scan_or_404(await repo.get_scan(scan_id))
    if scan.status not in ("queued", "running"):
        raise HTTPException(status_code=409, detail=f"scan is not running (status: {scan.status})")
    cancelled = runner.cancel(scan_id)
    if not cancelled:
        await repo.update_scan(scan_id, status="cancelled", completed_at=datetime.now(timezone.utc))
    await asyncio.sleep(0)  # yield so the worker can process the cancel
    refreshed = _scan_or_404(await repo.get_scan(scan_id))
    return ScanOut.model_validate(refreshed)


@router.get("/scans/{scan_id}/findings", response_model=FindingsPage)
async def list_findings(
    scan_id: str,
    severity: str | None = None,
    category: str | None = None,
    status: str | None = None,
    tool: str | None = None,
    confidence: str | None = None,
    session: AsyncSession = Depends(_get_session_with_factory),
) -> FindingsPage:
    repo = ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]
    _scan_or_404(await repo.get_scan(scan_id))
    findings = await repo.get_findings(scan_id)
    def match(f: Any) -> bool:
        if severity and f.severity != severity:
            return False
        if category and f.category != category:
            return False
        if status and f.status != status:
            return False
        if confidence and f.confidence != confidence:
            return False
        if tool and tool.lower() not in [t.lower() for t in (f.affected_tools or [])]:
            return False
        return True
    items = [f for f in findings if match(f)]
    triage = await repo.get_triage_map(scan_id)
    return FindingsPage(total=len(items), items=[finding_out(f, triage) for f in items])


@router.get("/scans/{scan_id}/tools", response_model=list[ToolOut])
async def list_tools(scan_id: str, session: AsyncSession = Depends(_get_session_with_factory)) -> list[ToolOut]:
    repo = ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]
    _scan_or_404(await repo.get_scan(scan_id))
    tools = await repo.get_tools(scan_id)
    return [ToolOut.model_validate(t) for t in tools]


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

async def _build_report_for(scan_id: str, session: AsyncSession) -> dict[str, Any]:
    repo = ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]
    scan = _scan_or_404(await repo.get_scan(scan_id))
    if scan.status not in ("completed", "failed", "cancelled"):
        raise HTTPException(status_code=409, detail=f"scan is {scan.status}; report is available once it finishes")
    findings = await repo.get_findings(scan_id)
    tools = await repo.get_tools(scan_id)
    tests = await repo.get_tests(scan_id)
    events = await repo.list_events(scan_id)

    def fdict(f: Any) -> dict[str, Any]:
        return {
            "rule_id": f.rule_id, "category": f.category, "severity": f.severity,
            "confidence": f.confidence, "status": f.status, "title": f.title,
            "description": f.description, "evidence": f.evidence or [],
            "affected_tools": f.affected_tools or [], "reproduction": f.reproduction or {},
            "impact": f.impact, "remediation": f.remediation, "references": f.references or [],
            "detector_sources": f.detector_sources or [],
        }

    def tdict(t: Any) -> dict[str, Any]:
        return {
            "test_id": t.test_id, "test_name": t.test_name, "tool_name": t.tool_name,
            "status": t.status, "detail": t.detail, "evidence": t.evidence or {},
            "duration_ms": t.duration_ms,
        }

    analyzer_statuses = (scan.config_snapshot or {}).get("analyzer_statuses", [])
    semantic_result = {
        "status": scan.semantic_status,
        "provider": (scan.config_snapshot or {}).get("semantic_provider", "disabled"),
        "reason": (scan.config_snapshot or {}).get("semantic_reason", ""),
    }
    ml_detail = (scan.config_snapshot or {}).get("ml_detail") or {}
    ml_result = {
        "note": "see ML.md; ML never overrides deterministic findings",
        **{k: v for k, v in ml_detail.items() if k in ("note", "model_version", "model_status", "flagged_tools", "tools_scored", "thresholds", "max_poisoned_probability", "disclaimer")},
        "status": scan.ml_status or "unavailable",
    }
    return build_report(
        scan=scan_to_dict(scan),
        tools=[{"name": t.name, "description": t.description, "input_schema": t.input_schema or {}, "capabilities": t.capabilities or []} for t in tools],
        findings=[fdict(f) for f in findings],
        tests=[tdict(t) for t in tests],
        events=[{"seq": e.seq, "timestamp": e.timestamp.isoformat(), "stage": e.stage, "event": e.event, "message": e.message, "level": e.level, "progress": e.progress} for e in events],
        risk_breakdown=scan.risk_breakdown or {},
        analyzer_statuses=analyzer_statuses,
        semantic_result=semantic_result,
        ml_result=ml_result,
        target_fingerprint=(scan.config_snapshot or {}).get("target_fingerprint", ""),
    )


@router.get("/scans/{scan_id}/report")
async def get_report(scan_id: str, session: AsyncSession = Depends(_get_session_with_factory)) -> dict[str, Any]:
    return await _build_report_for(scan_id, session)


@router.get("/scans/{scan_id}/report/pdf")
async def get_report_pdf(scan_id: str, session: AsyncSession = Depends(_get_session_with_factory)) -> Response:
    report = await _build_report_for(scan_id, session)
    try:
        pdf_bytes = generate_pdf(report)
    except PdfReportError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    filename = f"mcp-pentest-report-{scan_id[:12]}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ---------------------------------------------------------------------------
# Uploads & dashboard
# ---------------------------------------------------------------------------

@router.post("/uploads")
async def upload_config(file: UploadFile = File(...)) -> dict[str, str | int]:
    content = await file.read()
    try:
        path = validate_upload(file.filename or "", content)
    except UploadValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return {"stored_filename": path.name, "size_bytes": len(content)}


@router.get("/dashboard", response_model=DashboardStats)
async def dashboard(session: AsyncSession = Depends(_get_session_with_factory)) -> DashboardStats:
    repo = ScanRepository(session_factory=session.async_session_factory)  # type: ignore[attr-defined]
    stats = await repo.dashboard_stats()
    latest = stats.get("latest_scan")
    security_status = "No scans performed yet."
    if stats["total_scans"] > 0:
        if stats["scans_failed"] == stats["total_scans"]:
            security_status = "All scans have failed; no security conclusions can be drawn."
        elif stats["high_critical_findings"] > 0:
            security_status = f"{stats['high_critical_findings']} high/critical finding(s) across all scans."
        else:
            security_status = "No high/critical findings recorded. This does not mean targets are secure."
    return DashboardStats(
        total_scans=stats["total_scans"],
        scans_completed=stats["scans_completed"],
        scans_failed=stats["scans_failed"],
        high_critical_findings=stats["high_critical_findings"],
        average_risk_score=stats["average_risk_score"],
        latest_scan=ScanOut.model_validate(latest) if latest else None,
        tools_analyzed=stats["tools_analyzed"],
        tests_executed=stats["tests_executed"],
        tests_skipped=stats["tests_skipped"],
        security_status=security_status,
    )
