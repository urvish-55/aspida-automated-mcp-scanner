"""The scan pipeline: orchestrates every stage, persists real progress, and
guarantees honest terminal states.

Stage list and weights (progress = completed stage weights; never invented):
    initializing → parsing_target → enumerating_tools → static_analysis
    → dynamic_testing (optional/skipped) → semantic_analysis (optional/skipped)
    → risk_aggregation → report_generation → completed

Failure policy:
- Ingest failure (nothing analyzable) → scan failed with a clear error.
- Analyzer crash → ENGINE-001 finding (scan continues, coverage noted).
- Dynamic connection failure → error test record (scan continues).
- Semantic/ML unavailability → status fields, never errors of the scan.
- Cancellation → status cancelled, partial data kept.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timezone
from typing import Any

from backend.core.config import get_settings
from backend.core.logging import get_scan_logger
from backend.core.version import APP_VERSION, RULESET_VERSION
from backend.database.persistence import ScanRepository
from backend.risk.engine import compute_risk
from backend.risk.fusion import fuse_findings
from backend.scanners.dynamic.engine import DynamicScanner
from backend.scanners.dynamic.safety import SafetyController, ScanCancelled
from backend.scanners.mcp_ingest import NormalizedTarget, normalize_target, target_fingerprint
from backend.scanners.semantic.engine import run_semantic_analysis
from backend.scanners.static.capability_analyzer import infer_tool_capabilities
from backend.scanners.static.engine import run_static_analysis

# (stage_id, weight)
STAGES: tuple[tuple[str, int], ...] = (
    ("initializing", 2),
    ("parsing_target", 8),
    ("enumerating_tools", 10),
    ("static_analysis", 30),
    ("dynamic_testing", 25),
    ("semantic_analysis", 10),
    ("risk_aggregation", 8),
    ("report_generation", 5),
    ("completed", 2),
)


def _progress_at(stage_index: int) -> float:
    return round(sum(w for _, w in STAGES[:stage_index]), 1)


class ScanPipeline:
    def __init__(self, repo: ScanRepository, cancel_event: asyncio.Event) -> None:
        self.repo = repo
        self.cancel_event = cancel_event
        self.log = get_scan_logger("pending", "pipeline")

    async def run(self, scan_id: str) -> None:
        started = time.perf_counter()
        self.log = get_scan_logger(scan_id, "pipeline")
        scan = await self.repo.get_scan(scan_id)
        if scan is None:
            self.log.error("scan row missing at pipeline start")
            return
        await self.repo.update_scan(scan_id, status="running", started_at=datetime.now(timezone.utc))
        try:
            try:
                await asyncio.wait_for(self._run_stages(scan_id), timeout=get_settings().scan_timeout_seconds)
            except asyncio.TimeoutError:
                raise TimeoutError(
                    f"scan exceeded the overall timeout of {get_settings().scan_timeout_seconds}s and was aborted"
                )
        except ScanCancelled:
            await self.repo.add_event(scan_id, stage="pipeline", event="cancelled", message="Scan cancelled by operator", level="warning", progress=100)
            await self.repo.update_scan(scan_id, status="cancelled", completed_at=datetime.now(timezone.utc))
            self.log.info("scan cancelled")
        except Exception as exc:  # noqa: BLE001 - terminal guard
            self.log.error(f"scan failed: {type(exc).__name__}: {exc}")
            await self.repo.add_event(scan_id, stage="pipeline", event="error", message=f"Scan failed: {type(exc).__name__}", level="error", progress=100)
            await self.repo.update_scan(
                scan_id,
                status="failed",
                error=f"{type(exc).__name__}: {exc}"[:2000],
                completed_at=datetime.now(timezone.utc),
            )
        finally:
            duration = round(time.perf_counter() - started, 3)
            self.log.info(f"pipeline finished in {duration}s")

    # ------------------------------------------------------------------
    def _check_cancel(self) -> None:
        if self.cancel_event.is_set():
            raise ScanCancelled()

    async def _stage(self, scan_id: str, index: int, message: str = "") -> None:
        stage_id = STAGES[index][0]
        self._check_cancel()
        await self.repo.add_event(
            scan_id, stage=stage_id, event="started", message=message, progress=_progress_at(index)
        )
        self.log.info(f"stage started: {stage_id}")

    async def _stage_done(self, scan_id: str, index: int, message: str = "", duration_ms: int | None = None, level: str = "info") -> None:
        stage_id = STAGES[index][0]
        await self.repo.add_event(
            scan_id, stage=stage_id, event="completed", message=message, level=level,
            progress=_progress_at(index + 1), duration_ms=duration_ms,
        )

    # ------------------------------------------------------------------
    async def _run_stages(self, scan_id: str) -> None:
        settings = get_settings()
        scan = await self.repo.get_scan(scan_id)
        assert scan is not None
        config_snapshot = {
            "safe_mode": scan.safe_mode,
            "dynamic_enabled": scan.dynamic_enabled,
            "semantic_enabled": scan.semantic_enabled,
            "allow_local_targets": scan.allow_local_targets,
            "max_dynamic_requests": settings.max_dynamic_requests,
            "max_payload_size_bytes": settings.max_payload_size_bytes,
            "scan_timeout_seconds": settings.scan_timeout_seconds,
        }
        await self.repo.update_scan(scan_id, scanner_version=APP_VERSION, ruleset_version=RULESET_VERSION, config_snapshot=config_snapshot)

        # ---- Stage 0: initializing ------------------------------------
        await self._stage(scan_id, 0, "Pipeline initialized")

        # ---- Stage 1: parsing target -----------------------------------
        # Two target shapes:
        #   config scans: metadata comes from the provided config/manifest
        #   url scans:    metadata is discovered from the LIVE server during
        #                 the dynamic stage; static analysis runs on the
        #                 enumerated metadata afterwards.
        await self._stage(scan_id, 1)
        t0 = time.perf_counter()
        is_url_scan = scan.target_type == "url" and bool(scan.target_identifier)
        target: NormalizedTarget | None = None
        if not is_url_scan:
            raw_input: Any
            if scan.source_kind == "file" and scan.source_file:
                from backend.api.uploads import read_upload

                raw_input = await read_upload(scan.source_file)
            else:
                raw_input = scan.config_snapshot.get("inline_target")
            target = normalize_target(raw_input)
            if target.tools or target.servers:
                await self._stage_done(scan_id, 1, f"Parsed {len(target.tools)} tool(s), {len(target.servers)} server(s); {len(target.issues)} parse issue(s)", _ms(t0))
            else:
                issues = "; ".join(f"{i.code}: {i.message}" for i in target.issues[:5]) or "no recognizable MCP content"
                await self.repo.add_event(scan_id, stage="parsing_target", event="error", message=f"Target could not be parsed: {issues}", level="error")
                await self.repo.update_scan(scan_id, status="failed", error=f"Target could not be parsed: {issues}"[:2000], completed_at=datetime.now(timezone.utc))
                return
        else:
            await self._stage_done(scan_id, 1, f"URL target: {scan.target_identifier}; tools will be enumerated live", _ms(t0))

        # ---- Stage 2 (config scans): enumerating tools from parsed metadata
        dynamic_result: dict[str, Any] = {"enabled": scan.dynamic_enabled, "tests": [], "findings": [], "connection_error": ""}
        await self._stage(scan_id, 2)
        t0 = time.perf_counter()
        if not is_url_scan:
            assert target is not None  # parsed above for non-URL scans
            if len(target.tools) > settings.max_tools_per_scan:
                kept = target.tools[: settings.max_tools_per_scan]
                await self.repo.add_event(scan_id, stage="enumerating_tools", event="warning",
                    message=f"Target has {len(target.tools)} tools; analysis capped at {settings.max_tools_per_scan}", level="warning")
                target.tools = kept
            tool_dicts = [
                {
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                    "annotations": t.annotations,
                    "capabilities": infer_tool_capabilities(t),
                }
                for t in target.tools
            ]
            await self.repo.save_tools(scan_id, tool_dicts)
            await self._stage_done(scan_id, 2, f"{len(tool_dicts)} tool(s) enumerated and stored", _ms(t0))

        # ---- Stage 3: static analysis (config scans only; url scans run it
        # after live enumeration so the analyzers see real metadata) ----------
        static_dicts: list[dict[str, Any]] = []
        analyzer_statuses: list[dict[str, Any]] = []
        if not is_url_scan:
            await self._stage(scan_id, 3)
            t0 = time.perf_counter()
            assert target is not None
            static_findings, analyzer_statuses = run_static_analysis(target, scan_id)
            static_dicts = [f.to_dict() for f in static_findings]
            await self.repo.add_event(
                scan_id, stage="static_analysis", event="progress",
                message=f"Static analysis produced {len(static_dicts)} finding(s) from {len(analyzer_statuses)} analyzer(s)",
            )
            await self._stage_done(scan_id, 3, f"{len(static_dicts)} static finding(s)", _ms(t0))

        # ---- Stage 4: dynamic testing ------------------------------------
        await self._stage(scan_id, 4)
        t0 = time.perf_counter()
        if not is_url_scan:
            if not scan.dynamic_enabled:
                dynamic_result["tests"].append({
                    "test_id": "DYN-OFF-000", "test_name": "Dynamic testing", "tool_name": "",
                    "status": "not_applicable",
                    "detail": "Dynamic testing was disabled for this scan; no live probes were sent.",
                })
                await self._stage_done(scan_id, 4, "Dynamic testing disabled by configuration", _ms(t0))
            else:
                dynamic_result["tests"].append({
                    "test_id": "DYN-URL-000", "test_name": "Dynamic testing", "tool_name": "",
                    "status": "not_applicable",
                    "detail": "Dynamic testing requires a URL target; this scan analyzed a static configuration only.",
                })
                await self._stage_done(scan_id, 4, "No live endpoint: dynamic tests not applicable", _ms(t0))
        else:
            # URL scan: one live session provides tools/list (enumeration +
            # static-analysis input) and the probe run.
            safety = SafetyController.from_settings(
                dynamic_enabled=True, safe_mode=scan.safe_mode, allow_local=scan.allow_local_targets
            )
            dyn_scanner = DynamicScanner(scan.target_identifier, safety, scan_id)
            dyn_result = await dyn_scanner.run()
            dynamic_result["tests"] = [
                {
                    "test_id": t.test_id, "test_name": t.test_name, "tool_name": t.tool_name,
                    "status": t.status, "detail": t.detail, "evidence": t.evidence,
                    "duration_ms": t.duration_ms,
                }
                for t in dyn_result.tests
            ]
            dynamic_result["findings"] = dyn_result.findings
            dynamic_result["connection_error"] = dyn_result.connection_error
            dynamic_result["safety_summary"] = dyn_result.safety_summary

            # enumeration for URL scans: reflect live tools into the inventory
            # and run static analysis over the live metadata
            if dyn_result.tools_enumerated:
                live_target = normalize_target({"tools": dyn_result.tools_metadata})
                tool_dicts = [
                    {
                        "name": t.name, "description": t.description, "input_schema": t.input_schema,
                        "annotations": t.annotations, "capabilities": infer_tool_capabilities(t),
                    }
                    for t in live_target.tools
                ]
                await self.repo.save_tools(scan_id, tool_dicts)
                await self._stage_done(scan_id, 2, f"{len(tool_dicts)} tool(s) enumerated live", _ms(t0))
                await self._stage(scan_id, 3)
                t_static = time.perf_counter()
                static_findings, analyzer_statuses = run_static_analysis(live_target, scan_id)
                static_dicts = [f.to_dict() for f in static_findings]
                await self._stage_done(scan_id, 3, f"{len(static_dicts)} static finding(s) from live metadata", _ms(t_static))
            else:
                tool_dicts = []
                await self._stage_done(scan_id, 2, "no tools enumerated (connection failure)", _ms(t0), level="warning")

            executed = sum(1 for t in dynamic_result["tests"] if t["status"] in ("passed", "failed"))
            await self._stage_done(
                scan_id, 4,
                f"Dynamic: {executed} probe(s) executed, {len(dynamic_result['findings'])} finding(s)"
                + (f"; connection issue: {dyn_result.connection_error[:120]}" if dyn_result.connection_error else ""),
                _ms(t0),
                level="warning" if dyn_result.connection_error else "info",
            )

        # ---- Stage 5: semantic analysis -----------------------------------
        await self._stage(scan_id, 5)
        t0 = time.perf_counter()
        # provisional findings for semantic review (fused view happens later)
        preliminary = fuse_findings(static_dicts + dynamic_result["findings"])
        semantic_result = await run_semantic_analysis(preliminary, tool_dicts)
        await self._stage_done(
            scan_id, 5,
            f"Semantic analysis {semantic_result.status}"
            + (f": {semantic_result.reason[:150]}" if semantic_result.reason else ""),
            _ms(t0),
            level="info" if semantic_result.status == "completed" else "warning",
        )
        # semantic detail is persisted with the scan in stage 7

        # ---- Stage 6: risk aggregation --------------------------------------
        await self._stage(scan_id, 6)
        t0 = time.perf_counter()
        fused = fuse_findings(static_dicts + dynamic_result["findings"])
        # attach semantic stances to matching findings (annotation only; never overrides)
        if semantic_result.status == "completed":
            by_rule = {obs.rule_id: obs for obs in semantic_result.observations if obs.rule_id}
            for f in fused:
                obs = by_rule.get(str(f.get("rule_id")))
                if obs:
                    f.setdefault("semantic_review", {"stance": obs.stance, "note": obs.note, "provider": obs.provider})
        safety_summary = dynamic_result.get("safety_summary") or {}
        risk = compute_risk(fused, safety_summary or None)
        await self._stage_done(scan_id, 6, f"Risk score {risk['total']}/100 ({risk['band']})", _ms(t0))

        # ---- Stage 7: report generation (persist everything) -----------------
        await self._stage(scan_id, 7)
        t0 = time.perf_counter()
        await self.repo.save_findings(scan_id, fused)
        await self.repo.save_tests(scan_id, dynamic_result["tests"])
        ml_status = await _ml_status_for(fused, tool_dicts)
        # Fingerprint covers the analyzed content: parsed metadata for config
        # scans, the live-enumerated tool inventory for URL scans.
        if is_url_scan:
            fingerprint = target_fingerprint(normalize_target({"tools": tool_dicts}))
        else:
            assert target is not None
            fingerprint = target_fingerprint(target)
        # Persist semantic detail + fingerprint into the config snapshot so the
        # report builder (which reads them from there) renders real values.
        snapshot_update = dict(scan.config_snapshot or {})
        snapshot_update.update(
            {
                "target_fingerprint": fingerprint,
                "semantic_provider": semantic_result.provider,
                "semantic_reason": semantic_result.reason,
                "semantic_general_notes": semantic_result.general_notes,
                "semantic_observations": [vars(o) for o in semantic_result.observations],
                "analyzer_statuses": analyzer_statuses,
                "ml_detail": ml_status,
            }
        )
        await self.repo.update_scan(
            scan_id,
            risk_score=float(risk["total"]),
            risk_breakdown=risk,
            semantic_status=semantic_result.status,
            ml_status=ml_status.get("status", "unavailable"),
            ml_model_version=ml_status.get("model_version"),
            config_snapshot=snapshot_update,
        )
        await self._stage_done(scan_id, 7, f"{len(fused)} finding(ies) persisted; report available via API", _ms(t0))

        # ---- Stage 8: completed ------------------------------------------------
        await self._stage(scan_id, 8, "Scan completed")
        await self.repo.update_scan(scan_id, status="completed", completed_at=datetime.now(timezone.utc))


def _ms(t0: float) -> int:
    return int((time.perf_counter() - t0) * 1000)


async def _ml_status_for(findings: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict[str, Any]:
    """ML is optional assistance; absence degrades to an honest status."""
    settings = get_settings()
    if not settings.ml_enabled:
        return {"status": "disabled", "note": "ML assistance disabled by configuration"}
    try:
        from backend.ml.predict import predict_for_findings

        return await predict_for_findings(findings, tools)
    except ImportError:
        return {"status": "unavailable", "note": "ML artifacts not trained yet; see ML.md"}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "note": f"ML prediction failed: {type(exc).__name__}"}
