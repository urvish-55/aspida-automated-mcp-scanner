"""ScanRepository: all DB access for scans (keeps API and pipeline code free
of raw session management). Async throughout; SQLite via aiosqlite.

Idiom note: always write ``(await session.execute(q)).scalars().all()`` —
chaining onto an awaited coroutine without the inner parentheses is a
precedence bug, not a style choice.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from backend.models.db import DynamicTest, Finding, FindingTriage, Scan, ScanEvent, ToolRecord


class ScanRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._factory = session_factory

    # ------------------------------------------------------------------ scans
    async def create_scan(self, **kwargs: Any) -> Scan:
        async with self._factory() as session:
            scan = Scan(**kwargs)
            session.add(scan)
            await session.commit()
            await session.refresh(scan)
            return scan

    async def get_scan(self, scan_id: str) -> Scan | None:
        async with self._factory() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            return result.scalar_one_or_none()

    async def list_scans(self, *, limit: int = 50, offset: int = 0) -> tuple[int, list[Scan]]:
        async with self._factory() as session:
            total_result = await session.execute(select(func.count(Scan.id)))
            total = int(total_result.scalar_one())
            rows_result = await session.execute(
                select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
            )
            rows = rows_result.scalars().all()
            return total, list(rows)

    async def update_scan(self, scan_id: str, **updates: Any) -> Scan | None:
        async with self._factory() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                return None
            for key, value in updates.items():
                setattr(scan, key, value)
            await session.commit()
            await session.refresh(scan)
            return scan

    async def delete_scan(self, scan_id: str) -> bool:
        async with self._factory() as session:
            result = await session.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if scan is None:
                return False
            await session.execute(delete(FindingTriage).where(FindingTriage.scan_id == scan_id))
            await session.delete(scan)
            await session.commit()
            return True

    # ----------------------------------------------------------------- events
    async def add_event(
        self,
        scan_id: str,
        *,
        stage: str,
        event: str,
        message: str = "",
        level: str = "info",
        progress: float | None = None,
        duration_ms: int | None = None,
    ) -> ScanEvent:
        async with self._factory() as session:
            seq_result = await session.execute(
                select(func.coalesce(func.max(ScanEvent.seq), 0)).where(ScanEvent.scan_id == scan_id)
            )
            seq = int(seq_result.scalar_one()) + 1
            ev = ScanEvent(
                scan_id=scan_id,
                seq=seq,
                stage=stage,
                event=event,
                message=message[:2000],
                level=level,
                progress=progress,
                duration_ms=duration_ms,
            )
            session.add(ev)
            await session.commit()
            await session.refresh(ev)
            return ev

    async def list_events(self, scan_id: str, *, after_seq: int = 0) -> list[ScanEvent]:
        async with self._factory() as session:
            rows_result = await session.execute(
                select(ScanEvent)
                .where(ScanEvent.scan_id == scan_id, ScanEvent.seq > after_seq)
                .order_by(ScanEvent.seq)
            )
            return list(rows_result.scalars().all())

    # --------------------------------------------------------------- results
    async def save_tools(self, scan_id: str, tools: list[dict[str, Any]]) -> None:
        async with self._factory() as session:
            await session.execute(delete(ToolRecord).where(ToolRecord.scan_id == scan_id))
            for i, t in enumerate(tools):
                session.add(
                    ToolRecord(
                        scan_id=scan_id,
                        name=str(t.get("name", ""))[:256],
                        description=str(t.get("description", "")),
                        input_schema=t.get("input_schema") or {},
                        annotations=t.get("annotations") or {},
                        capabilities=t.get("capabilities") or [],
                        raw_index=i,
                    )
                )
            await session.commit()

    async def save_findings(self, scan_id: str, findings: list[dict[str, Any]]) -> None:
        async with self._factory() as session:
            await session.execute(delete(Finding).where(Finding.scan_id == scan_id))
            for f in findings:
                session.add(
                    Finding(
                        scan_id=scan_id,
                        rule_id=str(f.get("rule_id", ""))[:64],
                        category=str(f.get("category", ""))[:64],
                        severity=str(f.get("severity", "info")),
                        severity_rank=_severity_rank(f.get("severity", "info")),
                        confidence=str(f.get("confidence", "medium")),
                        status=str(f.get("status", "suspected")),
                        title=str(f.get("title", ""))[:512],
                        description=str(f.get("description", "")),
                        evidence=f.get("evidence") or [],
                        affected_tools=f.get("affected_tools") or [],
                        reproduction=f.get("reproduction") or {},
                        impact=str(f.get("impact", "")),
                        remediation=str(f.get("remediation", "")),
                        references=f.get("references") or [],
                        detector_sources=f.get("detector_sources") or [],
                    )
                )
            await session.commit()

    async def save_tests(self, scan_id: str, tests: list[dict[str, Any]]) -> None:
        async with self._factory() as session:
            await session.execute(delete(DynamicTest).where(DynamicTest.scan_id == scan_id))
            for t in tests:
                session.add(
                    DynamicTest(
                        scan_id=scan_id,
                        test_id=str(t.get("test_id", ""))[:64],
                        test_name=str(t.get("test_name", ""))[:256],
                        tool_name=str(t.get("tool_name", ""))[:256],
                        status=str(t.get("status", "pending")),
                        detail=str(t.get("detail", "")),
                        evidence=t.get("evidence") or {},
                        duration_ms=int(t.get("duration_ms", 0)),
                    )
                )
            await session.commit()

    async def get_findings(self, scan_id: str) -> list[Finding]:
        async with self._factory() as session:
            result = await session.execute(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .order_by(Finding.severity_rank.desc(), Finding.rule_id)
            )
            return list(result.scalars().all())

    async def get_tools(self, scan_id: str) -> list[ToolRecord]:
        async with self._factory() as session:
            result = await session.execute(
                select(ToolRecord).where(ToolRecord.scan_id == scan_id).order_by(ToolRecord.raw_index)
            )
            return list(result.scalars().all())

    async def get_tests(self, scan_id: str) -> list[DynamicTest]:
        async with self._factory() as session:
            result = await session.execute(
                select(DynamicTest).where(DynamicTest.scan_id == scan_id).order_by(DynamicTest.id)
            )
            return list(result.scalars().all())

    # ----------------------------------------------------------- triage / lookup
    async def get_triage_map(self, scan_id: str | None = None) -> dict[str, FindingTriage]:
        async with self._factory() as session:
            q = select(FindingTriage)
            if scan_id:
                q = q.where(FindingTriage.scan_id == scan_id)
            rows = (await session.execute(q)).scalars().all()
            return {r.finding_id: r for r in rows}

    async def set_triage(self, finding_id: str, status: str, note: str) -> FindingTriage | None:
        from datetime import datetime, timezone

        async with self._factory() as session:
            finding = (await session.execute(select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()
            if finding is None:
                return None
            row = (await session.execute(select(FindingTriage).where(FindingTriage.finding_id == finding_id))).scalar_one_or_none()
            if row is None:
                row = FindingTriage(finding_id=finding_id, scan_id=finding.scan_id)
                session.add(row)
            row.status = status
            row.note = note
            row.updated_at = datetime.now(timezone.utc)
            await session.commit()
            await session.refresh(row)
            return row

    async def get_finding(self, finding_id: str) -> Finding | None:
        async with self._factory() as session:
            return (await session.execute(select(Finding).where(Finding.id == finding_id))).scalar_one_or_none()

    async def all_findings(self, scan_id: str | None = None) -> list[tuple[Finding, Scan]]:
        async with self._factory() as session:
            q = select(Finding, Scan).join(Scan, Scan.id == Finding.scan_id)
            if scan_id:
                q = q.where(Finding.scan_id == scan_id)
            q = q.order_by(Finding.severity_rank.desc(), Scan.created_at.desc())
            return [(f, s) for f, s in (await session.execute(q)).all()]

    # ------------------------------------------------------------------ stats
    async def dashboard_stats(self) -> dict[str, Any]:
        async with self._factory() as session:
            async def count(model, *filters):  # type: ignore[no-untyped-def]
                q = select(func.count(model.id))
                for f in filters:
                    q = q.where(f)
                r = await session.execute(q)
                return int(r.scalar_one())

            total_scans = await count(Scan)
            completed = await count(Scan, Scan.status == "completed")
            failed = await count(Scan, Scan.status == "failed")

            avg_result = await session.execute(
                select(func.avg(Scan.risk_score)).where(Scan.status == "completed")
            )
            avg_risk = avg_result.scalar_one()

            latest_result = await session.execute(
                select(Scan).order_by(Scan.created_at.desc()).limit(1)
            )
            latest = latest_result.scalar_one_or_none()

            high_crit = await count(
                Finding,
                Finding.severity.in_(["high", "critical"]),
                Finding.status.in_(["confirmed", "suspected"]),
            )
            tools_analyzed = await count(ToolRecord)
            tests_executed = await count(DynamicTest, DynamicTest.status.in_(["passed", "failed"]))
            tests_skipped = await count(DynamicTest, DynamicTest.status == "skipped")

            return {
                "total_scans": total_scans,
                "scans_completed": completed,
                "scans_failed": failed,
                "high_critical_findings": high_crit,
                "average_risk_score": round(float(avg_risk), 1) if avg_risk is not None else None,
                "latest_scan": latest,
                "tools_analyzed": tools_analyzed,
                "tests_executed": tests_executed,
                "tests_skipped": tests_skipped,
            }


def _severity_rank(severity: str) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get(severity, 0)


def scan_to_dict(scan: Scan) -> dict[str, Any]:
    return {
        "id": scan.id,
        "status": scan.status,
        "target_label": scan.target_label,
        "target_type": scan.target_type,
        "target_identifier": scan.target_identifier,
        "safe_mode": scan.safe_mode,
        "dynamic_enabled": scan.dynamic_enabled,
        "semantic_enabled": scan.semantic_enabled,
        "authorization_confirmed": scan.authorization_confirmed,
        "risk_score": scan.risk_score,
        "risk_breakdown": scan.risk_breakdown,
        "semantic_status": scan.semantic_status,
        "ml_status": scan.ml_status,
        "error": scan.error,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "scanner_version": scan.scanner_version,
        "ruleset_version": scan.ruleset_version,
        "ml_model_version": scan.ml_model_version,
        "config_snapshot": scan.config_snapshot or {},
    }
