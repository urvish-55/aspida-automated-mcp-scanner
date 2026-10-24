"""Static scan engine: runs all registered analyzers, catches per-analyzer
errors (a broken analyzer must not abort the scan), and emits an engine-level
diagnostic finding if an analyzer crashed, so the failure is visible in the
report rather than silently swallowed.
"""

from __future__ import annotations

import time

from backend.core.logging import get_scan_logger
from backend.scanners.mcp_ingest import NormalizedTarget
from backend.scanners.static.base import Evidence, StaticAnalyzer, StaticFinding
from backend.scanners.static.capability_analyzer import CapabilityAnalyzer
from backend.scanners.static.collision_analyzer import CollisionAnalyzer
from backend.scanners.static.description_analyzer import DescriptionAnalyzer
from backend.scanners.static.name_analyzer import ToolNameAnalyzer
from backend.scanners.static.schema_analyzer import SchemaAnalyzer
from backend.scanners.static.unicode_analyzer import UnicodeAnalyzer

# Deterministic registration order = deterministic finding order.
ANALYZER_CLASSES: tuple[type[StaticAnalyzer], ...] = (
    UnicodeAnalyzer,
    DescriptionAnalyzer,
    ToolNameAnalyzer,
    SchemaAnalyzer,
    CapabilityAnalyzer,
    CollisionAnalyzer,
)


def get_analyzers() -> list[StaticAnalyzer]:
    return [cls() for cls in ANALYZER_CLASSES]


def run_static_analysis(target: NormalizedTarget, scan_id: str) -> tuple[list[StaticFinding], list[dict]]:
    """Returns (findings, analyzer_status) where analyzer_status records
    executed/errored state per analyzer for the report's limitations section."""
    log = get_scan_logger(scan_id, "static_analysis")
    findings: list[StaticFinding] = []
    statuses: list[dict] = []

    for analyzer in get_analyzers():
        name = type(analyzer).__name__
        started = time.perf_counter()
        try:
            produced = analyzer.analyze(target)
            findings.extend(produced)
            statuses.append(
                {
                    "analyzer": name,
                    "status": "executed",
                    "findings": len(produced),
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                }
            )
            log.debug(f"analyzer {name} produced {len(produced)} findings")
        except Exception as exc:  # noqa: BLE001 - isolation is the point
            statuses.append(
                {
                    "analyzer": name,
                    "status": "error",
                    "error": f"{type(exc).__name__}: {exc}",
                    "duration_ms": int((time.perf_counter() - started) * 1000),
                }
            )
            log.error(f"analyzer {name} failed", extra={"scan_ctx": {"error": str(exc)}})
            findings.append(
                StaticFinding(
                    rule_id="ENGINE-001",
                    category="engine",
                    severity="info",
                    title=f"Analyzer {name} could not complete",
                    description=(
                        f"The {name} analyzer raised {type(exc).__name__} and was skipped. "
                        f"Results are PARTIAL: findings from this analyzer are missing from this "
                        f"scan. This is a scanner limitation, not a property of the target."
                    ),
                    status="error",
                    confidence="high",
                    evidence=[
                        Evidence(
                            kind="engine_error",
                            summary=f"{type(exc).__name__}: {exc}",
                            detail={"analyzer": name, "error": f"{type(exc).__name__}: {exc}"},
                        )
                    ],
                    impact="Coverage gap: the affected analysis was not performed in this scan.",
                    remediation="Check scanner logs and report this as a scanner bug if reproducible.",
                )
            )
    return findings, statuses
