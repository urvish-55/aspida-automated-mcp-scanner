"""Domain models (SQLAlchemy 2.0, async SQLite with a PostgreSQL-compatible
design: no SQLite-specific column types, UUIDs stored as strings, JSON stored
as JSON-typed columns).

Schema overview
---------------
scans            one row per scan job (state machine: queued→running→completed/failed/cancelled)
scan_findings    evidence-backed findings (deduplicated across detectors)
scan_tools       tool inventory captured per scan
dynamic_tests    individual dynamic probe outcomes (including skipped/error)
scan_events      audit log / progress events for real-time progress + audit trail
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, JSON, DateTime, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return uuid.uuid4().hex


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    target_label: Mapped[str] = mapped_column(String(256), default="")
    target_type: Mapped[str] = mapped_column(String(16), default="config")  # config|url
    target_identifier: Mapped[str] = mapped_column(String(512), default="")
    source_kind: Mapped[str] = mapped_column(String(16), default="inline")  # inline|file
    source_file: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Configuration actually used (safe defaults enforced server-side).
    safe_mode: Mapped[bool] = mapped_column(Boolean, default=True)
    dynamic_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    semantic_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_local_targets: Mapped[bool] = mapped_column(Boolean, default=False)
    authorization_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)

    # Reproducibility metadata.
    scanner_version: Mapped[str] = mapped_column(String(32), default="")
    ruleset_version: Mapped[str] = mapped_column(String(32), default="")
    ml_model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    config_snapshot: Mapped[dict] = mapped_column(JSON, default=dict)

    # Results.
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_breakdown: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    semantic_status: Mapped[str] = mapped_column(String(16), default="not_run")
    ml_status: Mapped[str] = mapped_column(String(16), default="not_run")

    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", order_by="Finding.severity_rank"
    )
    tools: Mapped[list["ToolRecord"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    tests: Mapped[list["DynamicTest"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    events: Mapped[list["ScanEvent"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    category: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)  # critical|high|medium|low|info
    severity_rank: Mapped[int] = mapped_column(Integer, default=0)  # for ordering
    confidence: Mapped[str] = mapped_column(String(16), default="medium")  # high|medium|low
    status: Mapped[str] = mapped_column(String(16), default="suspected", index=True)
    # confirmed|suspected|informational|not_tested|not_applicable|error

    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[list] = mapped_column(JSON, default=list)
    affected_tools: Mapped[list] = mapped_column(JSON, default=list)
    reproduction: Mapped[dict] = mapped_column(JSON, default=dict)
    impact: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    references: Mapped[list] = mapped_column(JSON, default=list)
    detector_sources: Mapped[list] = mapped_column(JSON, default=list)  # dedup bookkeeping

    scan: Mapped[Scan] = relationship(back_populates="findings")


class ToolRecord(Base):
    __tablename__ = "scan_tools"
    __table_args__ = (Index("ix_scan_tools_scan_name", "scan_id", "name"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(256))
    description: Mapped[str] = mapped_column(Text, default="")
    input_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    annotations: Mapped[dict] = mapped_column(JSON, default=dict)
    capabilities: Mapped[list] = mapped_column(JSON, default=list)  # inferred capability tags
    raw_index: Mapped[int] = mapped_column(Integer, default=0)

    scan: Mapped[Scan] = relationship(back_populates="tools")


class DynamicTest(Base):
    __tablename__ = "dynamic_tests"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)

    test_id: Mapped[str] = mapped_column(String(64), index=True)  # e.g. DYN-PATH-001
    test_name: Mapped[str] = mapped_column(String(256))
    tool_name: Mapped[str] = mapped_column(String(256), default="")
    status: Mapped[str] = mapped_column(String(16), default="pending")
    # passed | failed | skipped | error | not_applicable | timeout
    detail: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)

    scan: Mapped[Scan] = relationship(back_populates="tests")


class ScanEvent(Base):
    __tablename__ = "scan_events"
    __table_args__ = (Index("ix_scan_events_scan_seq", "scan_id", "seq"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    seq: Mapped[int] = mapped_column(Integer, default=0)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    stage: Mapped[str] = mapped_column(String(64))
    event: Mapped[str] = mapped_column(String(64))  # started|progress|warning|error|completed
    message: Mapped[str] = mapped_column(Text, default="")
    level: Mapped[str] = mapped_column(String(16), default="info")
    progress: Mapped[float | None] = mapped_column(Float, nullable=True)  # 0..100 actual
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="events")


TRIAGE_STATUSES = ("open", "acknowledged", "in_progress", "resolved", "false_positive", "accepted_risk")


class FindingTriage(Base):
    """Remediation tracking: operator-set status per finding (spec 62.22).

    Kept in its own table so existing databases pick it up through create_all without an ALTER.
    Rows are removed together with the scan (see ScanRepository.delete_scan).
    """

    __tablename__ = "finding_triage"

    finding_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(32), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
