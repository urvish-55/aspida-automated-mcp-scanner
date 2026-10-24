"""Pydantic API schemas: request validation and response serialization.

Rule: the API never trusts client-side validation. Every endpoint input is
re-validated here. Response models deliberately exclude secret material.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
FindingStatus = Literal["confirmed", "suspected", "informational", "not_tested", "not_applicable", "error"]
ScanStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

class ScanCreate(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    target_type: Literal["config", "url"] = "config"
    # Inline MCP config/manifest/serialized tool list (JSON object or array).
    target_config: dict[str, Any] | list[Any] | str | None = None
    server_url: str | None = Field(default=None, max_length=512)
    # Name returned by POST /api/uploads (config scans only). Mutually exclusive with target_config.
    uploaded_file: str | None = Field(default=None, pattern=r"^[0-9a-f]{24}\.json$")

    safe_mode: bool = True
    dynamic_enabled: bool = False
    # Explicit human authorization for dynamic testing.
    authorization_confirmed: bool = False
    authorization_statement: str | None = Field(default=None, max_length=512)
    semantic_enabled: bool = False

    @field_validator("server_url")
    @classmethod
    def _require_url_for_url_mode(cls, v: str | None, info: Any) -> str | None:
        target_type = (info.data or {}).get("target_type", "config")
        if target_type == "url" and not v:
            raise ValueError("server_url is required when target_type is 'url'")
        if v and not v.lower().startswith(("http://", "https://")):
            raise ValueError("server_url must start with http:// or https://")
        return v

    @model_validator(mode="after")
    def _dynamic_requires_auth(self) -> "ScanCreate":
        if self.dynamic_enabled and not self.authorization_confirmed:
            raise ValueError(
                "authorization_confirmed must be true when dynamic_enabled is true: "
                "'I confirm that I am authorized to test this MCP server.'"
            )
        return self


class ScanCancel(BaseModel):
    reason: str = Field(default="", max_length=512)


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

class EventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    seq: int
    timestamp: datetime
    stage: str
    event: str
    message: str
    level: str
    progress: float | None = None
    duration_ms: int | None = None


class EvidenceOut(BaseModel):
    kind: str
    summary: str
    detail: dict[str, Any] = Field(default_factory=dict)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    rule_id: str
    category: str
    severity: str
    confidence: str
    status: str
    title: str
    description: str
    evidence: list[EvidenceOut] = []
    affected_tools: list[str] = []
    reproduction: dict[str, Any] = {}
    impact: str
    remediation: str
    references: list[str] = []
    detector_sources: list[str] = []
    # Remediation tracking (stored in finding_triage; defaults apply when never triaged).
    triage_status: str = "open"
    triage_note: str = ""
    triage_updated_at: datetime | None = None


class ToolOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    name: str
    description: str
    input_schema: dict[str, Any] = {}
    annotations: dict[str, Any] = {}
    capabilities: list[str] = []


class DynamicTestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    test_id: str
    test_name: str
    tool_name: str
    status: str
    detail: str
    evidence: dict[str, Any] = {}
    duration_ms: int


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    status: str
    target_label: str
    target_type: str
    target_identifier: str
    safe_mode: bool
    dynamic_enabled: bool
    semantic_enabled: bool
    allow_local_targets: bool = False
    risk_score: float | None
    risk_breakdown: dict[str, Any] | None
    semantic_status: str
    ml_status: str
    error: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    scanner_version: str
    ruleset_version: str
    ml_model_version: str | None


class ScanDetailOut(ScanOut):
    events: list[EventOut] = []
    findings: list[FindingOut] = []
    tools: list[ToolOut] = []
    tests: list[DynamicTestOut] = []


class FindingsPage(BaseModel):
    total: int
    items: list[FindingOut]


class DashboardStats(BaseModel):
    total_scans: int
    scans_completed: int
    scans_failed: int
    high_critical_findings: int
    average_risk_score: float | None
    latest_scan: ScanOut | None
    tools_analyzed: int
    tests_executed: int
    tests_skipped: int
    security_status: str  # derived text, never a fake "secure" claim


class VersionInfo(BaseModel):
    app_name: str
    version: str
    ruleset_version: str
    ml_model_version: str
    scanner_schema_version: str


class HealthInfo(BaseModel):
    status: str
    database: str
    llm_provider: str
    llm_available: bool
    ml_available: bool
    safe_mode_default: bool
    auth_required: bool
    time_utc: str


class ReportMeta(BaseModel):
    scan_id: str
    generated_at: str
    format: str
    size_bytes: int


class PaginatedScans(BaseModel):
    total: int
    items: list[ScanOut]
