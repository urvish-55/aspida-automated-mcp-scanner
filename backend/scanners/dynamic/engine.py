"""DynamicScanner orchestrator: enumerate tools on the live server, generate
inert probes, execute them under the SafetyController, analyze responses, and
produce evidence-backed dynamic findings.

Design rules:
- Static findings from config mode are NOT re-derived here; the pipeline fuses.
- A single failing probe becomes an error test result, never a scan failure.
- Test outcomes preserve skipped/error/not_applicable states honestly.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from backend.core.config import get_settings
from backend.core.logging import get_scan_logger
from backend.scanners.dynamic.connector import MCPConnector, MCPConnectionError
from backend.scanners.dynamic.probes import ProbeGenerator
from backend.scanners.dynamic.response_analyzer import ProbeOutcome, ResponseAnalyzer
from backend.scanners.dynamic.safety import SafetyController, SafetyViolation, ScanCancelled


@dataclass
class DynamicTestRecord:
    test_id: str
    test_name: str
    tool_name: str
    status: str  # passed|failed|skipped|error|not_applicable|timeout
    detail: str
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


@dataclass
class DynamicResult:
    tools_enumerated: list[str] = field(default_factory=list)
    # full live definitions (name, description, inputSchema, annotations) so static analysis sees real metadata
    tools_metadata: list[dict[str, Any]] = field(default_factory=list)
    tests: list[DynamicTestRecord] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    connection_error: str = ""
    safety_summary: dict[str, Any] = field(default_factory=dict)


# Stable rule-id prefixes per probe family (used by fusion topic mapping).
FAMILY_PREFIX: dict[str, str] = {
    "path_traversal": "PATH",
    "command_injection": "CMDI",
    "oversized": "OVER",
    "malformed": "MALF",
    "schema_violation": "VIOL",
}


def _finding_from_outcome(outcome: ProbeOutcome, scan_id: str) -> dict[str, Any]:
    p = outcome.probe
    return {
        "rule_id": f"DYN-{FAMILY_PREFIX.get(p.family, p.family.upper()[:4])}-001",
        "category": f"dynamic_{p.family}",
        "severity": outcome.severity,
        "title": outcome.title,
        "description": f"{outcome.probe.rationale} {outcome.note}".strip(),
        "status": "confirmed",
        "confidence": "high",
        "evidence": [
            {
                "kind": "dynamic_probe",
                "summary": outcome.title,
                "detail": outcome.evidence_detail,
            }
        ],
        "affected_tools": [p.tool_name],
        "impact": (
            "Dynamically confirmed against the live target under safe-mode constraints "
            "(inert payloads only). See reproduction for the exact request."
        ),
        "remediation": (
            "Validate and constrain the affected parameter server-side; see the matched "
            "family's recommendation in the report body."
        ),
        "reproduction": {
            "type": "dynamic",
            "tool": p.tool_name,
            "arguments": p.arguments,
            "test_id": p.test_id,
            "note": "Reproduce only against targets you are authorized to test.",
        },
        "references": ["OWASP LLM06 - Excessive Agency / SSRF & injection families"],
    }


class DynamicScanner:
    def __init__(self, url: str, safety: SafetyController, scan_id: str) -> None:
        self.url = url
        self.safety = safety
        self.scan_id = scan_id
        self.log = get_scan_logger(scan_id, "dynamic_testing")
        self.analyzer = ResponseAnalyzer()
        self.generator = ProbeGenerator()

    async def run(self) -> DynamicResult:
        result = DynamicResult()
        settings = get_settings()
        try:
            async with MCPConnector(self.url, timeout=settings.per_test_timeout_seconds * 2, allow_local=self.safety.allow_local) as conn:
                await self._run_with(conn, result)
        except ScanCancelled:
            raise
        except Exception as exc:  # connection-level failure: record honestly
            self.log.error(f"dynamic scan connection failed: {type(exc).__name__}")
            result.connection_error = f"{type(exc).__name__}: {exc}"
            result.tests.append(
                DynamicTestRecord(
                    test_id="DYN-CONN-000",
                    test_name="MCP server connection",
                    tool_name="",
                    status="error",
                    detail=f"Could not connect/initialize: {result.connection_error}",
                )
            )
        result.safety_summary = self.safety.audit_summary()
        return result

    async def _run_with(self, conn: MCPConnector, result: DynamicResult) -> None:
        try:
            await self.safety.run_with_timeout(conn.initialize(), test_id="init")
            tools = await self.safety.run_with_timeout(conn.list_tools(), test_id="tools_list")
        except (SafetyViolation, ScanCancelled) as raise_or_not:
            if isinstance(raise_or_not, ScanCancelled):
                raise
            result.tests.append(
                DynamicTestRecord(
                    test_id="DYN-CONN-000", test_name="MCP server connection", tool_name="",
                    status="error", detail=str(raise_or_not),
                )
            )
            return
        except MCPConnectionError as exc:
            result.tests.append(
                DynamicTestRecord(
                    test_id="DYN-CONN-000", test_name="MCP server connection", tool_name="",
                    status="error", detail=f"Handshake failed: {exc}",
                )
            )
            return

        result.tools_enumerated = [t.name for t in tools]
        result.tools_metadata = [
            {"name": t.name, "description": t.description, "inputSchema": t.input_schema, "annotations": t.annotations}
            for t in tools
        ]
        self.log.info(f"enumerated {len(tools)} tools on live target")

        for tool in tools:
            if self.safety.budget_remaining <= 0:
                result.tests.append(
                    DynamicTestRecord(
                        test_id="DYN-BUDGET-000", test_name="Probe budget", tool_name=tool.name,
                        status="skipped",
                        detail=f"Request budget exhausted before tool '{tool.name}' was probed.",
                    )
                )
                continue

            probes = self.generator.probes_for_tool(tool, max_payload_bytes=self.safety.max_payload_bytes)
            for probe in probes:
                if self.safety.budget_remaining <= 0:
                    result.tests.append(
                        DynamicTestRecord(
                            test_id=probe.test_id, test_name=probe.test_name, tool_name=tool.name,
                            status="skipped",
                            detail="Request budget exhausted; probe not sent.",
                        )
                    )
                    continue
                try:
                    self.safety.raise_if_cancelled()
                    await self.safety.check_and_reserve(
                        test_id=probe.test_id, tool=tool.name, payload_size=probe.payload_size
                    )
                    started = time.perf_counter()
                    call = await self.safety.run_with_timeout(
                        conn.call_tool(probe.tool_name, probe.arguments), test_id=probe.test_id
                    )
                    duration_ms = int((time.perf_counter() - started) * 1000)
                    outcome = self.analyzer.analyze(probe, call)
                    status_map = {"finding": "failed", "passed": "passed", "error": "error", "ambiguous": "error"}
                    result.tests.append(
                        DynamicTestRecord(
                            test_id=probe.test_id,
                            test_name=probe.test_name,
                            tool_name=tool.name,
                            status=status_map[outcome.verdict],
                            detail=outcome.note or outcome.title,
                            evidence=outcome.evidence_detail,
                            duration_ms=duration_ms,
                        )
                    )
                    if outcome.verdict == "finding":
                        result.findings.append(_finding_from_outcome(outcome, self.scan_id))
                except SafetyViolation as exc:
                    result.tests.append(
                        DynamicTestRecord(
                            test_id=probe.test_id, test_name=probe.test_name, tool_name=tool.name,
                            status="skipped", detail=f"Safety controller refused probe: {exc}",
                        )
                    )
                except ScanCancelled:
                    raise
                except Exception as exc:  # noqa: BLE001 - one probe must not kill the scan
                    self.log.error(f"probe {probe.test_id} crashed: {type(exc).__name__}")
                    result.tests.append(
                        DynamicTestRecord(
                            test_id=probe.test_id, test_name=probe.test_name, tool_name=tool.name,
                            status="error", detail=f"Probe crashed: {type(exc).__name__}: {exc}",
                        )
                    )
