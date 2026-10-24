import type { Analysis, Event, Finding, ScanDetail, Severity, Tool } from "../types";

export function finding(id: string, severity: Severity, tools: string[], over: Partial<Finding> = {}): Finding {
  return {
    id, rule_id: `R-${id}`, category: "tool_poisoning", severity, confidence: "high", status: "suspected", title: `Finding ${id}`,
    description: "d", evidence: [], affected_tools: tools, reproduction: {}, impact: "", remediation: "", references: [],
    detector_sources: [`R-${id}`], triage_status: "open", triage_note: "", triage_updated_at: null, ...over,
  };
}
export const tool = (name: string, capabilities: string[] = []): Tool => ({ name, description: "", input_schema: {}, annotations: {}, capabilities });

export function scan(over: Partial<ScanDetail> = {}): ScanDetail {
  return {
    id: "scan-1", status: "completed", target_label: "demo-server", target_type: "config", target_identifier: "x", safe_mode: true,
    dynamic_enabled: false, semantic_enabled: false, allow_local_targets: false, risk_score: 40, risk_breakdown: null,
    semantic_status: "skipped", ml_status: "skipped", error: null, created_at: "2026-01-01T00:00:00Z", started_at: null, completed_at: null,
    scanner_version: "1", ruleset_version: "1", ml_model_version: null, events: [], findings: [], tools: [], tests: [], ...over,
  };
}
export const analysis = (over: Partial<Analysis> = {}): Analysis => ({
  scan_id: "scan-1", exposure_note: "", tools: [], heatmap: { columns: [], rows: [] }, graph: { nodes: [], edges: [] }, attack_paths: [], ...over,
});
export const event = (seq: number, stage: string, over: Partial<Event> = {}): Event => ({
  seq, timestamp: "2026-01-01T00:00:00Z", stage, event: "stage_started", message: `${stage} msg`, level: "info", progress: null, duration_ms: null, ...over,
});
