/**
 * Story data: everything the narrative shows, derived from stored scan data.
 * With no scan it returns an explicitly labelled illustrative example; nothing here is ever presented as a real scan result unless source === "scan".
 */
import type { Analysis, AttackPath, Finding, ScanDetail, Severity } from "../types";
import { SEV_RANK } from "./severity";
import { riskBand } from "./utils";
import { capLabel, buildSecurityGraph } from "./securityGraph";
import { hasHiddenChars } from "./safeText";

export type VerifyState = "resolved" | "still_present" | "not_verified";
export interface StoryStats {
  tools: number; networkTools: number; filesystemTools: number; shellTools: number; credentialTools: number;
  findings: number; bySeverity: Record<Severity, number>; paths: number; riskScore: number | null; band: string;
}
export interface StoryData {
  source: "scan" | "demo";
  scan: ScanDetail;
  analysis: Analysis | undefined;
  stats: StoryStats;
  topFinding: Finding | null;
  topPath: AttackPath | null;
  hiddenCharTool: { name: string; text: string } | null;
  testSummary: { name: string; passed: number; failed: number; other: number }[];
  /** The finding being verified: the earlier scan's top finding when a re-scan exists. */
  verifyFinding: Finding | null;
  verify: { state: VerifyState; detail: string };
  riskParts: { label: string; points: number | null; cap: number | null }[];
}

const SEVS: Severity[] = ["critical", "high", "medium", "low", "info"];
const evidenceFindings = (fs: Finding[]) => fs.filter((f) => f.status !== "informational" && f.category !== "engine" && !["not_tested", "not_applicable", "error"].includes(f.status));

export function topFindingOf(fs: Finding[]): Finding | null {
  return [...evidenceFindings(fs)].sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity] || (a.status === "confirmed" ? -1 : 1) - (b.status === "confirmed" ? -1 : 1))[0] ?? null;
}
export const topPathOf = (a: Analysis | undefined): AttackPath | null =>
  [...(a?.attack_paths ?? [])].sort((x, y) => y.evidence_ratio - x.evidence_ratio || y.nodes.length - x.nodes.length)[0] ?? null;

const findingKey = (f: Finding) => `${f.rule_id}|${[...f.affected_tools].sort().join(",")}`;

/**
 * Verification is only ever as strong as the backend data. `finding` is a finding reported by the EARLIER scan; the later scan
 * either still contains it (same rule + tool), or does not. Absence alone is never called "resolved".
 */
export function verifyState(finding: Finding | null, previous: ScanDetail | null | undefined, current: ScanDetail): { state: VerifyState; detail: string } {
  if (!finding) return { state: "not_verified", detail: "There is no finding to verify." };
  if (!previous) return { state: "not_verified", detail: "No earlier scan of this target exists, so there is nothing to compare. Fix the issue, then run a second scan to verify." };
  if (current.findings.some((f) => findingKey(f) === findingKey(finding))) return { state: "still_present", detail: "The same finding (rule and tool) is present in the latest scan." };
  return finding.triage_status === "resolved"
    ? { state: "resolved", detail: "Not detected in the latest scan, and it is marked resolved in remediation tracking." }
    : { state: "not_verified", detail: "Not detected in the latest scan, but it is not marked resolved. The scan may have changed, so this is not confirmed as fixed." };
}

export function buildStoryData(scan: ScanDetail, analysis: Analysis | undefined, source: "scan" | "demo", previous?: ScanDetail | null): StoryData {
  const fs = evidenceFindings(scan.findings);
  const caps = (c: string) => scan.tools.filter((t) => t.capabilities.includes(c)).length;
  const bySeverity = Object.fromEntries(SEVS.map((s) => [s, fs.filter((f) => f.severity === s).length])) as Record<Severity, number>;
  const top = topFindingOf(scan.findings);
  const hidden = scan.tools.find((t) => hasHiddenChars(`${t.name}\n${t.description}`));
  const byName = new Map<string, { passed: number; failed: number; other: number }>();
  for (const t of scan.tests) {
    const e = byName.get(t.test_name) ?? { passed: 0, failed: 0, other: 0 };
    if (t.status === "passed") e.passed++; else if (t.status === "failed") e.failed++; else e.other++;
    byName.set(t.test_name, e);
  }
  const rb = scan.risk_breakdown as Record<string, { subtotal?: number; cap?: number; adjustment_points?: number } | undefined> | null;
  const part = (label: string, k: string) => ({ label, points: rb?.[k]?.subtotal ?? rb?.[k]?.adjustment_points ?? null, cap: rb?.[k]?.cap ?? null });
  return {
    source, scan, analysis,
    stats: {
      tools: scan.tools.length, networkTools: caps("network_access"), filesystemTools: caps("filesystem_read") + caps("filesystem_write") - scan.tools.filter((t) => t.capabilities.includes("filesystem_read") && t.capabilities.includes("filesystem_write")).length,
      shellTools: caps("shell_execution"), credentialTools: caps("credential_access"),
      findings: fs.length, bySeverity, paths: analysis?.attack_paths.length ?? 0, riskScore: scan.risk_score, band: riskBand(scan.risk_score).label,
    },
    topFinding: top, topPath: topPathOf(analysis),
    hiddenCharTool: hidden ? { name: hidden.name, text: `${hidden.name}\n${hidden.description}` } : null,
    testSummary: [...byName].map(([name, v]) => ({ name, ...v })),
    verifyFinding: previous ? topFindingOf(previous.findings) : top,
    verify: verifyState(previous ? topFindingOf(previous.findings) : top, previous, scan),
    riskParts: [part("Static findings", "static"), part("Dynamic confirmed", "dynamic"), part("Capability exposure", "capability"), part("Confidence adjustment", "confidence_adjustment")],
  };
}

export { capLabel, buildSecurityGraph };

/** Clearly labelled illustrative environment for visitors with no scan yet. Never shown as scan data. */
export function demoScan(): ScanDetail {
  const tool = (name: string, description: string, capabilities: string[]) => ({ name, description, input_schema: {}, annotations: {}, capabilities });
  const finding: Finding = {
    id: "demo-1", rule_id: "ILLUSTRATIVE", category: "tool_poisoning", severity: "high", confidence: "medium", status: "suspected",
    title: "Illustrative example: agent-directed instruction in a tool description", description: "This is an example shape of a finding. It is not from a scan.",
    evidence: [{ kind: "illustrative", summary: "Example evidence block", detail: { note: "Illustrative example, not scan data" } }], affected_tools: ["read_file"], reproduction: {},
    impact: "Example only.", remediation: "Example only: remove agent-directed instructions from tool descriptions.", references: [], detector_sources: ["ILLUSTRATIVE"],
    triage_status: "open", triage_note: "", triage_updated_at: null,
  };
  return {
    id: "demo", status: "completed", target_label: "Illustrative example", target_type: "demo", target_identifier: "demo", safe_mode: true, dynamic_enabled: false, semantic_enabled: false,
    allow_local_targets: false, risk_score: null, risk_breakdown: null, semantic_status: "skipped", ml_status: "skipped", error: null, created_at: new Date(0).toISOString(), started_at: null, completed_at: null,
    scanner_version: "", ruleset_version: "", ml_model_version: null, events: [], tests: [], findings: [finding],
    tools: [tool("read_file", "Example tool", ["filesystem_read"]), tool("fetch_url", "Example tool", ["network_access"]), tool("run_command", "Example tool", ["shell_execution"]), tool("query_db", "Example tool", ["database_access"])],
  };
}
export const demoAnalysis = (): Analysis => ({
  scan_id: "demo", exposure_note: "", tools: [], heatmap: { columns: [], rows: [] }, graph: { nodes: [], edges: [] },
  attack_paths: [{ id: "demo-path", kind: "illustrative", complete: false, label: "Illustrative example path", missing_stages: ["outcome"], confidence: "low", evidence_ratio: 0.5, nodes: [
    { stage: "entry", label: "Entry: tool description", status: "evidenced", tools: ["read_file"], finding_ids: ["demo-1"], evidence: [], confidence: "medium", category: null },
    { stage: "capability", label: "Network capability", status: "potential", tools: ["fetch_url"], finding_ids: [], evidence: [], confidence: null, category: null },
    { stage: "outcome", label: "Possible impact", status: "missing", tools: [], finding_ids: [], evidence: [], confidence: null, category: null },
  ] }],
});
