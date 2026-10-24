export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ScanStatus = "queued" | "running" | "completed" | "failed" | "cancelled";

export interface Evidence {
  kind: string;
  summary: string;
  detail: Record<string, unknown>;
}

export interface Finding {
  id: string;
  rule_id: string;
  category: string;
  severity: Severity;
  confidence: string;
  status: string;
  title: string;
  description: string;
  evidence: Evidence[];
  affected_tools: string[];
  reproduction: Record<string, unknown>;
  impact: string;
  remediation: string;
  references: string[];
  detector_sources: string[];
  triage_status: TriageStatus;
  triage_note: string;
  triage_updated_at: string | null;
}

export type TriageStatus = "open" | "acknowledged" | "in_progress" | "resolved" | "false_positive" | "accepted_risk";
export const TRIAGE_LABELS: Record<TriageStatus, string> = {
  open: "Open", acknowledged: "Acknowledged", in_progress: "In progress",
  resolved: "Resolved", false_positive: "False positive", accepted_risk: "Accepted risk",
};

export interface FindingRow extends Finding {
  scan_id: string;
  scan_label: string;
  scan_created_at: string | null;
}
export interface FindingsResponse {
  total: number;
  items: FindingRow[];
  facets: Record<string, Record<string, number>>;
}

export interface Event {
  seq: number;
  timestamp: string;
  stage: string;
  event: string;
  message: string;
  level: string;
  progress: number | null;
  duration_ms: number | null;
}

export interface Tool {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
  annotations: Record<string, unknown>;
  capabilities: string[];
}

export interface DynamicTest {
  test_id: string;
  test_name: string;
  tool_name: string;
  status: string;
  detail: string;
  evidence: Record<string, unknown>;
  duration_ms: number;
}

export interface Scan {
  id: string;
  status: ScanStatus;
  target_label: string;
  target_type: string;
  target_identifier: string;
  safe_mode: boolean;
  dynamic_enabled: boolean;
  semantic_enabled: boolean;
  allow_local_targets: boolean;
  risk_score: number | null;
  risk_breakdown: Record<string, unknown> | null;
  semantic_status: string;
  ml_status: string;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  scanner_version: string;
  ruleset_version: string;
  ml_model_version: string | null;
}

export interface ScanDetail extends Scan {
  events: Event[];
  findings: Finding[];
  tools: Tool[];
  tests: DynamicTest[];
}

export interface DashboardStats {
  total_scans: number;
  scans_completed: number;
  scans_failed: number;
  high_critical_findings: number;
  average_risk_score: number | null;
  latest_scan: Scan | null;
  tools_analyzed: number;
  tests_executed: number;
  tests_skipped: number;
  security_status: string;
}

export interface VersionInfo {
  app_name: string;
  version: string;
  ruleset_version: string;
  ml_model_version: string;
  scanner_schema_version: string;
}

export interface HeatCell { column: string; level: Severity | "none"; evidence: string[]; finding_ids: string[] }
export interface HeatRow { tool: string; cells: HeatCell[] }
export interface ToolExposure {
  name: string; capabilities: string[]; finding_count: number; max_severity: Severity | "none";
  exposure: { score: number; band: string; reasons: { kind: string; label: string; points: number }[] };
}
export interface GraphNode { id: string; kind: "server" | "tool" | "capability"; label: string; level: Severity | "none"; finding_count?: number; tool_count?: number }
export interface GraphEdge { source: string; target: string; verb: string }
export interface PathNode {
  stage: string; label: string; status: "evidenced" | "potential" | "missing";
  tools: string[]; finding_ids: string[]; evidence: string[]; confidence: string | null; category: string | null;
}
export interface AttackPath {
  id: string; kind: string; complete: boolean; label: string; missing_stages: string[];
  confidence: string; evidence_ratio: number; nodes: PathNode[];
}
export interface Analysis {
  scan_id: string; exposure_note: string; tools: ToolExposure[];
  heatmap: { columns: { id: string; label: string }[]; rows: HeatRow[] };
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  attack_paths: AttackPath[];
}
export interface Comparison {
  a: CompareSide; b: CompareSide;
  new_findings: CompareFinding[]; resolved_findings: CompareFinding[];
  changed_severity: (CompareFinding & { from: string; to: string })[];
  tools_added: string[]; tools_removed: string[];
  tools_changed: { name: string; what: string }[];
  capabilities_changed: { name: string; added: string[]; removed: string[] }[];
  note: string;
}
export interface CompareSide { id: string; label: string; created_at: string | null; risk_score: number | null; findings: number; critical: number; high: number; tools: number }
export interface CompareFinding { id: string; rule_id: string; title: string; severity: Severity; affected_tools: string[]; category: string }
export interface SearchResults {
  query: string;
  tools: { total: number; items: { name: string; scan_id: string; capabilities: string[] }[] };
  findings: { total: number; items: { id: string; title: string; severity: Severity; rule_id: string; scan_id: string; tools: string[] }[] };
  scans: { total: number; items: { id: string; label: string; status: string; risk_score: number | null; created_at: string }[] };
  reports: { total: number; items: { scan_id: string; label: string; created_at: string }[] };
}
export interface ActivityItem { timestamp: string; scan_id: string; scan_label: string; stage: string; event: string; level: string; message: string }
export interface NotificationItem { id: string; kind: string; level: string; title: string; message: string; scan_id: string; timestamp: string }
export interface DiscoverResult {
  servers: { name: string; transport: string; url: string }[];
  tools: { name: string; server: string; capabilities: string[] }[];
  tool_count: number; capabilities: Record<string, number>;
  issues: { code: string; message: string; severity: string }[];
  resources: null; prompts: null; note: string;
}
export interface ToolHistory {
  name: string;
  items: { scan_id: string; scan_label: string; created_at: string; finding_count: number; max_severity: string; definition_hash: string; capabilities: string[]; tests: { test_id: string; test_name: string; status: string; detail: string }[] }[];
}
export interface MlInfo {
  available: boolean; reason?: string; runtime_model_version: string;
  model_version?: string; model_type?: string; model_status?: string; usage?: string; trained_at?: string;
  feature_count?: number; features?: string[];
  dataset?: { synthetic?: boolean; total?: number; positive?: number; negative?: number; train_size?: number; test_size?: number; seed?: number; positive_sources?: Record<string, number>; negative_sources?: Record<string, number>; label_quality?: string };
  real_world_training_samples?: number | null; synthetic_share?: number | null;
  test?: { precision: number; recall: number; f1: number; balanced_accuracy: number };
  cv_f1_train?: { mean: number; std: number };
  confusion_matrix_test?: { labels: string[]; matrix: number[][] };
  cross_validation?: { folds: number; roc_auc: number; pr_auc: number; recall_at_fpr_1pct: number; recall_at_fpr_0_1pct: number; length_only_baseline_recall_at_fpr_1pct: number };
  leave_one_template_out_recall?: Record<string, number>;
  independent_evaluation?: { positives: number; negatives: number; recall_at_review_threshold: number | null; hits: number; false_positive_rate: number | null; false_positives: number; note: string; missed: { name: string; source: string; score: number }[] };
  thresholds?: { review: number; high: number; meaning: string };
  caveats?: string[]; input?: string;
  note?: string;
}
export interface SystemHealth {
  overall: "healthy" | "degraded" | "unavailable";
  components: { id: string; label: string; status: "healthy" | "degraded" | "unavailable"; detail: string }[];
  running_scans: string[]; time_utc: string;
}
export interface HealthInfo {
  status: string; llm_provider: string; llm_available: boolean; ml_available: boolean; database: string;
  safe_mode_default: boolean; auth_required: boolean;
}
export interface ReportJson { [k: string]: unknown }

export interface UnicodeChar { index: number; char: string; codepoint: string; name: string; category: string; category_label: string; bidi: string; script: string | null; utf8: string; invisible: boolean; suspicious: string | null }
export interface UnicodeInspection { length: number; suspicious_count: number; summary: Record<string, number>; chars: UnicodeChar[]; note: string }
