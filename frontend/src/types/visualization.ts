/** Data contracts for the 3D investigation views. Everything here is derived from backend responses. */
import type { Severity } from "../types";

export type NodeKind = "server" | "tool" | "capability" | "finding" | "resource";
export type SeverityOrNone = Severity | "none";

export interface SceneNode {
  id: string;
  kind: NodeKind;
  label: string;
  level: SeverityOrNone;
  /** Backend-supplied counts shown in the inspector; undefined when the backend does not provide them. */
  findingCount?: number;
  toolCount?: number;
  /** For finding nodes: the stored finding id / category / rule. */
  findingId?: string;
  category?: string;
  ruleId?: string;
  /** For tool nodes: the capability ids; for capability nodes: the raw capability id. */
  capabilities?: string[];
  capabilityId?: string;
  /** Tools this finding affects (finding nodes). */
  tools?: string[];
  /** Attack-path ids this node participates in (from the backend analysis). */
  pathIds: string[];
}

export interface SceneEdge {
  id: string;
  source: string;
  target: string;
  verb: string;
  /** Edge participates in an attack path (both endpoints belong to the same path). */
  pathIds: string[];
}

export interface SecurityGraph {
  scanId: string;
  nodes: SceneNode[];
  edges: SceneEdge[];
  /** Honest notes about what this graph does not contain. */
  notes: string[];
}

export type VizMode = "graph" | "paths" | "galaxy" | "capabilities" | "terrain" | "scan";
export const VIZ_MODES: { id: VizMode; label: string; hint: string }[] = [
  { id: "graph", label: "Security Graph", hint: "Server, tools, capabilities and findings" },
  { id: "paths", label: "Attack Paths", hint: "Evidence-backed candidate chains" },
  { id: "galaxy", label: "Threat Galaxy", hint: "Findings clustered by category" },
  { id: "capabilities", label: "Capability Network", hint: "Which tools reach which capabilities" },
  { id: "terrain", label: "Risk Terrain", hint: "Scored risk points per category" },
  { id: "scan", label: "Scan Mode", hint: "Live pipeline state from backend events" },
];

export type QualityPref = "auto" | "low" | "medium" | "high";
export type EffectsPref = "full" | "reduced" | "off";

export interface GraphFilters {
  severities: Severity[];
  kinds: NodeKind[];
  categories: string[]; // empty = all
  query: string;
}

export const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const DEFAULT_KINDS: NodeKind[] = ["server", "tool", "capability", "finding"];

export type StageState = "pending" | "active" | "done" | "failed";
export interface ScanStageView {
  id: string;
  label: string;
  state: StageState;
  /** Last real backend event message for this stage, if any. */
  message: string | null;
  durationMs: number | null;
}
