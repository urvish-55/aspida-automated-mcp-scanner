import type { Analysis, AttackPath, Finding, ScanDetail } from "../types";
import type { GraphFilters, NodeKind, SceneEdge, SceneNode, SecurityGraph, SeverityOrNone } from "../types/visualization";
import { safeLabel } from "./safeText";
import { maxSeverity, SEV_RANK } from "./severity";

const CAP_LABEL: Record<string, string> = {
  shell_execution: "Shell", filesystem_read: "Filesystem (read)", filesystem_write: "Filesystem (write)",
  network_access: "Network", credential_access: "Credentials", database_access: "Database", email_access: "Email",
};
export const capLabel = (c: string) => CAP_LABEL[c] ?? c.replace(/_/g, " ");

export const toolId = (name: string) => `tool:${name}`;
export const capId = (c: string) => `cap:${c}`;
export const findingId = (id: string) => `finding:${id}`;

/**
 * Build the investigation graph from stored scan data + the analysis response.
 * Nodes: one server, tools, capabilities (as reported by the backend), and persisted findings.
 * Resources/prompts are NOT in the graph: the backend does not analyse them.
 */
export function buildSecurityGraph(scan: ScanDetail, analysis: Analysis | undefined): SecurityGraph {
  const nodes = new Map<string, SceneNode>();
  const edges: SceneEdge[] = [];
  const notes: string[] = ["Resources and prompts are not analysed by the backend, so they are not shown."];

  nodes.set("server", { id: "server", kind: "server", label: safeLabel(scan.target_label || "MCP server"), level: "none", pathIds: [] });
  const sevOfTool = new Map<string, SeverityOrNone>();
  const findingsByTool = new Map<string, Finding[]>();
  for (const f of scan.findings) {
    if (f.status === "informational") continue;
    for (const t of f.affected_tools) {
      findingsByTool.set(t, [...(findingsByTool.get(t) ?? []), f]);
    }
  }
  for (const [t, fs] of findingsByTool) sevOfTool.set(t, maxSeverity(fs.map((f) => f.severity)));

  const capCounts = new Map<string, number>();
  for (const t of scan.tools) {
    const fs = findingsByTool.get(t.name) ?? [];
    nodes.set(toolId(t.name), {
      id: toolId(t.name), kind: "tool", label: safeLabel(t.name), level: sevOfTool.get(t.name) ?? "none",
      findingCount: fs.length, capabilities: t.capabilities, pathIds: [],
    });
    edges.push({ id: `e:server>${t.name}`, source: "server", target: toolId(t.name), verb: "exposes", pathIds: [] });
    for (const c of t.capabilities) {
      capCounts.set(c, (capCounts.get(c) ?? 0) + 1);
      edges.push({ id: `e:${t.name}>${c}`, source: toolId(t.name), target: capId(c), verb: "has capability", pathIds: [] });
    }
  }
  // Capability severity: take the backend's own level when the analysis supplies it, else derive from nothing ("none").
  const backendLevel = new Map((analysis?.graph.nodes ?? []).filter((n) => n.kind === "capability").map((n) => [n.id, n.level]));
  for (const [c, n] of capCounts) {
    nodes.set(capId(c), {
      id: capId(c), kind: "capability", label: capLabel(c), level: backendLevel.get(capId(c)) ?? "none",
      toolCount: n, capabilityId: c, pathIds: [],
    });
  }
  for (const f of scan.findings) {
    const id = findingId(f.id);
    nodes.set(id, {
      id, kind: "finding", label: safeLabel(f.title), level: f.severity, findingId: f.id, category: f.category, ruleId: f.rule_id,
      tools: f.affected_tools, pathIds: [],
    });
    const targets = f.affected_tools.filter((t) => nodes.has(toolId(t)));
    if (targets.length === 0) edges.push({ id: `e:${f.id}>server`, source: id, target: "server", verb: "affects scan", pathIds: [] });
    for (const t of targets) edges.push({ id: `e:${f.id}>${t}`, source: id, target: toolId(t), verb: "affects", pathIds: [] });
  }
  if (!scan.tools.length) notes.push("This scan stored no tool definitions, so only the server and findings are shown.");

  annotatePaths(nodes, edges, analysis?.attack_paths ?? []);
  return { scanId: scan.id, nodes: [...nodes.values()], edges, notes };
}

/** Mark the nodes/edges that the backend's attack-path candidates touch. */
export function annotatePaths(nodes: Map<string, SceneNode>, edges: SceneEdge[], paths: AttackPath[]): void {
  for (const p of paths) {
    const ids = new Set<string>();
    for (const n of p.nodes) {
      for (const t of n.tools) ids.add(toolId(t));
      for (const f of n.finding_ids) ids.add(findingId(f));
    }
    for (const id of ids) {
      const node = nodes.get(id);
      if (node && !node.pathIds.includes(p.id)) node.pathIds.push(p.id);
    }
    for (const e of edges) {
      if (ids.has(e.source) && ids.has(e.target) && !e.pathIds.includes(p.id)) e.pathIds.push(p.id);
    }
  }
}

export interface FilteredGraph extends SecurityGraph { hiddenCount: number }

/** Apply filters. Edges survive only if both endpoints survive. The server node is kept whenever tools are shown. */
export function filterGraph(g: SecurityGraph, f: GraphFilters): FilteredGraph {
  const q = f.query.trim().toLowerCase();
  const keepKind = new Set<NodeKind>(f.kinds);
  const nodes = g.nodes.filter((n) => {
    if (!keepKind.has(n.kind)) return false;
    if (n.kind === "finding") {
      if (!f.severities.includes(n.level as never)) return false;
      if (f.categories.length && !f.categories.includes(n.category ?? "")) return false;
    }
    if (q && !n.label.toLowerCase().includes(q) && !(n.ruleId ?? "").toLowerCase().includes(q) && !(n.category ?? "").toLowerCase().includes(q)) {
      return n.kind === "server";
    }
    return true;
  });
  const ids = new Set(nodes.map((n) => n.id));
  const edges = g.edges.filter((e) => ids.has(e.source) && ids.has(e.target));
  return { ...g, nodes, edges, hiddenCount: g.nodes.length - nodes.length };
}

export function neighbours(g: { edges: SceneEdge[] }, id: string): Set<string> {
  const s = new Set<string>([id]);
  for (const e of g.edges) {
    if (e.source === id) s.add(e.target);
    if (e.target === id) s.add(e.source);
  }
  return s;
}

export function pathNodeSet(g: SecurityGraph, pathId: string): Set<string> {
  return new Set(g.nodes.filter((n) => n.pathIds.includes(pathId)).map((n) => n.id));
}

export function worstFirst(a: SceneNode, b: SceneNode): number {
  return SEV_RANK[b.level] - SEV_RANK[a.level] || a.label.localeCompare(b.label);
}
