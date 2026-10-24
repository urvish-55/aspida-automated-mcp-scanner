/**
 * Pure scene models: each visualization mode turns backend data into positioned items and lines.
 * Nothing here touches Three.js, so every mode is unit-testable and the 2D fallback can reuse the same data.
 */
import type { Analysis, AttackPath, Finding, ScanDetail } from "../types";
import type { ScanStageView, SceneEdge, SceneNode, SeverityOrNone, StageState } from "../types/visualization";
import { fibonacciSphere, layoutGalaxy, layoutPathLanes, layoutSecurityGraph, radii, type Vec3 } from "./graphLayout";
import { safeLabel } from "./safeText";
import { SEV_RANK } from "./severity";
import { capLabel, toolId } from "./securityGraph";
import { terrainCells } from "./terrain";

export type Shape = "sphere" | "octa" | "box" | "ico" | "bar" | "ring";
export type ItemKind = SceneNode["kind"] | "pathnode" | "cell" | "stage";

export interface SceneItem {
  id: string;
  kind: ItemKind;
  label: string;
  pos: Vec3;
  shape: Shape;
  level: SeverityOrNone;
  scale: [number, number, number];
  /** Rendered translucent/wireframe: "potential" or "missing" path stages. Never drawn as solid evidence. */
  ghost?: boolean;
  pathIds: string[];
  stageState?: StageState;
  pulse?: boolean;
  /** Short always-visible label priority (higher = shown first when label budget is limited). */
  labelPriority: number;
}
export interface SceneLine { id: string; a: string; b: string; pathIds: string[]; dashed?: boolean; kind: "structure" | "affects" | "path" | "combo" }
export interface SceneLabel { id: string; text: string; pos: Vec3 }
export interface SceneModel { mode: string; items: SceneItem[]; lines: SceneLine[]; labels: SceneLabel[]; radius: number; empty?: string }

const SEV_SCALE: Record<SeverityOrNone, number> = { critical: 1.45, high: 1.25, medium: 1.05, low: 0.9, info: 0.75, none: 1 };
const sc = (n: number): [number, number, number] => [n, n, n];
const radiusOf = (items: { pos: Vec3 }[]) => items.reduce((m, i) => Math.max(m, Math.hypot(...i.pos)), 4);

export function buildGraphScene(nodes: SceneNode[], edges: SceneEdge[]): SceneModel {
  const pos = layoutSecurityGraph(nodes, edges);
  const items: SceneItem[] = nodes.map((n) => {
    const base = n.kind === "server" ? 1.5 : n.kind === "tool" ? 0.95 : n.kind === "capability" ? 1.25 : 0.62 * SEV_SCALE[n.level];
    return {
      id: n.id, kind: n.kind, label: n.label, pos: pos.get(n.id) ?? [0, 0, 0], level: n.level, pathIds: n.pathIds,
      shape: n.kind === "server" ? "ico" : n.kind === "tool" ? "sphere" : n.kind === "capability" ? "box" : "octa",
      scale: sc(base),
      labelPriority: n.kind === "server" ? 100 : n.kind === "capability" ? 60 : n.kind === "finding" ? SEV_RANK[n.level] * 5 : 10 + SEV_RANK[n.level] * 3,
    };
  });
  const lines: SceneLine[] = edges.map((e) => ({ id: e.id, a: e.source, b: e.target, pathIds: e.pathIds, kind: e.verb === "affects" || e.verb === "affects scan" ? "affects" : "structure" }));
  return { mode: "graph", items, lines, labels: [], radius: radiusOf(items) + 8 };
}

/** Capability network: tools and capabilities only, tools placed on a shell, capabilities on a ring. Combos are highlighted ONLY from backend CAP-010 findings. */
export function buildCapabilityScene(nodes: SceneNode[], edges: SceneEdge[], findings: Finding[]): SceneModel {
  const tools = nodes.filter((n) => n.kind === "tool");
  const caps = nodes.filter((n) => n.kind === "capability");
  const items: SceneItem[] = [];
  const R = radii(tools.length);
  const capR = Math.max(5, caps.length * 1.5);
  caps.forEach((c, i) => {
    const a = (i / Math.max(1, caps.length)) * Math.PI * 2;
    items.push({ id: c.id, kind: "capability", label: c.label, pos: [Math.cos(a) * capR, 0, Math.sin(a) * capR], shape: "box", level: c.level, scale: sc(1.5), pathIds: [], labelPriority: 80 });
  });
  const comboTools = new Set(findings.filter((f) => f.rule_id === "CAP-010").flatMap((f) => f.affected_tools).map(toolId));
  fibonacciSphere(tools.length, R.tool * 0.8).forEach((p, i) => {
    const t = tools[i];
    items.push({ id: t.id, kind: "tool", label: t.label, pos: [p[0], p[1] * 0.35 + 7, p[2]], shape: "sphere", level: comboTools.has(t.id) ? "high" : "none", scale: sc(comboTools.has(t.id) ? 1.1 : 0.8), pathIds: [], labelPriority: comboTools.has(t.id) ? 40 : 8 });
  });
  const lines: SceneLine[] = edges.filter((e) => e.target.startsWith("cap:")).map((e) => ({
    id: e.id, a: e.source, b: e.target, pathIds: [], kind: comboTools.has(e.source) ? "combo" : "structure",
  }));
  return { mode: "capabilities", items, lines, labels: [], radius: radiusOf(items) + 8, empty: caps.length === 0 ? "This scan has no tool capabilities to chart." : undefined };
}

export function buildGalaxyScene(nodes: SceneNode[]): SceneModel {
  const findings = nodes.filter((n) => n.kind === "finding");
  const { pos, clusters } = layoutGalaxy(findings);
  const items: SceneItem[] = findings.map((n) => ({
    id: n.id, kind: "finding", label: n.label, pos: pos.get(n.id) ?? [0, 0, 0], shape: "octa", level: n.level, scale: sc(0.55 * SEV_SCALE[n.level]), pathIds: n.pathIds, labelPriority: SEV_RANK[n.level],
  }));
  const labels = clusters.map((c) => ({ id: `cluster:${c.category}`, text: `${c.category.replace(/_/g, " ")} (${c.count})`, pos: [c.centre[0], c.centre[1] + 3.4, c.centre[2]] as Vec3 }));
  return { mode: "galaxy", items, lines: [], labels, radius: radiusOf(items) + 10, empty: findings.length === 0 ? "No findings to chart." : undefined };
}

const PATH_STATUS_LEVEL: Record<string, SeverityOrNone> = { evidenced: "high", potential: "medium", missing: "none" };

/** Attack paths: one lane per backend candidate, one node per backend stage. Only `evidenced` stages are drawn solid. */
export function buildPathScene(paths: AttackPath[], onlyId?: string | null): SceneModel {
  const shown = onlyId ? paths.filter((p) => p.id === onlyId) : paths;
  const stages = Math.max(1, ...shown.map((p) => p.nodes.length));
  const at = layoutPathLanes(stages, shown.length);
  const items: SceneItem[] = [];
  const lines: SceneLine[] = [];
  const labels: SceneLabel[] = [];
  shown.forEach((p, lane) => {
    p.nodes.forEach((n, i) => {
      items.push({
        id: `pathnode:${p.id}:${i}`, kind: "pathnode", label: safeLabel(n.label), pos: at(lane, i), pathIds: [p.id],
        shape: n.status === "missing" ? "ring" : n.status === "evidenced" ? "sphere" : "octa",
        level: PATH_STATUS_LEVEL[n.status] ?? "none", scale: sc(n.status === "evidenced" ? 1.3 : 1.1), ghost: n.status !== "evidenced", labelPriority: 50,
      });
      if (i > 0) lines.push({ id: `pl:${p.id}:${i}`, a: `pathnode:${p.id}:${i - 1}`, b: `pathnode:${p.id}:${i}`, pathIds: [p.id], dashed: n.status !== "evidenced" || p.nodes[i - 1].status !== "evidenced", kind: "path" });
    });
    const first = at(lane, 0);
    labels.push({ id: `lane:${p.id}`, text: `${safeLabel(p.label)} · ${p.complete ? "all stages present" : `${p.missing_stages.length} stage(s) missing`}`, pos: [first[0] - 5, 2.8, first[2]] });
  });
  return { mode: "paths", items, lines, labels, radius: Math.max(14, stages * 5.5), empty: shown.length === 0 ? "The evidence does not support any attack path for this scan." : undefined };
}

/** Risk terrain: bar height = raw RISK-1 points for (category × severity). */
export function buildTerrainScene(findings: Finding[]): SceneModel {
  const cells = terrainCells(findings);
  const cats = [...new Set(cells.map((c) => c.category))].sort();
  const sevs = (["critical", "high", "medium", "low"] as const).filter((s) => cells.some((c) => c.severity === s));
  const items: SceneItem[] = cells.map((c) => {
    const x = (cats.indexOf(c.category) - (cats.length - 1) / 2) * 3.2;
    const z = (sevs.indexOf(c.severity as (typeof sevs)[number]) - (sevs.length - 1) / 2) * 3.2;
    const h = Math.max(0.2, c.points * 0.1);
    return { id: `cell:${c.category}|${c.severity}`, kind: "cell", label: `${c.category} / ${c.severity}: ${c.points} pts`, pos: [x, h / 2, z], shape: "bar", level: c.severity, scale: [2.4, h, 2.4], pathIds: [], labelPriority: c.points };
  });
  const labels: SceneLabel[] = [
    ...cats.map((c, i) => ({ id: `col:${c}`, text: c.replace(/_/g, " "), pos: [(i - (cats.length - 1) / 2) * 3.2, 0.2, ((sevs.length - 1) / 2 + 1.5) * 3.2] as Vec3 })),
    ...sevs.map((s, i) => ({ id: `row:${s}`, text: s, pos: [-((cats.length - 1) / 2 + 1.7) * 3.2, 0.2, (i - (sevs.length - 1) / 2) * 3.2] as Vec3 })),
  ];
  return { mode: "terrain", items, lines: [], labels, radius: Math.max(14, Math.max(cats.length, sevs.length) * 4.2), empty: cells.length === 0 ? "No scored findings, so there is no terrain to draw." : undefined };
}

/** Scan mode: the real pipeline stages in a ring. Pulses exist only for the single backend-active stage while the scan is running. */
export function buildScanScene(stages: ScanStageView[], live: boolean, scan: ScanDetail, analysis?: Analysis): SceneModel {
  const R = 11;
  const items: SceneItem[] = stages.map((s, i) => {
    const a = (i / stages.length) * Math.PI * 2 - Math.PI / 2;
    return {
      id: `stage:${s.id}`, kind: "stage", label: s.label, pos: [Math.cos(a) * R, 0, Math.sin(a) * R], shape: "sphere",
      level: s.state === "failed" ? "critical" : "none", scale: sc(s.state === "active" ? 1.5 : 1.15), stageState: s.state, pulse: live && s.state === "active", pathIds: [], labelPriority: 50,
    };
  });
  const lines: SceneLine[] = stages.slice(1).map((s, i) => ({ id: `sl:${i}`, a: `stage:${stages[i].id}`, b: `stage:${s.id}`, pathIds: [], kind: "structure" }));
  const labels: SceneLabel[] = [
    { id: "centre", text: `${scan.tools.length} tools stored · ${scan.findings.length} findings stored`, pos: [0, 2.2, 0] },
    ...(analysis ? [{ id: "paths", text: `${analysis.attack_paths.length} attack-path candidate(s)`, pos: [0, 0.4, 0] as Vec3 }] : []),
  ];
  return { mode: "scan", items, lines, labels, radius: R + 10 };
}

export { capLabel };
