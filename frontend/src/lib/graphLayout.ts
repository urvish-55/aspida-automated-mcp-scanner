import type { SceneEdge, SceneNode } from "../types/visualization";

export type Vec3 = [number, number, number];
export type Layout = Map<string, Vec3>;

const GOLDEN = Math.PI * (3 - Math.sqrt(5));

/** Even spread of n points on a sphere of radius r (deterministic Fibonacci lattice). */
export function fibonacciSphere(n: number, r: number, offset = 0): Vec3[] {
  const out: Vec3[] = [];
  for (let i = 0; i < n; i++) {
    const y = n === 1 ? 0 : 1 - (i / (n - 1)) * 2;
    const rad = Math.sqrt(Math.max(0, 1 - y * y));
    const th = GOLDEN * (i + offset);
    out.push([Math.cos(th) * rad * r, y * r, Math.sin(th) * rad * r]);
  }
  return out;
}

function norm(v: Vec3): Vec3 {
  const l = Math.hypot(v[0], v[1], v[2]) || 1;
  return [v[0] / l, v[1] / l, v[2] / l];
}

/** Radii scale with node count so 10, 100 and 500 node graphs all stay legible. */
export function radii(toolCount: number): { tool: number; cap: number; finding: number } {
  const tool = Math.max(7, Math.cbrt(Math.max(1, toolCount)) * 5.2);
  return { tool, cap: tool * 1.85, finding: Math.max(1.6, tool * 0.28) };
}

/**
 * Security graph layout: server at the origin, tools on a shell, capabilities on an outer shell in the
 * direction of their tools, findings orbiting the tool they affect. Positions are a pure function of the input.
 */
export function layoutSecurityGraph(nodes: SceneNode[], edges: SceneEdge[]): Layout {
  const pos: Layout = new Map();
  const tools = nodes.filter((n) => n.kind === "tool");
  const caps = nodes.filter((n) => n.kind === "capability");
  const findings = nodes.filter((n) => n.kind === "finding");
  const R = radii(tools.length);
  pos.set("server", [0, 0, 0]);
  fibonacciSphere(tools.length, R.tool).forEach((p, i) => pos.set(tools[i].id, p));
  for (const c of caps) {
    let sum: Vec3 = [0, 0, 0];
    let n = 0;
    for (const e of edges) if (e.target === c.id) { const p = pos.get(e.source); if (p) { sum = [sum[0] + p[0], sum[1] + p[1], sum[2] + p[2]]; n++; } }
    const dir = n ? norm(sum) : norm([1, 0.4, 0.2]);
    pos.set(c.id, [dir[0] * R.cap, dir[1] * R.cap, dir[2] * R.cap]);
  }
  // separate capabilities that landed on the same spot
  const placed: Vec3[] = [];
  for (const c of caps) {
    let p = pos.get(c.id) as Vec3;
    for (let k = 0; k < 20 && placed.some((q) => Math.hypot(p[0] - q[0], p[1] - q[1], p[2] - q[2]) < 3.2); k++) p = [p[0] + 1.6, p[1] + 1.1, p[2] + 1.3];
    pos.set(c.id, p);
    placed.push(p);
  }
  // findings orbit their (first) tool, outward from the server
  const slot = new Map<string, number>();
  for (const f of findings) {
    const anchorId = edges.find((e) => e.source === f.id)?.target ?? "server";
    const base = pos.get(anchorId) ?? [0, 0, 0];
    const k = slot.get(anchorId) ?? 0;
    slot.set(anchorId, k + 1);
    const out = norm(base[0] === 0 && base[1] === 0 && base[2] === 0 ? [0, 1, 0] : base);
    const ang = k * GOLDEN;
    const up: Vec3 = Math.abs(out[1]) > 0.9 ? [1, 0, 0] : [0, 1, 0];
    const side = norm([out[1] * up[2] - out[2] * up[1], out[2] * up[0] - out[0] * up[2], out[0] * up[1] - out[1] * up[0]]);
    const r = R.finding * (1 + Math.floor(k / 6) * 0.5);
    pos.set(f.id, [
      base[0] + out[0] * r * 0.9 + side[0] * Math.cos(ang) * r,
      base[1] + out[1] * r * 0.9 + side[1] * Math.cos(ang) * r + Math.sin(ang) * r * 0.7,
      base[2] + out[2] * r * 0.9 + side[2] * Math.cos(ang) * r,
    ]);
  }
  return pos;
}

/** Threat Galaxy: one cluster per finding category on a ring, findings spiral inside. Position within cluster is by rank. */
export function layoutGalaxy(findings: SceneNode[]): { pos: Layout; clusters: { category: string; centre: Vec3; count: number }[] } {
  const cats = [...new Set(findings.map((f) => f.category ?? "uncategorised"))].sort();
  const pos: Layout = new Map();
  const ringR = Math.max(10, cats.length * 3.4);
  const clusters: { category: string; centre: Vec3; count: number }[] = [];
  cats.forEach((cat, ci) => {
    const a = (ci / Math.max(1, cats.length)) * Math.PI * 2;
    const centre: Vec3 = [Math.cos(a) * ringR, ((ci % 3) - 1) * 2.2, Math.sin(a) * ringR];
    const members = findings.filter((f) => (f.category ?? "uncategorised") === cat);
    clusters.push({ category: cat, centre, count: members.length });
    members.forEach((m, i) => {
      const r = 1.2 + Math.sqrt(i) * 1.15;
      const th = i * GOLDEN;
      pos.set(m.id, [centre[0] + Math.cos(th) * r, centre[1] + ((i % 5) - 2) * 0.35, centre[2] + Math.sin(th) * r]);
    });
  });
  return { pos, clusters };
}

/** Attack-path lanes: each path is a row; its backend stages are laid out left-to-right in order. */
export function layoutPathLanes(stages: number, lanes: number, gapX = 9, gapZ = 7): (lane: number, stage: number) => Vec3 {
  return (lane, stage) => [(stage - (stages - 1) / 2) * gapX, 0, (lane - (lanes - 1) / 2) * gapZ];
}

/** Simple 2D projection for the WebGL-unavailable fallback and the mobile view. */
export function layout2D(nodes: SceneNode[], edges: SceneEdge[], w = 900, h = 640): Map<string, [number, number]> {
  const p3 = layoutSecurityGraph(nodes, edges);
  let max = 1;
  for (const v of p3.values()) max = Math.max(max, Math.hypot(v[0], v[2]));
  const out = new Map<string, [number, number]>();
  for (const [id, v] of p3) out.set(id, [w / 2 + (v[0] / max) * (w / 2 - 50), h / 2 + (v[2] / max) * (h / 2 - 40) + v[1] * 0.6]);
  return out;
}
