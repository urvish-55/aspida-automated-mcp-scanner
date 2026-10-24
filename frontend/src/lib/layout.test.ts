import { describe, expect, it } from "vitest";
import { analysis, finding, scan, tool } from "../test/fixtures";
import { fibonacciSphere, layout2D, layoutGalaxy, layoutSecurityGraph } from "./graphLayout";
import { buildSecurityGraph } from "./securityGraph";
import { terrainCells } from "./terrain";

const many = (n: number) => scan({
  tools: Array.from({ length: n }, (_, i) => tool(`t${i}`, i % 2 ? ["network_access"] : ["filesystem_read"])),
  findings: Array.from({ length: n }, (_, i) => finding(`${i}`, "medium", [`t${i}`])),
});

describe("layout", () => {
  it.each([10, 100, 500])("places every node at a finite, unique position (%i tools)", (n) => {
    const g = buildSecurityGraph(many(n), analysis());
    const pos = layoutSecurityGraph(g.nodes, g.edges);
    expect(pos.size).toBe(g.nodes.length);
    const seen = new Set<string>();
    for (const v of pos.values()) {
      expect(v.every(Number.isFinite)).toBe(true);
      seen.add(v.map((x) => x.toFixed(2)).join(","));
    }
    expect(seen.size).toBe(g.nodes.length);
  });
  it("is deterministic", () => {
    const g = buildSecurityGraph(many(30), analysis());
    expect(layoutSecurityGraph(g.nodes, g.edges)).toEqual(layoutSecurityGraph(g.nodes, g.edges));
  });
  it("fibonacciSphere keeps all points on the radius", () => {
    for (const p of fibonacciSphere(50, 7)) expect(Math.hypot(...p)).toBeCloseTo(7, 5);
  });
  it("2D layout stays inside the viewport", () => {
    const g = buildSecurityGraph(many(60), analysis());
    for (const [x, y] of layout2D(g.nodes, g.edges, 900, 640).values()) { expect(x).toBeGreaterThanOrEqual(0); expect(x).toBeLessThanOrEqual(900); expect(y).toBeGreaterThanOrEqual(-40); expect(y).toBeLessThanOrEqual(700); }
  });
  it("galaxy clusters findings by category", () => {
    const g = buildSecurityGraph(scan({ findings: [finding("a", "high", [], { category: "x" }), finding("b", "low", [], { category: "y" }), finding("c", "low", [], { category: "y" })] }), undefined);
    const { clusters, pos } = layoutGalaxy(g.nodes.filter((n) => n.kind === "finding"));
    expect(clusters.map((c) => [c.category, c.count])).toEqual([["x", 1], ["y", 2]]);
    expect(pos.size).toBe(3);
  });
});

describe("terrain", () => {
  it("uses the RISK-1 point table and ignores coverage gaps", () => {
    const cells = terrainCells([
      finding("1", "critical", []), finding("2", "critical", []),
      finding("3", "high", [], { status: "confirmed", detector_sources: ["DYN-001"] }),
      finding("4", "high", [], { status: "not_tested" }), finding("5", "high", [], { category: "engine" }),
    ]);
    const get = (c: string, s: string) => cells.find((x) => x.category === c && x.severity === s)?.points;
    expect(get("tool_poisoning", "critical")).toBe(40);
    expect(get("tool_poisoning", "high")).toBe(20);
    expect(cells.some((c) => c.category === "engine")).toBe(false);
  });
});
