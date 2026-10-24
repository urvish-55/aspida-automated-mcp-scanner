import { describe, expect, it } from "vitest";
import { analysis, finding, scan, tool } from "../test/fixtures";
import { buildSecurityGraph, filterGraph, neighbours, pathNodeSet } from "./securityGraph";
import { defaultFilters } from "../state/investigation";
import type { AttackPath } from "../types";

const s = scan({
  tools: [tool("read_file", ["filesystem_read"]), tool("http_get", ["network_access"]), tool("idle")],
  findings: [finding("1", "critical", ["read_file"]), finding("2", "low", ["http_get"], { category: "permission" }), finding("3", "info", [], { status: "informational" })],
});
const path: AttackPath = {
  id: "p1", kind: "exfil", complete: false, label: "x", missing_stages: ["outcome"], confidence: "low", evidence_ratio: 0.5,
  nodes: [{ stage: "collection", label: "c", status: "evidenced", tools: ["read_file"], finding_ids: ["1"], evidence: [], confidence: "high", category: null }],
};

describe("buildSecurityGraph", () => {
  const g = buildSecurityGraph(s, analysis({ attack_paths: [path] }));
  it("creates one node per server, tool, capability and finding", () => {
    expect(g.nodes.filter((n) => n.kind === "server")).toHaveLength(1);
    expect(g.nodes.filter((n) => n.kind === "tool")).toHaveLength(3);
    expect(g.nodes.filter((n) => n.kind === "capability").map((n) => n.id).sort()).toEqual(["cap:filesystem_read", "cap:network_access"]);
    expect(g.nodes.filter((n) => n.kind === "finding")).toHaveLength(3);
  });
  it("maps severity from findings only; tools without findings are 'none'", () => {
    expect(g.nodes.find((n) => n.id === "tool:read_file")?.level).toBe("critical");
    expect(g.nodes.find((n) => n.id === "tool:idle")?.level).toBe("none");
  });
  it("does not count informational findings toward a tool's finding count", () => {
    expect(g.nodes.find((n) => n.id === "tool:read_file")?.findingCount).toBe(1);
  });
  it("generates edges server→tool, tool→capability, finding→tool, and finding→server when no tool", () => {
    const has = (a: string, b: string) => g.edges.some((e) => e.source === a && e.target === b);
    expect(has("server", "tool:read_file")).toBe(true);
    expect(has("tool:read_file", "cap:filesystem_read")).toBe(true);
    expect(has("finding:1", "tool:read_file")).toBe(true);
    expect(has("finding:3", "server")).toBe(true);
  });
  it("never invents resources", () => {
    expect(g.nodes.some((n) => n.kind === "resource")).toBe(false);
    expect(g.notes.join(" ")).toMatch(/not analysed/);
  });
  it("annotates attack-path membership from the backend analysis", () => {
    expect(pathNodeSet(g, "p1")).toEqual(new Set(["tool:read_file", "finding:1"]));
    expect(g.edges.find((e) => e.id === "e:1>read_file")?.pathIds).toEqual(["p1"]);
  });
  it("has no path membership without backend paths", () => {
    expect(buildSecurityGraph(s, undefined).nodes.every((n) => n.pathIds.length === 0)).toBe(true);
  });
  it("handles a scan with no tools", () => {
    const e = buildSecurityGraph(scan(), undefined);
    expect(e.nodes).toHaveLength(1);
    expect(e.notes.join(" ")).toMatch(/no tool definitions/);
  });
});

describe("filterGraph", () => {
  const g = buildSecurityGraph(s, undefined);
  it("filters findings by severity and drops dangling edges", () => {
    const f = filterGraph(g, { ...defaultFilters(), severities: ["critical"] });
    expect(f.nodes.filter((n) => n.kind === "finding").map((n) => n.id)).toEqual(["finding:1"]);
    expect(f.edges.every((e) => f.nodes.some((n) => n.id === e.source) && f.nodes.some((n) => n.id === e.target))).toBe(true);
    expect(f.hiddenCount).toBeGreaterThan(0);
  });
  it("filters by node kind", () => {
    const f = filterGraph(g, { ...defaultFilters(), kinds: ["server", "tool"] });
    expect(f.nodes.every((n) => n.kind === "server" || n.kind === "tool")).toBe(true);
  });
  it("filters by category", () => {
    const f = filterGraph(g, { ...defaultFilters(), categories: ["permission"] });
    expect(f.nodes.filter((n) => n.kind === "finding").map((n) => n.id)).toEqual(["finding:2"]);
  });
  it("searches by label and keeps the server", () => {
    const f = filterGraph(g, { ...defaultFilters(), query: "http" });
    expect(f.nodes.map((n) => n.id).sort()).toEqual(["server", "tool:http_get"]);
  });
  it("neighbours returns the selection plus directly connected nodes", () => {
    expect(neighbours(g, "tool:read_file")).toEqual(new Set(["tool:read_file", "server", "cap:filesystem_read", "finding:1"]));
  });
});
