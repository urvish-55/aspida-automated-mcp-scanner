import { describe, expect, it } from "vitest";
import { analysis, event, finding, scan, tool } from "../test/fixtures";
import { computeHighlight } from "./highlight";
import { buildCapabilityScene, buildGalaxyScene, buildGraphScene, buildPathScene, buildScanScene, buildTerrainScene } from "./sceneModel";
import { buildSecurityGraph } from "./securityGraph";
import { deriveStages } from "./scanEvents";
import type { AttackPath } from "../types";

const s = scan({
  tools: [tool("a", ["filesystem_read"]), tool("b", ["network_access"])],
  findings: [finding("1", "critical", ["a"]), finding("2", "high", ["b"], { rule_id: "CAP-010", category: "capability" })],
});
const path: AttackPath = {
  id: "p1", kind: "exfil", complete: false, label: "Exfil", missing_stages: ["outcome"], confidence: "low", evidence_ratio: 0.5,
  nodes: [
    { stage: "collection", label: "Collect", status: "evidenced", tools: ["a"], finding_ids: ["1"], evidence: [], confidence: "high", category: null },
    { stage: "egress", label: "Egress", status: "potential", tools: ["b"], finding_ids: [], evidence: [], confidence: "low", category: null },
    { stage: "outcome", label: "Outcome", status: "missing", tools: [], finding_ids: [], evidence: [], confidence: null, category: null },
  ],
};
const g = buildSecurityGraph(s, analysis({ attack_paths: [path] }));
const none = { selectedId: null, hoveredId: null, activePathId: null, isolateId: null };

describe("scene models", () => {
  it("graph scene has one item per node and one line per edge", () => {
    const m = buildGraphScene(g.nodes, g.edges);
    expect(m.items).toHaveLength(g.nodes.length);
    expect(m.lines).toHaveLength(g.edges.length);
  });
  it("only evidenced path stages are solid; potential and missing are ghosts, and lines into them are dashed", () => {
    const m = buildPathScene([path]);
    expect(m.items.map((i) => i.ghost)).toEqual([false, true, true]);
    expect(m.items[2].shape).toBe("ring");
    expect(m.lines.every((l) => l.dashed)).toBe(true);
  });
  it("reports an honest empty state when no path is supported", () => {
    expect(buildPathScene([]).empty).toMatch(/does not support/);
  });
  it("capability scene highlights combos only from backend CAP-010 findings", () => {
    const m = buildCapabilityScene(g.nodes, g.edges, s.findings);
    expect(m.lines.filter((l) => l.kind === "combo").map((l) => l.a)).toEqual(["tool:b"]);
    expect(buildCapabilityScene(g.nodes, g.edges, []).lines.some((l) => l.kind === "combo")).toBe(false);
  });
  it("terrain heights come from RISK-1 points", () => {
    const m = buildTerrainScene(s.findings);
    const crit = m.items.find((i) => i.id === "cell:tool_poisoning|critical");
    expect(crit?.scale[1]).toBeCloseTo(2.0);
  });
  it("galaxy contains findings only", () => {
    expect(buildGalaxyScene(g.nodes).items.every((i) => i.kind === "finding")).toBe(true);
  });
  it("scan scene pulses only the active stage of a running scan", () => {
    const stages = deriveStages([event(1, "initializing"), event(2, "parsing_target")], "running");
    expect(buildScanScene(stages, true, s).items.filter((i) => i.pulse).map((i) => i.id)).toEqual(["stage:parsing_target"]);
    expect(buildScanScene(deriveStages([event(1, "initializing")], "completed"), false, s).items.some((i) => i.pulse)).toBe(false);
  });
});

describe("highlight", () => {
  const m = buildGraphScene(g.nodes, g.edges);
  it("is all normal with nothing selected", () => {
    expect([...computeHighlight(m, none).item.values()].every((e) => e === "normal")).toBe(true);
  });
  it("focuses the selection, marks neighbours related and dims the rest", () => {
    const h = computeHighlight(m, { ...none, selectedId: "tool:a" });
    expect(h.item.get("tool:a")).toBe("focus");
    expect(h.item.get("finding:1")).toBe("related");
    expect(h.item.get("tool:b")).toBe("dim");
  });
  it("hover wins over selection for emphasis", () => {
    expect(computeHighlight(m, { ...none, selectedId: "tool:a", hoveredId: "tool:b" }).item.get("tool:b")).toBe("focus");
  });
  it("highlights attack-path members and dims others", () => {
    const h = computeHighlight(m, { ...none, activePathId: "p1" });
    expect(h.item.get("tool:a")).toBe("related");
    expect(h.item.get("tool:b")).toBe("related"); // the egress stage names tool b
    expect(h.item.get("finding:2")).toBe("dim"); // not referenced by any path stage
    expect(h.line.get("e:1>a")).toBe("related");
  });
  it("isolation hides unrelated nodes", () => {
    const h = computeHighlight(m, { ...none, isolateId: "finding:1" });
    expect(h.hidden.has("tool:b")).toBe(true);
    expect(h.hidden.has("tool:a")).toBe(false);
  });
  it("comparison overlay emphasises marked ids and dims the rest", () => {
    const h = computeHighlight(m, { ...none, markedIds: new Set(["finding:1"]) });
    expect(h.item.get("finding:1")).toBe("related");
    expect(h.item.get("finding:2")).toBe("dim");
  });
});
