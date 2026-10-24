import { describe, expect, it } from "vitest";
import { analysis, finding, scan, tool } from "../test/fixtures";
import { buildStoryData, demoAnalysis, demoScan, topFindingOf, topPathOf, verifyState } from "./storyData";

const s = scan({
  tools: [tool("a", ["network_access"]), tool("b", ["filesystem_read", "filesystem_write"]), tool("c​", ["shell_execution"])],
  findings: [finding("1", "low", ["a"]), finding("2", "critical", ["b"], { status: "confirmed" }), finding("3", "info", [], { status: "informational" })],
  risk_score: 61,
  risk_breakdown: { static: { subtotal: 22, cap: 40 }, dynamic: { subtotal: 30, cap: 35 }, capability: { subtotal: 10, cap: 20 }, confidence_adjustment: { adjustment_points: 1 } },
  tests: [{ test_id: "t", test_name: "Path traversal", tool_name: "a", status: "passed", detail: "", evidence: {}, duration_ms: 1 }, { test_id: "t2", test_name: "Path traversal", tool_name: "b", status: "failed", detail: "", evidence: {}, duration_ms: 1 }],
});

describe("story data", () => {
  const d = buildStoryData(s, analysis(), "scan");
  it("counts only what is stored", () => {
    expect(d.stats).toMatchObject({ tools: 3, networkTools: 1, shellTools: 1, findings: 2, riskScore: 61, paths: 0 });
    expect(d.stats.filesystemTools).toBe(1); // a tool with read+write counts once
    expect(d.stats.bySeverity).toMatchObject({ critical: 1, low: 1, info: 0 });
  });
  it("picks the most severe finding and ignores informational ones", () => {
    expect(topFindingOf(s.findings)?.id).toBe("2");
    expect(topFindingOf([finding("x", "info", [], { status: "informational" })])).toBeNull();
  });
  it("finds invisible characters in tool metadata", () => { expect(d.hiddenCharTool?.name).toBe("c​"); });
  it("summarises recorded tests by name", () => { expect(d.testSummary).toEqual([{ name: "Path traversal", passed: 1, failed: 1, other: 0 }]); });
  it("explains the risk score from the stored breakdown", () => { expect(d.riskParts.map((p) => p.points)).toEqual([22, 30, 10, 1]); });
  it("risk score unavailable stays null", () => { expect(buildStoryData(scan({ risk_score: null }), undefined, "scan").stats.riskScore).toBeNull(); });
  it("picks the path with the most evidence", () => {
    const p = (id: string, r: number) => ({ id, kind: "", complete: false, label: id, missing_stages: [], confidence: "low", evidence_ratio: r, nodes: [] });
    expect(topPathOf(analysis({ attack_paths: [p("a", 0.3), p("b", 0.8)] }))?.id).toBe("b");
    expect(topPathOf(undefined)).toBeNull();
  });
});

describe("verification never overclaims", () => {
  const top = finding("2", "critical", ["b"]); // a finding reported by the EARLIER scan
  const withF = scan({ findings: [top] });
  const without = scan({ findings: [] });
  it("needs an earlier scan", () => { expect(verifyState(top, null, withF).state).toBe("not_verified"); });
  it("still present when the same rule+tool is in the later scan", () => { expect(verifyState(top, withF, withF).state).toBe("still_present"); });
  it("absent but not marked resolved is NOT verified", () => { expect(verifyState(top, withF, without).state).toBe("not_verified"); });
  it("resolved only when absent AND marked resolved", () => { expect(verifyState({ ...top, triage_status: "resolved" }, withF, without).state).toBe("resolved"); });
  it("uses the earlier scan's finding when a re-scan exists", () => {
    const d = buildStoryData(without, undefined, "scan", withF);
    expect(d.verifyFinding?.id).toBe("2");
    expect(d.verify.state).toBe("not_verified");
  });
});

describe("illustrative example", () => {
  it("is labelled as an example everywhere it could be mistaken for a scan", () => {
    const sc = demoScan();
    expect(sc.target_label).toMatch(/Illustrative/);
    expect(sc.risk_score).toBeNull();
    expect(sc.findings[0].title).toMatch(/Illustrative/);
    expect(demoAnalysis().attack_paths[0].label).toMatch(/Illustrative/);
    expect(buildStoryData(sc, demoAnalysis(), "demo").source).toBe("demo");
  });
});
