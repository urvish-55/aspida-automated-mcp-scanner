import { describe, expect, it } from "vitest";
import { event } from "../test/fixtures";
import { deriveStages, findingsAvailable, isLive } from "./scanEvents";

describe("scan events", () => {
  it("marks a stage active only while the backend says running and no later stage has started", () => {
    const st = deriveStages([event(1, "initializing"), event(2, "parsing_target"), event(3, "enumerating_tools")], "running");
    expect(st.map((s) => s.state).slice(0, 4)).toEqual(["done", "done", "active", "pending"]);
  });
  it("derives nothing from time: no events means everything pending", () => {
    expect(deriveStages([], "queued").every((s) => s.state === "pending")).toBe(true);
  });
  it("shows all started stages done on completion and carries real messages", () => {
    const st = deriveStages([event(1, "initializing", { message: "hello" }), event(2, "static_analysis", { duration_ms: 12 }), event(3, "static_analysis", { duration_ms: 8 })], "completed");
    expect(st[0].message).toBe("hello");
    expect(st[3]).toMatchObject({ state: "done", durationMs: 20 });
    expect(st[7].state).toBe("pending");
  });
  it("marks the interrupted stage failed on failure/cancel", () => {
    const st = deriveStages([event(1, "initializing"), event(2, "parsing_target")], "failed");
    expect(st[1].state).toBe("failed");
    expect(st[0].state).toBe("done");
  });
  it("allows animation only for running scans", () => {
    expect(isLive("running")).toBe(true);
    for (const s of ["queued", "completed", "failed", "cancelled"] as const) expect(isLive(s)).toBe(false);
    expect(isLive(undefined)).toBe(false);
  });
  it("reports findings as unavailable before risk aggregation", () => {
    expect(findingsAvailable([event(1, "static_analysis")], "running")).toBe(false);
    expect(findingsAvailable([event(1, "risk_aggregation")], "running")).toBe(true);
    expect(findingsAvailable([], "completed")).toBe(true);
  });
});
