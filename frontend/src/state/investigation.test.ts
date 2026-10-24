import { beforeEach, describe, expect, it } from "vitest";
import { defaultFilters, useInvestigation } from "./investigation";

const s = () => useInvestigation.getState();
beforeEach(() => useInvestigation.setState({ selectedId: null, isolateId: null, activePathId: null, focusId: null, focusTick: 0, filters: defaultFilters(), mode: "graph" }));

describe("investigation store", () => {
  it("focus selects the node and bumps the tick even for a repeated target", () => {
    s().focus("tool:a");
    const t1 = s().focusTick;
    s().focus("tool:a");
    expect(s().selectedId).toBe("tool:a");
    expect(s().focusTick).toBe(t1 + 1);
  });
  it("Esc steps back isolation → path → selection", () => {
    useInvestigation.setState({ selectedId: "n", activePathId: "p", isolateId: "n" });
    s().escape(); expect(s().isolateId).toBeNull(); expect(s().activePathId).toBe("p");
    s().escape(); expect(s().activePathId).toBeNull(); expect(s().selectedId).toBe("n");
    s().escape(); expect(s().selectedId).toBeNull();
  });
  it("toggles filters and resets them", () => {
    s().toggleSeverity("info"); expect(s().filters.severities).not.toContain("info");
    s().toggleKind("finding"); expect(s().filters.kinds).not.toContain("finding");
    s().toggleCategory("x"); expect(s().filters.categories).toEqual(["x"]);
    s().resetFilters(); expect(s().filters).toEqual(defaultFilters());
  });
  it("leaving the paths mode clears the active path", () => {
    s().setMode("paths"); s().setActivePath("p"); s().setMode("graph");
    expect(s().activePathId).toBeNull();
  });
  it("sync: selecting from the 2D list and the 3D scene is the same state", () => {
    s().select("finding:1");
    expect(s().selectedId).toBe("finding:1");
  });
});
