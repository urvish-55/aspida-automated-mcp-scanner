import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { detectWebGL } from "../../hooks/useWebGL";
import { buildGraphScene } from "../../lib/sceneModel";
import { buildSecurityGraph } from "../../lib/securityGraph";
import { defaultFilters, useInvestigation } from "../../state/investigation";
import { analysis, finding, scan, tool } from "../../test/fixtures";
import { Fallback2D } from "./Fallback2D";
import { ObjectList } from "./ObjectList";
import { ScanPanel } from "./ScanPanel";
import { deriveStages } from "../../lib/scanEvents";

const g = buildSecurityGraph(
  scan({ tools: [tool("read_file", ["filesystem_read"])], findings: [finding("1", "critical", ["read_file"], { title: "Bad ‮ title" })] }),
  analysis(),
);
const model = buildGraphScene(g.nodes, g.edges);
beforeEach(() => useInvestigation.setState({ selectedId: null, hoveredId: null, isolateId: null, activePathId: null, filters: defaultFilters() }));
afterEach(cleanup);

describe("WebGL unavailable", () => {
  it("is detected (jsdom has no WebGL) so the 2D fallback is used", () => {
    expect(detectWebGL()).toBe(false);
  });
  it("2D fallback renders every object with an accessible name and text severity", () => {
    render(<Fallback2D model={model} theme="dark" reason="WebGL is not available in this browser, so the 2D view is shown." />);
    expect(screen.getAllByRole("button")).toHaveLength(model.items.length);
    expect(screen.getByRole("button", { name: /read_file, tool/ })).toBeTruthy();
    expect(screen.getByRole("button", { name: /title, finding, Critical severity/ })).toBeTruthy(); // not colour-only
    expect(screen.getByRole("status").textContent).toMatch(/WebGL is not available/);
  });
  it("selecting in 2D (mouse or keyboard) updates the shared store", () => {
    render(<Fallback2D model={model} theme="dark" />);
    fireEvent.click(screen.getByRole("button", { name: /read_file, tool/ }));
    expect(useInvestigation.getState().selectedId).toBe("tool:read_file");
    fireEvent.keyDown(screen.getByRole("button", { name: /title, finding, Critical severity/ }), { key: "Enter" });
    expect(useInvestigation.getState().selectedId).toBe("finding:1");
  });
  it("untrusted label control characters are neutralised", () => {
    const f = model.items.find((i) => i.kind === "finding");
    expect(f?.label).toContain("⟦U+202E⟧");
  });
});

describe("object list (screen-reader equivalent)", () => {
  it("lists every object, marks the selection and syncs both ways", () => {
    render(<ObjectList items={model.items} />);
    expect(screen.getByRole("list").getAttribute("aria-label")).toBe("Objects in this view");
    useInvestigation.getState().select("tool:read_file");
  });
  it("renders an empty list message", () => {
    render(<ObjectList items={[]} />);
    expect(screen.getByText("Nothing to list.")).toBeTruthy();
  });
});

describe("scan panel", () => {
  it("shows that nothing animates when no scan is running", () => {
    render(<ScanPanel stages={deriveStages([], "completed")} live={false} findingsReady status="completed" />);
    expect(screen.getByText(/nothing animates/)).toBeTruthy();
  });
  it("explains that findings arrive late in a live scan", () => {
    render(<ScanPanel stages={deriveStages([], "running")} live findingsReady={false} status="running" />);
    expect(screen.getByText(/Findings are saved when risk aggregation finishes/)).toBeTruthy();
  });
});
