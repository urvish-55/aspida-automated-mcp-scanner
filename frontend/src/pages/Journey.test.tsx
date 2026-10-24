import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { SectionBody, type SectionCtx } from "../components/story/StorySections";
import { buildStoryData, demoAnalysis, demoScan } from "../lib/storyData";
import { SECTIONS } from "../lib/storyTimeline";
import { scan } from "../test/fixtures";

const mk = (status: SectionCtx["status"], d = buildStoryData(scan({ risk_score: null, findings: [], tools: [] }), undefined, "scan")): SectionCtx =>
  ({ data: d, status, motion: false, onInvestigate: () => {}, onGo: () => {}, reload: () => {} });
const view = (id: Parameters<typeof SectionBody>[0]["id"], ctx: SectionCtx) =>
  render(<QueryClientProvider client={new QueryClient()}><MemoryRouter><SectionBody id={id} ctx={ctx} /></MemoryRouter></QueryClientProvider>);

describe("story sections", () => {
  it("renders all 12 sections with real headings", () => {
    for (const s of SECTIONS) { const { container, unmount } = view(s.id, mk("empty")); expect(container.querySelector("h1,h2")).not.toBeNull(); unmount(); }
  });
  it("empty state never invents numbers", () => {
    view("surface", mk("empty"));
    expect(screen.getAllByText("Data unavailable").length).toBeGreaterThan(0);
    expect(screen.getByText("No scan has been performed.")).toBeTruthy();
  });
  it("risk score unavailable when null", () => {
    view("risk", mk("ready"));
    expect(screen.getByText("Risk score unavailable.")).toBeTruthy();
  });
  it("verify is NOT VERIFIED without a scan, and the demo is labelled", () => {
    const { unmount } = view("verify", mk("empty"));
    expect(screen.getByText(/NOT VERIFIED/)).toBeTruthy(); unmount();
    view("surface", mk("demo", buildStoryData(demoScan(), demoAnalysis(), "demo")));
    expect(screen.getByText(/Illustrative Example/)).toBeTruthy();
  });
  it("final section has the three actions", () => {
    view("final", mk("empty"));
    for (const t of ["Start Scan", "Open Dashboard", "View Documentation"]) expect(screen.getByText(t)).toBeTruthy();
    expect(screen.getByText(/START YOUR SECURITY SCAN/)).toBeTruthy();
  });
});

import { BootOverlay } from "../components/story/BootOverlay";
describe("boot overlay", () => {
  it("is frontend-only, and absent in 2D or reduced motion", () => {
    const a = render(<BootOverlay use3D={false} engineReady={false} reduced={false} />); expect(a.container.innerHTML).toBe(""); a.unmount();
    const b = render(<BootOverlay use3D engineReady={false} reduced />); expect(b.container.innerHTML).toBe(""); b.unmount();
    render(<BootOverlay use3D engineReady={false} reduced={false} />);
    expect(screen.getByText(/Initializing MCP security environment/)).toBeTruthy();
    expect(screen.queryByText(/scan progress/i)).toBeNull();
  });
});
