import { describe, expect, it } from "vitest";
import { alongPath, cameraAt, clamp01, locate, progressFromScroll, reveal, scrollTopForSection, SECTIONS, SECTION_INDEX, staticPose, totalViewports } from "./storyTimeline";

const anchors = { R: 10, threat: [4, 1, 2] as [number, number, number], path: [[0, 0, 0], [6, 0, 0], [6, 4, 0]] as [number, number, number][] };

describe("timeline", () => {
  it("covers all 12 sections in order from p=0 to p=1", () => {
    expect(SECTIONS).toHaveLength(12);
    expect(locate(0).id).toBe("intro");
    expect(locate(1).id).toBe("final");
    let last = -1;
    for (let p = 0; p <= 1; p += 0.01) { const i = locate(p).index; expect(i).toBeGreaterThanOrEqual(last); last = i; }
  });
  it("local progress is 0..1 and monotonic inside a section", () => {
    const a = locate(0.3); const b = locate(0.31);
    expect(a.local).toBeGreaterThanOrEqual(0); expect(b.local).toBeLessThanOrEqual(1);
    if (a.index === b.index) expect(b.local).toBeGreaterThan(a.local);
  });
  it("section jump targets land inside the section", () => {
    const vh = 800; const doc = totalViewports() * vh;
    for (let i = 0; i < SECTIONS.length; i++) expect(locate(progressFromScroll(scrollTopForSection(i, vh) + 2, vh, doc)).index).toBe(i);
  });
  it("progress clamps", () => {
    expect(progressFromScroll(-50, 800, 8000)).toBe(0);
    expect(progressFromScroll(99999, 800, 8000)).toBe(1);
    expect(clamp01(2)).toBe(1);
  });
  it("reveal eases between bounds", () => {
    expect(reveal(0, 0.2, 0.4)).toBe(0); expect(reveal(0.5, 0.2, 0.4)).toBe(1); expect(reveal(0.3, 0.2, 0.4)).toBeCloseTo(0.5);
  });
});

describe("camera", () => {
  const d = (a: number[], b: number[]) => Math.hypot(a[0] - b[0], a[1] - b[1], a[2] - b[2]);
  it("is smooth: no jumps between neighbouring scroll positions", () => {
    let prev = cameraAt(0, anchors).position;
    for (let p = 0.001; p <= 1; p += 0.001) { const c = cameraAt(p, anchors).position; expect(d(prev, c)).toBeLessThan(1.6); prev = c; }
  });
  it("follows the attack path during the path section", () => {
    const s = SECTION_INDEX.path;
    const start = cameraAt(0.0, anchors); expect(start.target).toEqual([0, 0, 0]);
    let first: number[] | null = null; let last: number[] | null = null;
    for (let p = 0; p <= 1; p += 0.002) { const l = locate(p); if (l.index === s) { const t = cameraAt(p, anchors).target; first ??= t; last = t; } }
    expect(d(first as number[], [0, 0, 0])).toBeLessThan(0.5);
    expect(d(last as number[], [6, 4, 0])).toBeLessThan(0.8);
  });
  it("holds still for the first part of the evidence section", () => {
    const poses: number[][] = [];
    for (let p = 0; p <= 1; p += 0.0005) { const l = locate(p); if (l.index === SECTION_INDEX.evidence && l.local < 0.55) poses.push(cameraAt(p, anchors).position); }
    expect(poses.length).toBeGreaterThan(5);
    expect(Math.max(...poses.map((q) => d(q, poses[0])))).toBeLessThan(1e-9);
  });
  it("works with no threat and no path (honest empty data)", () => {
    const empty = { R: 10, threat: null, path: [] };
    for (let p = 0; p <= 1; p += 0.05) expect(cameraAt(p, empty).position.every(Number.isFinite)).toBe(true);
  });
  it("alongPath interpolates by arc length", () => {
    expect(alongPath([[0, 0, 0], [10, 0, 0]], 0.5)).toEqual([5, 0, 0]);
    expect(alongPath([], 0.5)).toEqual([0, 0, 0]);
  });
  it("static pose is finite", () => { expect(staticPose(anchors).position.every(Number.isFinite)).toBe(true); });
});
