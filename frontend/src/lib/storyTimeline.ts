/**
 * The scroll timeline for the story. One place owns every scroll → scene mapping:
 * section boundaries, local progress, easing and the camera path. Pure functions, no DOM or Three.js.
 */
import type { Vec3 } from "./graphLayout";

export type SectionId = "intro" | "ecosystem" | "discovery" | "surface" | "testing" | "threat" | "path" | "evidence" | "risk" | "remediation" | "verify" | "final";

/** `weight` is the section's scroll length in viewport heights. */
export const SECTIONS: { id: SectionId; label: string; weight: number }[] = [
  { id: "intro", label: "Intro", weight: 1.6 },
  { id: "ecosystem", label: "Ecosystem", weight: 1.8 },
  { id: "discovery", label: "01 Discover", weight: 2.2 },
  { id: "surface", label: "02 Map", weight: 1.8 },
  { id: "testing", label: "03 Test", weight: 2.0 },
  { id: "threat", label: "04 Detect", weight: 1.8 },
  { id: "path", label: "05 Trace", weight: 3.2 },
  { id: "evidence", label: "06 Prove", weight: 1.7 },
  { id: "risk", label: "07 Assess", weight: 1.8 },
  { id: "remediation", label: "08 Fix", weight: 1.6 },
  { id: "verify", label: "09 Verify", weight: 1.6 },
  { id: "final", label: "Start", weight: 1.0 },
];
export const SECTION_INDEX = Object.fromEntries(SECTIONS.map((s, i) => [s.id, i])) as Record<SectionId, number>;

const TOTAL = SECTIONS.reduce((a, s) => a + s.weight, 0);
/** Document height in viewport heights; progress 0..1 spans (TOTAL - 1) because the last screen is visible at p = 1. */
export const totalViewports = () => TOTAL;
const cumulative = (() => { let c = 0; return SECTIONS.map((s) => { const start = c; c += s.weight; return start; }); })();

export const clamp01 = (x: number) => Math.min(1, Math.max(0, x));
export const smoothstep = (x: number) => { const t = clamp01(x); return t * t * (3 - 2 * t); };
export const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
/** 0 before `from`, 1 after `to`, eased in between. */
export const reveal = (p: number, from: number, to: number) => smoothstep((p - from) / Math.max(1e-6, to - from));

/** Scroll offset (in viewport heights) → progress 0..1. */
export const progressFromScroll = (scrollY: number, viewportH: number, docH: number): number => {
  const max = Math.max(1, docH - viewportH);
  return clamp01(scrollY / max);
};
/** Progress → scroll offset in px for jumping to a section. */
export function scrollTopForSection(i: number, viewportH: number): number {
  return cumulative[Math.max(0, Math.min(SECTIONS.length - 1, i))] * viewportH;
}
const sectionStartP = (i: number) => cumulative[i] / (TOTAL - 1);

/** [start, end] progress of a section. */
export const sectionRange = (id: SectionId): [number, number] => { const i = SECTION_INDEX[id]; return [sectionStartP(i), i === SECTIONS.length - 1 ? 1 : sectionStartP(i + 1)]; };

export interface Located { index: number; id: SectionId; local: number }
/** Which section is active and how far (0..1) we are through it. */
export function locate(p: number): Located {
  const pp = clamp01(p);
  let index = 0;
  for (let i = 0; i < SECTIONS.length; i++) if (pp >= sectionStartP(i) - 1e-9) index = i;
  const start = sectionStartP(index);
  const end = index === SECTIONS.length - 1 ? 1 : sectionStartP(index + 1);
  return { index, id: SECTIONS[index].id, local: clamp01((pp - start) / Math.max(1e-6, end - start)) };
}

// ---- camera ----------------------------------------------------------------------------
export interface StoryAnchors {
  /** Scene radius (world units). */
  R: number;
  /** Position of the most severe finding, if any. */
  threat: Vec3 | null;
  /** Ordered points of the top attack path in the scene, if the backend supports one. */
  path: Vec3[];
}
interface Key { target: Vec3 | "threat" | "pathStart" | "pathEnd"; dist: number; az: number; el: number }
const O: Vec3 = [0, 0, 0];

function keys(): Key[] {
  return [
    { target: O, dist: 2.7, az: 0.3, el: 0.28 },          // 0 intro
    { target: O, dist: 1.9, az: 0.95, el: 0.3 },          // 1 ecosystem
    { target: O, dist: 1.45, az: 1.6, el: 0.36 },         // 2 discovery
    { target: O, dist: 2.4, az: 2.3, el: 0.55 },          // 3 surface (pull back)
    { target: O, dist: 1.0, az: 3.2, el: 0.12 },          // 4 testing (travel through)
    { target: "threat", dist: 0.55, az: 3.9, el: 0.22 },  // 5 threat
    { target: "pathStart", dist: 0.42, az: 4.2, el: 0.2 },// 6 path
    { target: "pathEnd", dist: 0.34, az: 4.9, el: 0.18 }, // 7 evidence (frozen at the end)
    { target: O, dist: 2.7, az: 5.3, el: 0.7 },           // 8 risk (pull back to a landscape)
    { target: O, dist: 1.7, az: 5.7, el: 0.4 },           // 9 remediation
    { target: "threat", dist: 0.5, az: 6.1, el: 0.22 },   // 10 verify (return to the tool)
    { target: O, dist: 2.9, az: 6.8, el: 0.32 },          // 11 final
    { target: O, dist: 3.1, az: 7.0, el: 0.34 },          // end
  ];
}

const resolveTarget = (t: Key["target"], a: StoryAnchors): Vec3 =>
  t === "threat" ? a.threat ?? O : t === "pathStart" ? a.path[0] ?? a.threat ?? O : t === "pathEnd" ? a.path[a.path.length - 1] ?? a.threat ?? O : t;

/** Polyline position at t (0..1) by arc length. */
export function alongPath(points: Vec3[], t: number): Vec3 {
  if (points.length === 0) return O;
  if (points.length === 1) return points[0];
  const seg: number[] = [];
  let total = 0;
  for (let i = 1; i < points.length; i++) { const d = Math.hypot(points[i][0] - points[i - 1][0], points[i][1] - points[i - 1][1], points[i][2] - points[i - 1][2]); seg.push(d); total += d; }
  let want = clamp01(t) * total;
  for (let i = 0; i < seg.length; i++) {
    if (want <= seg[i] || i === seg.length - 1) {
      const k = seg[i] === 0 ? 0 : Math.min(1, want / seg[i]);
      const a = points[i]; const b = points[i + 1];
      return [lerp(a[0], b[0], k), lerp(a[1], b[1], k), lerp(a[2], b[2], k)];
    }
    want -= seg[i];
  }
  return points[points.length - 1];
}

export interface CameraPose { position: Vec3; target: Vec3 }
/** Camera pose at scroll progress p. Smooth between per-section keys; follows the attack path during the path section. */
export function cameraAt(p: number, anchors: StoryAnchors): CameraPose {
  const { index, local } = locate(p);
  const K = keys();
  const a = K[index]; const b = K[Math.min(K.length - 1, index + 1)];
  // Evidence: the scene holds still while the panel is read (first 60%), then eases toward the risk camera.
  const k = index === SECTION_INDEX.evidence ? smoothstep((local - 0.6) / 0.4) : smoothstep(local);
  const R = anchors.R;
  let target: Vec3;
  if (index === SECTION_INDEX.path && anchors.path.length > 1) target = alongPath(anchors.path, k);
  else { const ta = resolveTarget(a.target, anchors); const tb = resolveTarget(b.target, anchors); target = [lerp(ta[0], tb[0], k), lerp(ta[1], tb[1], k), lerp(ta[2], tb[2], k)]; }
  const dist = lerp(a.dist, b.dist, k) * R;
  const az = lerp(a.az, b.az, k);
  const el = lerp(a.el, b.el, k);
  const position: Vec3 = [target[0] + Math.sin(az) * Math.cos(el) * dist, target[1] + Math.sin(el) * dist, target[2] + Math.cos(az) * Math.cos(el) * dist];
  return { position, target };
}

/** Reduced motion / static: a single overview pose that shows the whole surface. */
export const staticPose = (anchors: StoryAnchors): CameraPose => cameraAt(sectionStartP(SECTION_INDEX.surface) + 0.0001, anchors);
