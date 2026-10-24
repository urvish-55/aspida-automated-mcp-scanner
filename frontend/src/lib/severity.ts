import type { Severity } from "../types";
import type { SeverityOrNone } from "../types/visualization";

/** HSL triples copied from the CSS tokens in index.css (WebGL cannot read CSS variables); keep in sync. */
const HSL = {
  dark: { critical: [0, 84, 73], high: [24, 95, 58], medium: [45, 93, 54], low: [210, 90, 62], info: [218, 14, 64], none: [218, 14, 50], bg: [222, 30, 6], line: [222, 20, 18], brand: [172, 78, 52], server: [214, 32, 92], cap: [265, 70, 72] },
  light: { critical: [0, 72, 40], high: [22, 90, 36], medium: [40, 90, 26], low: [212, 80, 40], info: [218, 12, 38], none: [218, 12, 50], bg: [210, 25, 97], line: [214, 22, 86], brand: [174, 80, 23], server: [222, 35, 14], cap: [265, 55, 42] },
} as const;

export function hslToHex([h, s, l]: readonly [number, number, number] | readonly number[]): string {
  const S = s / 100; const L = l / 100;
  const k = (n: number) => (n + h / 30) % 12;
  const a = S * Math.min(L, 1 - L);
  const f = (n: number) => Math.round(255 * (L - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)))));
  return `#${[f(0), f(8), f(4)].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}
export type Theme = "dark" | "light";
export const themeHex = (theme: Theme, key: keyof (typeof HSL)["dark"]): string => hslToHex(HSL[theme][key]);

export const SEV_COLORS_DARK = Object.fromEntries((["critical", "high", "medium", "low", "info", "none"] as const).map((k) => [k, themeHex("dark", k)])) as Record<SeverityOrNone, string>;
export const SEV_COLORS_LIGHT = Object.fromEntries((["critical", "high", "medium", "low", "info", "none"] as const).map((k) => [k, themeHex("light", k)])) as Record<SeverityOrNone, string>;
export const SEV_LABEL: Record<SeverityOrNone, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", none: "None",
};
/** Severity is never colour-only: each level has a letter and a distinct 3D geometry. */
export const SEV_GLYPH: Record<SeverityOrNone, string> = { critical: "C", high: "H", medium: "M", low: "L", info: "I", none: "–" };
export const SEV_RANK: Record<SeverityOrNone, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 };

export function maxSeverity(levels: Iterable<SeverityOrNone>): SeverityOrNone {
  let best: SeverityOrNone = "none";
  for (const l of levels) if (SEV_RANK[l] > SEV_RANK[best]) best = l;
  return best;
}

export function asSeverity(s: string | null | undefined): Severity | null {
  return s === "critical" || s === "high" || s === "medium" || s === "low" || s === "info" ? s : null;
}

export function sevColor(level: SeverityOrNone, theme: Theme): string {
  return (theme === "dark" ? SEV_COLORS_DARK : SEV_COLORS_LIGHT)[level];
}
