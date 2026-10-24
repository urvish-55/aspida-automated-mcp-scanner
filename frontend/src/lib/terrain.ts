import type { Finding, Severity } from "../types";

const STATIC_POINTS: Record<Severity, number> = { critical: 20, high: 12, medium: 6, low: 2, info: 0 };
const DYNAMIC_POINTS: Record<Severity, number> = { critical: 30, high: 20, medium: 10, low: 4, info: 0 };

export interface TerrainCell { category: string; severity: Severity; points: number; findingIds: string[] }

/**
 * Raw RISK-1 points per (category × severity), computed from stored findings with the backend's own point table.
 * These are the values BEFORE the section caps (static 40 / dynamic 35 / capability 20) and are not the scan score.
 * Findings the scorer ignores (engine category, error / not_tested / not_applicable) contribute 0, like the backend.
 */
export function terrainCells(findings: Finding[]): TerrainCell[] {
  const map = new Map<string, TerrainCell>();
  for (const f of findings) {
    if (f.category === "engine" || ["error", "not_tested", "not_applicable", "informational"].includes(f.status)) continue;
    const dynamic = f.detector_sources.some((s) => s.startsWith("DYN-")) && f.status === "confirmed";
    const pts = (dynamic ? DYNAMIC_POINTS : STATIC_POINTS)[f.severity] ?? 0;
    const key = `${f.category}|${f.severity}`;
    const cell = map.get(key) ?? { category: f.category, severity: f.severity, points: 0, findingIds: [] };
    cell.points += pts;
    cell.findingIds.push(f.id);
    map.set(key, cell);
  }
  return [...map.values()];
}
