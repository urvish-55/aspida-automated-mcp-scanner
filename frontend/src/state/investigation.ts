import { create } from "zustand";
import { ALL_SEVERITIES, DEFAULT_KINDS, type EffectsPref, type GraphFilters, type NodeKind, type QualityPref, type VizMode } from "../types/visualization";
import type { Severity } from "../types";

/**
 * UI state for the 3D investigation views. Server data stays in TanStack Query; this store only holds
 * selection, filters and view preferences. It is a zustand store because React context does not cross the R3F Canvas.
 */
export interface InvestigationState {
  mode: VizMode;
  selectedId: string | null;
  hoveredId: string | null;
  /** Node the camera should fly to (set by search, list clicks, "View in 3D"). */
  focusId: string | null;
  focusTick: number; // bumps on every focus request so re-focusing the same node still animates
  isolateId: string | null;
  resetTick: number;
  tourTick: number;
  activePathId: string | null;
  filters: GraphFilters;
  quality: QualityPref;
  effects: EffectsPref;
  labels: boolean;
  force2D: boolean;
  setMode: (m: VizMode) => void;
  select: (id: string | null) => void;
  hover: (id: string | null) => void;
  focus: (id: string | null) => void;
  isolate: (id: string | null) => void;
  setActivePath: (id: string | null) => void;
  resetView: () => void;
  playTour: (pathId: string) => void;
  toggleSeverity: (s: Severity) => void;
  toggleKind: (k: NodeKind) => void;
  toggleCategory: (c: string) => void;
  setQuery: (q: string) => void;
  resetFilters: () => void;
  setQuality: (q: QualityPref) => void;
  setEffects: (e: EffectsPref) => void;
  setLabels: (b: boolean) => void;
  setForce2D: (b: boolean) => void;
  escape: () => void;
}

const KEY = "mcp-pentester-3d";
function loadPrefs(): Pick<InvestigationState, "quality" | "effects" | "labels" | "force2D"> {
  const d = { quality: "auto" as QualityPref, effects: "full" as EffectsPref, labels: true, force2D: false };
  try {
    const p = JSON.parse(localStorage.getItem(KEY) ?? "{}");
    return {
      quality: ["auto", "low", "medium", "high"].includes(p.quality) ? p.quality : d.quality,
      effects: ["full", "reduced", "off"].includes(p.effects) ? p.effects : d.effects,
      labels: typeof p.labels === "boolean" ? p.labels : d.labels,
      force2D: !!p.force2D,
    };
  } catch { return d; }
}
function savePrefs(s: InvestigationState) {
  try { localStorage.setItem(KEY, JSON.stringify({ quality: s.quality, effects: s.effects, labels: s.labels, force2D: s.force2D })); } catch { /* storage blocked */ }
}

export const defaultFilters = (): GraphFilters => ({ severities: [...ALL_SEVERITIES], kinds: [...DEFAULT_KINDS], categories: [], query: "" });
const toggle = <T,>(arr: T[], v: T) => (arr.includes(v) ? arr.filter((x) => x !== v) : [...arr, v]);

export const useInvestigation = create<InvestigationState>((set, get) => ({
  mode: "graph", selectedId: null, hoveredId: null, focusId: null, focusTick: 0, isolateId: null, activePathId: null, resetTick: 0, tourTick: 0,
  filters: defaultFilters(), ...loadPrefs(),
  setMode: (mode) => set({ mode, isolateId: null, activePathId: mode === "paths" ? get().activePathId : null }),
  select: (selectedId) => set({ selectedId }),
  hover: (hoveredId) => { if (get().hoveredId !== hoveredId) set({ hoveredId }); },
  focus: (focusId) => set((s) => ({ focusId, focusTick: s.focusTick + 1, selectedId: focusId ?? s.selectedId })),
  isolate: (isolateId) => set({ isolateId }),
  setActivePath: (activePathId) => set({ activePathId }),
  resetView: () => set((s) => ({ resetTick: s.resetTick + 1 })),
  playTour: (pathId) => set((s) => ({ activePathId: pathId, tourTick: s.tourTick + 1 })),
  toggleSeverity: (sev) => set((s) => ({ filters: { ...s.filters, severities: toggle(s.filters.severities, sev) } })),
  toggleKind: (k) => set((s) => ({ filters: { ...s.filters, kinds: toggle(s.filters.kinds, k) } })),
  toggleCategory: (c) => set((s) => ({ filters: { ...s.filters, categories: toggle(s.filters.categories, c) } })),
  setQuery: (query) => set((s) => ({ filters: { ...s.filters, query } })),
  resetFilters: () => set({ filters: defaultFilters() }),
  setQuality: (quality) => { set({ quality }); savePrefs(get()); },
  setEffects: (effects) => { set({ effects }); savePrefs(get()); },
  setLabels: (labels) => { set({ labels }); savePrefs(get()); },
  setForce2D: (force2D) => { set({ force2D }); savePrefs(get()); },
  // Esc: step back one level (isolation → path → selection).
  escape: () => {
    const s = get();
    if (s.isolateId) set({ isolateId: null });
    else if (s.activePathId) set({ activePathId: null });
    else if (s.selectedId) set({ selectedId: null });
  },
}));
