import { create } from "zustand";
import { locate, type SectionId } from "../lib/storyTimeline";

/** Centralised scroll state for the story. Written by one scroll listener; the 3D scene reads it inside its frame loop without React renders. */
export interface StoryState {
  progress: number; // 0..1 over the whole page
  index: number;    // active section
  id: SectionId;
  local: number;    // 0..1 inside the active section
  /** Optional camera focus requested by clicking an object; cleared when the section changes. */
  focus: { pos: [number, number, number]; tick: number } | null;
  setFocus: (pos: [number, number, number] | null) => void;
  setProgress: (p: number) => void;
}
export const useStory = create<StoryState>((set, get) => ({
  progress: 0, index: 0, id: "intro", local: 0, focus: null,
  setFocus: (pos) => set((s) => ({ focus: pos ? { pos, tick: (s.focus?.tick ?? 0) + 1 } : null })),
  setProgress: (p) => {
    const l = locate(p);
    const s = get();
    if (s.progress === p) return;
    set({ progress: p, index: l.index, id: l.id, local: l.local, focus: l.index !== s.index ? null : s.focus });
  },
}));
