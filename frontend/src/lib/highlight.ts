import type { SceneLine, SceneModel } from "./sceneModel";

export type Emphasis = "normal" | "focus" | "related" | "dim";

export interface HighlightInput {
  selectedId: string | null;
  hoveredId: string | null;
  activePathId: string | null;
  isolateId: string | null;
  /** Optional overlay (scan comparison): these ids are emphasised, the rest dimmed, when nothing else is selected. */
  markedIds?: ReadonlySet<string>;
}
export interface HighlightResult {
  item: Map<string, Emphasis>;
  line: Map<string, Emphasis>;
  /** Items hidden entirely by isolation. */
  hidden: Set<string>;
}

/**
 * Selection / hover / attack-path emphasis, computed from the model alone.
 * Selected or hovered → that node is `focus`, its direct neighbours `related`, everything else `dim`.
 * Active attack path → every item/line of that path is `related`, the rest `dim`.
 * Isolation → everything not adjacent to the isolated node is hidden.
 */
export function computeHighlight(model: SceneModel, h: HighlightInput): HighlightResult {
  const item = new Map<string, Emphasis>();
  const line = new Map<string, Emphasis>();
  const hidden = new Set<string>();
  const adj = new Map<string, Set<string>>();
  const link = (a: string, b: string) => { (adj.get(a) ?? adj.set(a, new Set()).get(a)!).add(b); (adj.get(b) ?? adj.set(b, new Set()).get(b)!).add(a); };
  for (const l of model.lines) link(l.a, l.b);

  if (h.isolateId) {
    const keep = new Set<string>([h.isolateId, ...(adj.get(h.isolateId) ?? [])]);
    // one more hop so a tool's findings and capabilities stay visible when a server/tool is isolated
    for (const id of [...keep]) for (const n of adj.get(id) ?? []) if (id === h.isolateId || model.items.find((i) => i.id === id)?.kind === "tool") keep.add(n);
    for (const i of model.items) if (!keep.has(i.id)) hidden.add(i.id);
  }
  const focusId = h.hoveredId ?? h.selectedId;
  const near = focusId ? new Set<string>([focusId, ...(adj.get(focusId) ?? [])]) : null;
  const pathId = h.activePathId;
  const lineOn = (l: SceneLine): Emphasis => {
    if (hidden.has(l.a) || hidden.has(l.b)) return "dim";
    if (pathId) return l.pathIds.includes(pathId) ? "related" : "dim";
    if (!near && h.markedIds && h.markedIds.size) return h.markedIds.has(l.a) && h.markedIds.has(l.b) ? "related" : "dim";
    if (near) return l.a === focusId || l.b === focusId ? "related" : "dim";
    return "normal";
  };
  for (const i of model.items) {
    let e: Emphasis = "normal";
    if (pathId) e = i.pathIds.includes(pathId) ? (i.id === focusId ? "focus" : "related") : "dim";
    else if (near) e = i.id === focusId ? "focus" : near.has(i.id) ? "related" : "dim";
    else if (h.markedIds && h.markedIds.size) e = h.markedIds.has(i.id) ? "related" : "dim";
    if (h.selectedId === i.id && e !== "focus") e = "focus";
    item.set(i.id, e);
  }
  for (const l of model.lines) line.set(l.id, lineOn(l));
  return { item, line, hidden };
}
