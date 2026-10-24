import { Html } from "@react-three/drei";
import { useMemo } from "react";
import type { Emphasis } from "../../lib/highlight";
import type { SceneItem, SceneLabel } from "../../lib/sceneModel";
import { SEV_GLYPH, SEV_LABEL } from "../../lib/severity";

const KIND_LABEL: Record<string, string> = { server: "Server", tool: "Tool", capability: "Capability", finding: "Finding", resource: "Resource", pathnode: "Path stage", cell: "Risk cell", stage: "Pipeline stage" };

/** Text labels: a budgeted set of the most important items, the focused/related ones, scene annotations, and the hover tooltip. */
export function Labels({ items, labels, emphasis, hidden, budget, show, hoveredId, selectedId }: {
  items: SceneItem[]; labels: SceneLabel[]; emphasis: Map<string, Emphasis>; hidden: Set<string>; budget: number; show: boolean; hoveredId: string | null; selectedId: string | null;
}) {
  const chosen = useMemo(() => {
    const out = new Map<string, SceneItem>();
    for (const i of items) if (!hidden.has(i.id) && (emphasis.get(i.id) === "focus" || (emphasis.get(i.id) === "related" && out.size < budget * 1.5 && (selectedId || hoveredId)))) out.set(i.id, i);
    if (show) [...items].filter((i) => !hidden.has(i.id) && emphasis.get(i.id) !== "dim").sort((a, b) => b.labelPriority - a.labelPriority).slice(0, budget).forEach((i) => out.set(i.id, i));
    return [...out.values()];
  }, [items, emphasis, hidden, budget, show, selectedId, hoveredId]);
  const hovered = hoveredId ? items.find((i) => i.id === hoveredId) : undefined;

  return (
    <>
      {chosen.map((i) => (
        <Html key={i.id} position={[i.pos[0], i.pos[1] + Math.max(...i.scale) * 1.5, i.pos[2]]} center zIndexRange={[10, 0]} style={{ pointerEvents: "none" }}>
          <div className={`max-w-[180px] truncate rounded px-1.5 py-0.5 text-[10.5px] leading-tight shadow ${emphasis.get(i.id) === "focus" ? "bg-brand text-bg font-semibold" : "bg-panel/90 text-fg"}`}>{i.label}</div>
        </Html>
      ))}
      {labels.map((l) => (
        <Html key={l.id} position={l.pos} center zIndexRange={[8, 0]} style={{ pointerEvents: "none" }}>
          <div className="whitespace-nowrap rounded border border-line bg-panel/90 px-1.5 py-0.5 text-[10.5px] text-dim">{l.text}</div>
        </Html>
      ))}
      {hovered && (
        <Html position={[hovered.pos[0], hovered.pos[1] - Math.max(...hovered.scale) * 1.4, hovered.pos[2]]} center zIndexRange={[30, 20]} style={{ pointerEvents: "none" }}>
          <div className="w-max max-w-[260px] rounded-lg border border-line bg-raised px-2.5 py-1.5 text-[11.5px] shadow-lg" role="tooltip">
            <div className="font-semibold text-fg">{hovered.label}</div>
            <div className="text-dim">{KIND_LABEL[hovered.kind] ?? hovered.kind}{hovered.level !== "none" ? ` · ${SEV_GLYPH[hovered.level]} ${SEV_LABEL[hovered.level]}` : ""}{hovered.ghost ? " · not evidenced" : ""}</div>
          </div>
        </Html>
      )}
    </>
  );
}
