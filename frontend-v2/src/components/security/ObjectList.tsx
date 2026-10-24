import { useVirtualizer } from "@tanstack/react-virtual";
import { useRef } from "react";
import type { SceneItem } from "../../lib/sceneModel";
import { SEV_GLYPH, SEV_LABEL } from "../../lib/severity";
import { cn } from "../../lib/utils";
import { useInvestigation } from "../../state/investigation";

const KIND: Record<string, string> = { server: "Server", tool: "Tool", capability: "Capability", finding: "Finding", resource: "Resource", pathnode: "Path stage", cell: "Risk cell", stage: "Stage" };

/** Text equivalent of the 3D scene: every object, keyboard-operable, synced with the scene's selection. */
export function ObjectList({ items, label = "Objects in this view" }: { items: SceneItem[]; label?: string }) {
  const sel = useInvestigation((s) => s.selectedId);
  const select = useInvestigation((s) => s.select);
  const focus = useInvestigation((s) => s.focus);
  const hover = useInvestigation((s) => s.hover);
  const ref = useRef<HTMLDivElement>(null);
  const v = useVirtualizer({ count: items.length, getScrollElement: () => ref.current, estimateSize: () => 40, overscan: 8 });
  return (
    <div>
      <h2 className="label mb-2">{label} ({items.length})</h2>
      <div ref={ref} className="max-h-[320px] overflow-auto rounded-lg border border-line" role="list" aria-label={label} tabIndex={-1}>
        <div style={{ height: v.getTotalSize(), position: "relative" }}>
          {v.getVirtualItems().map((row) => {
            const i = items[row.index];
            return (
              <div key={i.id} role="listitem" style={{ position: "absolute", top: 0, left: 0, right: 0, transform: `translateY(${row.start}px)`, height: row.size }}>
                <button
                  className={cn("flex h-full w-full items-center gap-2 border-b border-line/60 px-3 text-left text-[12.5px] hover:bg-raised focus-visible:bg-raised", sel === i.id && "bg-brand/10")}
                  aria-pressed={sel === i.id}
                  onClick={() => { select(i.id); focus(i.id); }}
                  onMouseEnter={() => hover(i.id)} onMouseLeave={() => hover(null)} onFocus={() => hover(i.id)} onBlur={() => hover(null)}
                >
                  <span className="w-20 shrink-0 text-dim">{KIND[i.kind] ?? i.kind}</span>
                  <span className="min-w-0 flex-1 truncate">{i.label}</span>
                  {i.level !== "none" && <span className="shrink-0 rounded border border-line px-1.5 text-[11px] font-semibold" style={{ color: `hsl(var(--sev-${i.level}))` }}>{SEV_GLYPH[i.level]} {SEV_LABEL[i.level]}</span>}
                  {i.ghost && <span className="shrink-0 text-[11px] text-dim">not evidenced</span>}
                </button>
              </div>
            );
          })}
        </div>
        {items.length === 0 && <p className="p-3 text-dim">Nothing to list.</p>}
      </div>
    </div>
  );
}
