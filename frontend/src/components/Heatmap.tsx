import { cn, SEV_BG, SEV_SOFT } from "../lib/utils";
import type { HeatCell } from "../types";
import { Tip } from "./ui";

const CELL: Record<string, string> = {
  none: "bg-raised/50 text-dim",
  info: "bg-sev-info/25",
  low: "bg-sev-low",
  medium: "bg-sev-medium",
  high: "bg-sev-high",
  critical: "bg-sev-critical",
};
const LEVEL_LABEL: Record<string, string> = { none: "No signal", info: "Capability present", low: "Low", medium: "Medium", high: "High", critical: "Critical" };

export function Heatmap({ columns, rows, onOpenTool }: { columns: { id: string; label: string }[]; rows: { tool: string; cells: HeatCell[] }[]; onOpenTool: (tool: string, cell: HeatCell) => void }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-separate border-spacing-1 text-[12.5px]" aria-label="Security heatmap: tools by risk category">
        <thead>
          <tr>
            <th className="sticky left-0 bg-panel px-2 py-1 text-left"><span className="label">Tool</span></th>
            {columns.map((c) => <th key={c.id} className="px-1 py-1 text-center"><span className="label">{c.label}</span></th>)}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.tool}>
              <th scope="row" className="sticky left-0 max-w-[220px] truncate bg-panel px-2 py-1 text-left font-mono text-[12px] font-medium" title={r.tool}>{r.tool}</th>
              {r.cells.map((c) => (
                <td key={c.column} className="p-0">
                  <Tip side="top" label={
                    `${r.tool} · ${columns.find((x) => x.id === c.column)?.label}: ${LEVEL_LABEL[c.level]}` +
                    (c.evidence.length ? `\n${c.evidence.slice(0, 3).join("\n")}` : "")
                  }>
                    <button onClick={() => onOpenTool(r.tool, c)} aria-label={`${r.tool}, ${columns.find((x) => x.id === c.column)?.label}: ${LEVEL_LABEL[c.level]}`}
                      className={cn("h-9 w-full min-w-[64px] rounded-md border border-transparent transition hover:border-fg/60 focus-visible:border-fg", CELL[c.level])}>
                      {c.level === "none" ? <span aria-hidden>-</span> : <span className={cn("text-[10.5px] font-bold uppercase tracking-wide", c.level === "info" ? "text-fg" : "text-bg")}>{c.level === "info" ? "cap" : c.level}</span>}
                    </button>
                  </Tip>
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="mt-3 flex flex-wrap items-center gap-3 text-[11.5px] text-dim">
        {(["none", "info", "low", "medium", "high", "critical"] as const).map((l) => (
          <span key={l} className="inline-flex items-center gap-1.5"><span className={cn("h-3 w-3 rounded", CELL[l], l !== "none" && SEV_BG[l] && "")} /> {LEVEL_LABEL[l]}</span>
        ))}
      </div>
    </div>
  );
}
export { SEV_SOFT };
