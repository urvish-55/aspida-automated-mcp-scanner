import { RotateCcw } from "lucide-react";
import { SEV_LABEL } from "../../lib/severity";
import { cn, humanize } from "../../lib/utils";
import { useInvestigation } from "../../state/investigation";
import { ALL_SEVERITIES, type NodeKind } from "../../types/visualization";

const KINDS: { id: NodeKind; label: string }[] = [
  { id: "server", label: "Server" }, { id: "tool", label: "Tools" }, { id: "capability", label: "Capabilities" }, { id: "finding", label: "Findings" },
];

function Chip({ on, onClick, children, sev }: { on: boolean; onClick: () => void; children: React.ReactNode; sev?: string }) {
  return (
    <button type="button" aria-pressed={on} onClick={onClick}
      className={cn("rounded-md border px-2 py-1 text-[12px] transition", on ? "border-brand/60 bg-brand/10 text-fg" : "border-line text-dim line-through decoration-dim/60 hover:text-fg")}>
      {sev && <span aria-hidden className="mr-1 inline-block h-2 w-2 rounded-sm" style={{ background: `hsl(var(--sev-${sev}))` }} />}
      {children}
    </button>
  );
}

export function FilterPanel({ categories, hidden, total }: { categories: string[]; hidden: number; total: number }) {
  const { filters, toggleSeverity, toggleKind, toggleCategory, setQuery, resetFilters } = useInvestigation();
  const active = filters.severities.length < 5 || filters.kinds.length < 4 || filters.categories.length > 0 || filters.query !== "";
  return (
    <section aria-label="Graph filters" className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="label">Filters</h2>
        <button className="btn-ghost !px-1.5 !py-0.5 text-[12px]" onClick={resetFilters} disabled={!active}><RotateCcw className="h-3 w-3" aria-hidden /> Reset</button>
      </div>
      <div>
        <label htmlFor="g-search" className="label mb-1 block">Find in graph</label>
        <input id="g-search" className="input" placeholder="Tool, finding, rule, category…" value={filters.query} onChange={(e) => setQuery(e.target.value)} />
      </div>
      <fieldset><legend className="label mb-1.5">Finding severity</legend>
        <div className="flex flex-wrap gap-1.5">{ALL_SEVERITIES.map((s) => <Chip key={s} sev={s} on={filters.severities.includes(s)} onClick={() => toggleSeverity(s)}>{SEV_LABEL[s]}</Chip>)}</div>
      </fieldset>
      <fieldset><legend className="label mb-1.5">Object types</legend>
        <div className="flex flex-wrap gap-1.5">{KINDS.map((k) => <Chip key={k.id} on={filters.kinds.includes(k.id)} onClick={() => toggleKind(k.id)}>{k.label}</Chip>)}</div>
      </fieldset>
      {categories.length > 0 && (
        <fieldset><legend className="label mb-1.5">Finding category</legend>
          <div className="flex flex-wrap gap-1.5">{categories.map((c) => <Chip key={c} on={filters.categories.length === 0 || filters.categories.includes(c)} onClick={() => toggleCategory(c)}>{humanize(c)}</Chip>)}</div>
          {filters.categories.length > 0 && <p className="mt-1 text-[11.5px] text-dim">Showing only selected categories.</p>}
        </fieldset>
      )}
      <p className="text-[12px] text-dim" role="status">{hidden > 0 ? `${hidden} of ${total} objects hidden by filters.` : `${total} objects shown.`}</p>
    </section>
  );
}
