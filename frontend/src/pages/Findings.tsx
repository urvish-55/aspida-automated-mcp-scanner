import { useVirtualizer } from "@tanstack/react-virtual";
import { useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, FileSearch, Filter, Search, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { InvestigationDrawer } from "../components/Investigation";
import { ConfidenceBadge, EmptyState, ErrorState, PageHeader, SeverityBadge, Skeleton, TriagePill } from "../components/ui";
import { api } from "../services/api";
import { useFindingsQuery } from "../state/queries";
import { cn, humanize, SEV_BG, timeAgo } from "../lib/utils";
import type { FindingRow } from "../types";
import { TRIAGE_LABELS } from "../types";

const PAGE = 200;
const DIMS: { key: string; label: string; fmt?: (v: string) => string }[] = [
  { key: "severity", label: "Severity" },
  { key: "category", label: "Category", fmt: humanize },
  { key: "status", label: "Detector status", fmt: humanize },
  { key: "triage", label: "Remediation", fmt: (v) => TRIAGE_LABELS[v as keyof typeof TRIAGE_LABELS] ?? humanize(v) },
  { key: "confidence", label: "Confidence" },
  { key: "tool", label: "Tool" },
];
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => { const t = setTimeout(() => setD(v), ms); return () => clearTimeout(t); }, [v, ms]);
  return d;
}

function FindingCard({ f, onOpen, selected }: { f: FindingRow; onOpen: () => void; selected: boolean }) {
  return (
    <button onClick={onOpen} className={cn("card relative flex h-[148px] w-full flex-col gap-1.5 overflow-hidden p-4 pl-5 text-left transition hover:border-brand/60", selected && "border-brand")} aria-label={`${f.severity} finding: ${f.title}`}>
      <span className={cn("absolute left-0 top-0 h-full w-1", SEV_BG[f.severity])} aria-hidden />
      <div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><ConfidenceBadge value={f.confidence} /><TriagePill status={f.triage_status} /><span className="ml-auto text-[11px] text-dim">{f.rule_id}</span></div>
      <div className="truncate font-semibold">{f.title}</div>
      <div className="flex items-center gap-4 text-[12.5px] text-dim">
        <span className="truncate">Tool: <span className="mono text-fg">{f.affected_tools.join(", ") || "scan-wide"}</span></span>
        <span className="shrink-0">Evidence available: {f.evidence.length}</span>
        <span className="hidden shrink-0 sm:inline">{humanize(f.category)}</span>
      </div>
      <div className="mt-auto flex items-center justify-between pt-1 text-[12px]"><span className="truncate text-dim">{f.scan_label} · {timeAgo(f.scan_created_at)}</span><span className="text-brand">View investigation →</span></div>
    </button>
  );
}

export default function Findings() {
  const [sp, setSp] = useSearchParams();
  const scan = sp.get("scan") ?? "";
  const open = sp.get("open") ?? "";
  const page = Number(sp.get("page") ?? "0") || 0;
  const [qText, setQText] = useState(sp.get("q") ?? "");
  const dq = useDebounced(qText.trim(), 250);

  const filters = useMemo(() => Object.fromEntries(DIMS.map((d) => [d.key, sp.get(d.key) ?? ""])) as Record<string, string>, [sp]);
  const setParam = (k: string, v: string | null) => setSp((p) => { const n = new URLSearchParams(p); if (v) n.set(k, v); else n.delete(k); if (k !== "page" && k !== "open") n.delete("page"); return n; }, { replace: true });
  useEffect(() => { if ((sp.get("q") ?? "") !== dq) setParam("q", dq || null); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [dq]);

  const since = sp.get("since") ?? "";
  const sinceIso = since ? new Date(Date.now() - Number(since) * 86400000).toISOString() : undefined;
  const q = useFindingsQuery({ scan_id: scan || undefined, severity: filters.severity, category: filters.category, status: filters.status, triage: filters.triage, confidence: filters.confidence, tool: filters.tool, q: sp.get("q") ?? "", since: sinceIso && since ? sinceIso.slice(0, 10) : undefined, include_info: sp.get("info") === "1", limit: PAGE, offset: page * PAGE });
  const items = q.data?.items ?? [];
  const total = q.data?.total ?? 0;

  const parent = useRef<HTMLDivElement>(null);
  const virt = useVirtualizer({ count: items.length, getScrollElement: () => parent.current, estimateSize: () => 160, overscan: 6 });

  const openFromList = items.find((f) => f.id === open);
  const fetched = useQuery({ queryKey: ["finding", open], queryFn: () => api.finding(open), enabled: !!open && !openFromList });
  const openFinding = openFromList ?? fetched.data ?? null;

  const toggleVal = (k: string, v: string) => {
    const cur = new Set((filters[k] || "").split(",").filter(Boolean));
    if (cur.has(v)) cur.delete(v); else cur.add(v);
    setParam(k, [...cur].join(",") || null);
  };
  const chips = DIMS.flatMap((d) => (filters[d.key] || "").split(",").filter(Boolean).map((v) => ({ k: d.key, v, label: `${d.label}: ${d.fmt ? d.fmt(v) : v}` })));
  if (scan) chips.unshift({ k: "scan", v: scan, label: `Scan: ${scan.slice(0, 8)}` });
  if (sp.get("q")) chips.push({ k: "q", v: "", label: `Search: ${sp.get("q")}` });
  if (since) chips.push({ k: "since", v: "", label: `Last ${since} days` });
  const removeChip = (c: { k: string; v: string }) => {
    if (c.k === "scan" || c.k === "q" || c.k === "since") { if (c.k === "q") setQText(""); setParam(c.k, null); return; }
    toggleVal(c.k, c.v);
  };
  const clearAll = () => { setQText(""); setSp(new URLSearchParams(), { replace: true }); };

  const facets = q.data?.facets ?? {};

  return (
    <div>
      <PageHeader title="Findings" sub="Filter, open and triage evidence-backed findings across scans." />
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-[250px_minmax(0,1fr)]">
        <aside className="card h-fit p-4 lg:sticky lg:top-20" aria-label="Filters">
          <div className="mb-3 flex items-center gap-2"><Filter className="h-4 w-4 text-brand" /><h2 className="font-semibold">Filters</h2>{chips.length > 0 && <button className="ml-auto text-[12px] text-brand hover:underline" onClick={clearAll}>Clear all</button>}</div>
          <label className="relative mb-4 block"><Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-dim" aria-hidden /><input className="input !pl-8" placeholder="Search findings" value={qText} onChange={(e) => setQText(e.target.value)} aria-label="Search findings" /></label>
          <div className="mb-4"><div className="label mb-1.5">Date</div>
            <select className="input" value={since} onChange={(e) => setParam("since", e.target.value || null)} aria-label="Date range"><option value="">Any time</option><option value="1">Last 24 hours</option><option value="7">Last 7 days</option><option value="30">Last 30 days</option></select></div>
          <label className="mb-4 flex cursor-pointer items-center gap-2 text-[13px]"><input type="checkbox" className="accent-[hsl(var(--brand))]" checked={sp.get("info") === "1"} onChange={(e) => setParam("info", e.target.checked ? "1" : null)} /> Include informational</label>
          {DIMS.map((d) => {
            const entries = Object.entries(facets[d.key] ?? {}).sort((a, b) => d.key === "severity" ? SEV_ORDER.indexOf(a[0]) - SEV_ORDER.indexOf(b[0]) : b[1] - a[1]);
            const sel = new Set((filters[d.key] || "").split(",").filter(Boolean));
            const merged = [...entries, ...[...sel].filter((s) => !entries.some(([k]) => k === s)).map((s) => [s, 0] as [string, number])];
            if (merged.length === 0) return null;
            return (
              <fieldset key={d.key} className="mb-4"><legend className="label mb-1.5">{d.label}</legend>
                <div className="max-h-44 space-y-0.5 overflow-y-auto pr-1">
                  {merged.slice(0, 40).map(([val, n]) => (
                    <label key={val} className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-[13px] hover:bg-raised">
                      <input type="checkbox" className="accent-[hsl(var(--brand))]" checked={sel.has(val)} onChange={() => toggleVal(d.key, val)} />
                      <span className="min-w-0 flex-1 truncate capitalize">{d.fmt ? d.fmt(val) : val}</span><span className="tabular-nums text-dim">{n}</span>
                    </label>
                  ))}
                </div>
              </fieldset>
            );
          })}
          {Object.keys(facets).length === 0 && !q.isLoading && <p className="text-[12.5px] text-dim">Filter options appear when findings exist.</p>}
        </aside>

        <section aria-label="Findings list" className="min-w-0">
          {chips.length > 0 && (
            <div className="mb-3 flex flex-wrap gap-2" aria-label="Active filters">
              {chips.map((c) => <button key={`${c.k}-${c.v}`} className="chip hover:border-sev-critical/60 hover:text-fg" onClick={() => removeChip(c)} aria-label={`Remove filter ${c.label}`}>{c.label} <X className="h-3 w-3" /></button>)}
            </div>
          )}
          <div className="mb-2 flex items-center justify-between text-[12.5px] text-dim" aria-live="polite">
            <span>{q.isLoading ? "Loading…" : `${total.toLocaleString()} finding${total === 1 ? "" : "s"}`}{q.isFetching && !q.isLoading && " · updating"}</span>
            {total > PAGE && (
              <span className="flex items-center gap-1">
                <button className="btn-ghost !p-1" disabled={page === 0} onClick={() => setParam("page", String(page - 1))} aria-label="Previous page"><ChevronLeft className="h-4 w-4" /></button>
                Page {page + 1} / {Math.ceil(total / PAGE)}
                <button className="btn-ghost !p-1" disabled={(page + 1) * PAGE >= total} onClick={() => setParam("page", String(page + 1))} aria-label="Next page"><ChevronRight className="h-4 w-4" /></button>
              </span>
            )}
          </div>
          {q.error ? <ErrorState title="Findings could not be loaded" message={(q.error as Error).message} onRetry={() => void q.refetch()} />
            : q.isLoading ? <div className="space-y-3">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-[148px]" />)}</div>
            : items.length === 0 ? (
              chips.length > 0
                ? <EmptyState icon={<FileSearch className="h-6 w-6" />} title="No findings match these filters." body="Remove a filter chip or clear all filters to see more." />
                : <EmptyState icon={<FileSearch className="h-6 w-6" />} title="No findings yet." body={<>Findings appear here after a scan. <Link className="text-brand hover:underline" to="/scan">Start a scan</Link>.</>} />
            ) : (
              <div ref={parent} className="max-h-[calc(100vh-190px)] min-h-[300px] overflow-y-auto pr-1" tabIndex={-1}>
                <div style={{ height: virt.getTotalSize(), position: "relative" }}>
                  {virt.getVirtualItems().map((v) => {
                    const f = items[v.index];
                    return <div key={f.id} className="absolute left-0 top-0 w-full pb-3" style={{ transform: `translateY(${v.start}px)`, height: v.size }}><FindingCard f={f} selected={f.id === open} onOpen={() => setParam("open", f.id)} /></div>;
                  })}
                </div>
              </div>
            )}
        </section>
      </div>
      <InvestigationDrawer finding={openFinding} scanId={openFinding ? (openFinding as FindingRow).scan_id : null} onClose={() => setParam("open", null)} />
    </div>
  );
}
