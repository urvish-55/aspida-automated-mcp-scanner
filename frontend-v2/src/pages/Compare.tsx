import { useQuery } from "@tanstack/react-query";
import { GitCompare } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import { ContextLoader, EmptyState, ErrorState, PageHeader, Pill, SeverityBadge } from "../components/ui";
import { fmtDateTime, humanize, riskBand, SEV_TEXT, cn } from "../lib/utils";
import { api } from "../services/api";
import { useScans } from "../state/queries";
import type { CompareFinding, CompareSide } from "../types";

function Side({ s, tag }: { s: CompareSide; tag: string }) {
  const band = riskBand(s.risk_score);
  return (
    <div className="card p-5">
      <div className="label">{tag}</div>
      <div className="mt-1 truncate font-medium">{s.label}</div><div className="text-[12px] text-dim">{fmtDateTime(s.created_at)} · {s.id.slice(0, 8)}</div>
      <div className={cn("mt-3 text-4xl font-semibold tabular-nums", SEV_TEXT[band.sev])}>{s.risk_score != null ? Math.round(s.risk_score) : "-"}<span className="ml-2 text-[11px] font-bold tracking-widest">{band.label}</span></div>
      <dl className="mt-3 grid grid-cols-3 gap-2 text-center"><div className="rounded-lg bg-raised p-2"><dt className="label">Findings</dt><dd className="text-lg font-semibold tabular-nums">{s.findings}</dd></div><div className="rounded-lg bg-raised p-2"><dt className="label">Critical</dt><dd className="text-lg font-semibold tabular-nums">{s.critical}</dd></div><div className="rounded-lg bg-raised p-2"><dt className="label">Tools</dt><dd className="text-lg font-semibold tabular-nums">{s.tools}</dd></div></dl>
    </div>
  );
}

function FList({ title, items, tone }: { title: string; items: CompareFinding[]; tone: string }) {
  return (
    <section className="card p-4"><h3 className={cn("mb-2 font-semibold", tone)}>{title} <span className="text-dim">({items.length})</span></h3>
      {items.length === 0 ? <p className="text-dim">None.</p> : <ul className="divide-y divide-line">{items.map((f, i) => <li key={`${f.id}-${i}`} className="flex items-center gap-3 py-2"><SeverityBadge severity={f.severity} /><span className="min-w-0 flex-1 truncate">{f.title}</span><span className="mono text-[12px] text-dim">{f.affected_tools[0] ?? ""}</span></li>)}</ul>}
    </section>
  );
}

export default function Compare() {
  const [sp, setSp] = useSearchParams();
  const a = sp.get("a") ?? ""; const b = sp.get("b") ?? "";
  const scans = useScans(200);
  const done = (scans.data?.items ?? []).filter((s) => s.status === "completed");
  const q = useQuery({ queryKey: ["compare", a, b], queryFn: () => api.compare(a, b), enabled: !!a && !!b && a !== b });
  const set = (k: string, v: string) => setSp((p) => { const n = new URLSearchParams(p); n.set(k, v); return n; }, { replace: true });
  const sel = (k: string, v: string, label: string) => (
    <label key={k} className="flex items-center gap-2"><span className="label">{label}</span>
      <select className="input !w-auto max-w-[300px]" value={v} onChange={(e) => set(k, e.target.value)}><option value="">Choose a scan…</option>{done.map((s) => <option key={s.id} value={s.id}>{(s.target_label || s.id.slice(0, 8)).slice(0, 36)} · {fmtDateTime(s.created_at)}</option>)}</select></label>
  );
  return (
    <div>
      <PageHeader title="Compare scans" sub="See what is new, resolved or changed between two scans." actions={<>{sel("a", a, "Scan A")}{sel("b", b, "Scan B")}</>} />
      {scans.isLoading ? <ContextLoader message="Loading scans…" /> : done.length < 2 ? (
        <EmptyState icon={<GitCompare className="h-6 w-6" />} title="Two completed scans are needed." body={`You have ${done.length} completed scan(s). Run another scan, then compare them here.`} action={{ label: "Start New Scan", to: "/scan" }} />
      ) : !a || !b ? <EmptyState icon={<GitCompare className="h-6 w-6" />} title="Choose two scans." body="Pick Scan A (baseline) and Scan B (newer) above." />
      : a === b ? <EmptyState title="Pick two different scans." body="Scan A and Scan B are the same scan." />
      : q.isLoading ? <ContextLoader message="Comparing findings, tools and capabilities…" />
      : q.error ? <ErrorState title="Comparison failed" message={(q.error as Error).message} onRetry={() => void q.refetch()} />
      : q.data && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2"><Side s={q.data.a} tag="Scan A" /><Side s={q.data.b} tag="Scan B" /></div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <FList title="New findings" items={q.data.new_findings} tone="text-sev-high" />
            <FList title="Resolved findings" items={q.data.resolved_findings} tone="text-ok" />
          </div>
          <section className="card p-4"><h3 className="mb-2 font-semibold">Changed severity <span className="text-dim">({q.data.changed_severity.length})</span></h3>
            {q.data.changed_severity.length === 0 ? <p className="text-dim">None.</p> : <ul className="divide-y divide-line">{q.data.changed_severity.map((f, i) => <li key={i} className="flex items-center gap-3 py-2"><span className="min-w-0 flex-1 truncate">{f.title}</span><SeverityBadge severity={f.from} /> → <SeverityBadge severity={f.to} /></li>)}</ul>}</section>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            <section className="card p-4"><h3 className="mb-2 font-semibold">Changed tools</h3>{q.data.tools_added.length + q.data.tools_removed.length + q.data.tools_changed.length === 0 ? <p className="text-dim">None.</p> : <ul className="space-y-1 text-[13px]">{q.data.tools_added.map((t) => <li key={t}><Pill tone="ok">added</Pill> <span className="mono">{t}</span></li>)}{q.data.tools_removed.map((t) => <li key={t}><Pill tone="bad">removed</Pill> <span className="mono">{t}</span></li>)}{q.data.tools_changed.map((t) => <li key={t.name}><Pill tone="warn">changed</Pill> <span className="mono">{t.name}</span> <span className="text-dim">{t.what}</span></li>)}</ul>}</section>
            <section className="card p-4 lg:col-span-2"><h3 className="mb-2 font-semibold">Changed capabilities</h3>{q.data.capabilities_changed.length === 0 ? <p className="text-dim">None.</p> : <ul className="space-y-1 text-[13px]">{q.data.capabilities_changed.map((c) => <li key={c.name}><span className="mono">{c.name}</span> {c.added.map((x) => <Pill key={x} tone="bad">+ {humanize(x)}</Pill>)} {c.removed.map((x) => <Pill key={x} tone="ok">− {humanize(x)}</Pill>)}</li>)}</ul>}</section>
          </div>
          <p className="text-[12px] text-dim">{q.data.note}</p>
        </div>
      )}
    </div>
  );
}
