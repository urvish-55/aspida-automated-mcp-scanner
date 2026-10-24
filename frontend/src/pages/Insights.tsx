import { Lightbulb } from "lucide-react";
import { useMemo } from "react";
import { Link } from "react-router-dom";
import { ScanPicker } from "../components/ScanPicker";
import { ContextLoader, EmptyState, PageHeader, SeverityBadge, Stat } from "../components/ui";
import { SEV_RANK, humanize } from "../lib/utils";
import { useActiveScan, useScanDetail } from "../state/queries";
import { TRIAGE_LABELS, type TriageStatus } from "../types";

export default function Insights() {
  const { scan, loading } = useActiveScan();
  const d = useScanDetail(scan?.id);
  const findings = useMemo(() => (d.data?.findings ?? []).filter((f) => f.status !== "informational" && f.category !== "engine" && !["not_tested", "not_applicable", "error"].includes(f.status)), [d.data]);
  const byTriage = useMemo(() => { const m: Record<string, number> = {}; findings.forEach((f) => { m[f.triage_status] = (m[f.triage_status] ?? 0) + 1; }); return m; }, [findings]);
  const fixes = useMemo(() => {
    const m = new Map<string, { text: string; n: number; worst: number; sev: string }>();
    findings.filter((f) => f.triage_status === "open" || f.triage_status === "acknowledged" || f.triage_status === "in_progress").forEach((f) => {
      const k = f.remediation.trim();
      if (!k) return;
      const e = m.get(k) ?? { text: k, n: 0, worst: 0, sev: "info" };
      e.n++; if (SEV_RANK[f.severity] > e.worst) { e.worst = SEV_RANK[f.severity]; e.sev = f.severity; }
      m.set(k, e);
    });
    return [...m.values()].sort((a, b) => b.worst - a.worst || b.n - a.n).slice(0, 8);
  }, [findings]);
  const tools = useMemo(() => { const m = new Map<string, number>(); findings.forEach((f) => f.affected_tools.forEach((t) => m.set(t, (m.get(t) ?? 0) + 1))); return [...m].sort((a, b) => b[1] - a[1]).slice(0, 6); }, [findings]);
  const cats = useMemo(() => { const m = new Map<string, number>(); findings.forEach((f) => m.set(f.category, (m.get(f.category) ?? 0) + 1)); return [...m].sort((a, b) => b[1] - a[1]); }, [findings]);

  if (loading || d.isLoading) return <ContextLoader message="Analyzing findings…" />;
  if (!scan) return <div><PageHeader title="Security insights" /><EmptyState icon={<Lightbulb className="h-6 w-6" />} title="No scans yet." body="Run your first MCP security scan to begin analyzing tools and capabilities." action={{ label: "Start New Scan", to: "/scan" }} /></div>;
  const resolved = (byTriage.resolved ?? 0) + (byTriage.false_positive ?? 0) + (byTriage.accepted_risk ?? 0);
  return (
    <div>
      <PageHeader title="Security insights" sub="What to fix first, derived from this scan's findings and your remediation tracking." actions={<ScanPicker />} />
      {findings.length === 0 ? <EmptyState title="No scored findings." body="The enabled tests found nothing to act on. This does not prove the target is secure." /> : (
        <>
          <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Stat label="Findings" value={findings.length} />
            <Stat label="Open" value={byTriage.open ?? 0} tone={byTriage.open ? "text-sev-high" : undefined} />
            <Stat label="In progress / ack." value={(byTriage.in_progress ?? 0) + (byTriage.acknowledged ?? 0)} />
            <Stat label="Closed out" value={`${resolved} / ${findings.length}`} hint="resolved, false positive or accepted" />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <section className="card p-4"><h2 className="mb-3 font-semibold">Fix these first</h2>
              {fixes.length === 0 ? <p className="text-dim">Nothing left open.</p> : <ol className="space-y-3">{fixes.map((f, i) => <li key={i} className="flex gap-3"><span className="mt-0.5 text-dim">{i + 1}.</span><div className="min-w-0"><div className="flex items-center gap-2"><SeverityBadge severity={f.sev} /><span className="text-[12px] text-dim">resolves {f.n} finding{f.n === 1 ? "" : "s"}</span></div><p className="mt-1 text-[13px]">{f.text}</p></div></li>)}</ol>}
            </section>
            <div className="space-y-4">
              <section className="card p-4"><h2 className="mb-3 font-semibold">Remediation progress</h2><ul className="space-y-1.5 text-[13px]">{(Object.keys(TRIAGE_LABELS) as TriageStatus[]).map((s) => <li key={s} className="flex justify-between"><Link className="hover:text-brand" to={`/findings?scan=${scan.id}&triage=${s}`}>{TRIAGE_LABELS[s]}</Link><span className="tabular-nums text-dim">{byTriage[s] ?? 0}</span></li>)}</ul></section>
              <section className="card p-4"><h2 className="mb-3 font-semibold">Most affected tools</h2>{tools.length === 0 ? <p className="text-dim">All findings are scan-wide.</p> : <ul className="space-y-1.5">{tools.map(([t, n]) => <li key={t} className="flex justify-between"><Link className="mono hover:text-brand" to={`/tools?scan=${scan.id}&tool=${encodeURIComponent(t)}`}>{t}</Link><span className="tabular-nums text-dim">{n}</span></li>)}</ul>}</section>
              <section className="card p-4"><h2 className="mb-3 font-semibold">Where the findings come from</h2><ul className="space-y-1.5">{cats.map(([c, n]) => <li key={c} className="flex justify-between"><Link className="hover:text-brand" to={`/findings?scan=${scan.id}&category=${c}`}>{humanize(c)}</Link><span className="tabular-nums text-dim">{n}</span></li>)}</ul></section>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
