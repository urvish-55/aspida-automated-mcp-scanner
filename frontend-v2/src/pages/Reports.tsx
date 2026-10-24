import { useMutation, useQuery } from "@tanstack/react-query";
import { Box, Download, FileJson, FileText } from "lucide-react";
import { Link } from "react-router-dom";
import { useEffect, useRef, useState } from "react";
import { ScanPicker } from "../components/ScanPicker";
import { ContextLoader, EmptyState, ErrorState, PageHeader, Pill, SeverityBadge } from "../components/ui";
import { api } from "../services/api";
import { useActiveScan, useAnalysis, useScanDetail } from "../state/queries";
import { cn, fmtDateTime, humanize, riskBand, SEV_TEXT, SEVERITIES } from "../lib/utils";
import { AttackPathView } from "../components/AttackPathView";
import { RiskGauge } from "../components/RiskGauge";

const SECTIONS = ["Executive Summary", "Risk", "Findings", "Evidence", "Attack Paths", "Recommendations", "Limitations"] as const;
const id = (s: string) => `rep-${s.toLowerCase().replace(/ /g, "-")}`;

export default function Reports() {
  const { scan, loading } = useActiveScan();
  const d = useScanDetail(scan?.id);
  const a = useAnalysis(scan?.id);
  const report = useQuery({ queryKey: ["report", scan?.id], queryFn: () => api.report(scan?.id as string), enabled: !!scan && scan.status !== "running" && scan.status !== "queued" });
  const dl = useMutation({ mutationFn: (kind: "pdf" | "json") => api.downloadReport(scan?.id as string, kind) });
  const [active, setActive] = useState<string>(SECTIONS[0]);
  const root = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const els = SECTIONS.map((s) => document.getElementById(id(s))).filter(Boolean) as HTMLElement[];
    if (!els.length) return;
    const io = new IntersectionObserver((es) => { const v = es.filter((e) => e.isIntersecting).sort((x, y) => x.boundingClientRect.top - y.boundingClientRect.top)[0]; if (v) setActive(SECTIONS.find((s) => id(s) === v.target.id) ?? SECTIONS[0]); }, { rootMargin: "-80px 0px -60% 0px" });
    els.forEach((e) => io.observe(e));
    return () => io.disconnect();
  }, [d.data, report.data]);

  if (loading || d.isLoading) return <ContextLoader message="Generating security report…" />;
  if (!scan || !d.data) return <div><PageHeader title="Reports" /><EmptyState icon={<FileText className="h-6 w-6" />} title="No scans yet." body="Run your first MCP security scan to begin analyzing tools and capabilities." action={{ label: "Start New Scan", to: "/scan" }} /></div>;

  const s = d.data;
  const findings = s.findings.filter((f) => f.status !== "informational" && f.category !== "engine" && !["not_tested", "not_applicable", "error"].includes(f.status));
  const band = riskBand(s.risk_score);
  const recs = ((report.data?.recommendations as string[] | undefined) ?? []);
  const lims = ((report.data?.limitations as string[] | undefined) ?? []);
  const jump = (sec: string) => document.getElementById(id(sec))?.scrollIntoView({ behavior: "smooth", block: "start" });
  const running = s.status === "running" || s.status === "queued";

  return (
    <div ref={root}>
      <PageHeader title="Report preview" sub="Review the report before you download it." actions={<>
        <ScanPicker />
        <Link className="btn" to={`/command?scan=${scan.id}`}><Box className="h-4 w-4" aria-hidden /> Open 3D Investigation</Link>
        <button className="btn" onClick={() => dl.mutate("json")} disabled={dl.isPending || running}><FileJson className="h-4 w-4" /> JSON</button>
        <button className="btn-primary" onClick={() => dl.mutate("pdf")} disabled={dl.isPending || running}><Download className="h-4 w-4" /> {dl.isPending ? "Generating…" : "Download PDF"}</button>
      </>} />
      {dl.isError && <div className="mb-4"><ErrorState title="Report could not be generated" message={(dl.error as Error).message} onRetry={() => dl.mutate(dl.variables ?? "pdf")} /></div>}
      {running && <p className="mb-4 rounded-lg border border-warn/40 bg-warn/5 p-3 text-[13px]">This scan is still running. The report is available when it finishes.</p>}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[200px_minmax(0,1fr)]">
        <nav aria-label="Report sections" className="lg:sticky lg:top-20 lg:h-fit"><ul className="flex gap-1 overflow-x-auto lg:flex-col">{SECTIONS.map((sec) => <li key={sec}><button onClick={() => jump(sec)} aria-current={active === sec} className={cn("w-full whitespace-nowrap rounded-lg px-3 py-2 text-left text-[13px] transition", active === sec ? "bg-brand/10 font-medium text-fg" : "text-dim hover:bg-raised hover:text-fg")}>{sec}</button></li>)}</ul></nav>
        <article className="card space-y-10 p-6 sm:p-8">
          <section id={id("Executive Summary")} className="scroll-mt-24"><h2 className="mb-3 text-lg font-semibold">Executive Summary</h2>
            <p className="leading-relaxed">Automated MCP Pentester analyzed <b>{s.target_label}</b> on {fmtDateTime(s.created_at)} ({s.scanner_version ? `scanner ${s.scanner_version}, ruleset ${s.ruleset_version}` : "scanner version not recorded"}). {s.tools.length} tool(s) were inspected and {findings.length} finding(s) were recorded. {findings.length === 0 ? "No findings were produced by the enabled tests; that is not a claim that the target is secure." : `${findings.filter((f) => f.severity === "critical" || f.severity === "high").length} are high or critical.`}</p>
            <p className="mt-2 text-dim">Dynamic testing: {s.dynamic_enabled ? "enabled" : "off"} · Semantic analysis: {s.semantic_status} · ML advisory: {s.ml_status}</p></section>
          <section id={id("Risk")} className="scroll-mt-24"><h2 className="mb-3 text-lg font-semibold">Risk</h2><div className="flex flex-wrap items-center gap-8"><RiskGauge score={s.risk_score} size={170} /><div><div className={cn("text-xl font-semibold", SEV_TEXT[band.sev])}>{band.label}</div><p className="mt-1 max-w-md text-dim">Deterministic RISK-1 score. It prioritizes work; it is not a probability and a low score is not proof of safety.</p></div></div></section>
          <section id={id("Findings")} className="scroll-mt-24"><h2 className="mb-3 text-lg font-semibold">Findings</h2>
            {findings.length === 0 ? <p className="text-dim">None.</p> : <ul className="divide-y divide-line">{[...findings].sort((x, y) => SEVERITIES.indexOf(x.severity) - SEVERITIES.indexOf(y.severity)).map((f) => <li key={f.id} className="flex items-center gap-3 py-2"><SeverityBadge severity={f.severity} /><span className="min-w-0 flex-1 truncate">{f.title}</span><span className="mono text-[12px] text-dim">{f.affected_tools[0] ?? "scan-wide"}</span></li>)}</ul>}</section>
          <section id={id("Evidence")} className="scroll-mt-24"><h2 className="mb-3 text-lg font-semibold">Evidence</h2>
            {findings.filter((f) => f.evidence.length).length === 0 ? <p className="text-dim">No evidence blocks recorded.</p> : <ul className="space-y-2">{findings.filter((f) => f.evidence.length).slice(0, 12).map((f) => <li key={f.id}><div className="font-medium">{f.title}</div><ul className="mt-1 list-disc pl-5 text-[13px] text-dim">{f.evidence.slice(0, 3).map((e, i) => <li key={i}><Pill>{humanize(e.kind)}</Pill> {e.summary.slice(0, 220)}</li>)}</ul></li>)}</ul>}
            <p className="mt-2 text-[12px] text-dim">Open the Evidence page for the full, highlighted view.</p></section>
          <section id={id("Attack Paths")} className="scroll-mt-24"><h2 className="mb-3 text-lg font-semibold">Attack Paths</h2>
            {(a.data?.attack_paths.length ?? 0) === 0 ? <p className="text-dim">No attack path is supported by the evidence.</p> : <div className="space-y-3">{a.data?.attack_paths.slice(0, 3).map((p) => <AttackPathView key={p.id} path={p} onFinding={() => undefined} onTool={() => undefined} />)}</div>}</section>
          <section id={id("Recommendations")} className="scroll-mt-24"><h2 className="mb-3 text-lg font-semibold">Recommendations</h2>
            {report.isLoading ? <p className="text-dim">Loading…</p> : recs.length === 0 ? <p className="text-dim">No recommendations: there were no findings.</p> : <ol className="list-decimal space-y-2 pl-5">{recs.map((r, i) => <li key={i}>{r}</li>)}</ol>}</section>
          <section id={id("Limitations")} className="scroll-mt-24"><h2 className="mb-3 text-lg font-semibold">Limitations</h2>
            {report.isLoading ? <p className="text-dim">Loading…</p> : <ul className="list-disc space-y-1.5 pl-5 text-dim">{lims.map((r, i) => <li key={i}>{r}</li>)}</ul>}</section>
        </article>
      </div>
    </div>
  );
}
