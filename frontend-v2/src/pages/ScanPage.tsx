import { useMutation } from "@tanstack/react-query";
import { Check, ChevronDown, ChevronRight, Circle, Download, Loader2, XCircle } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { AttackPathView } from "../components/AttackPathView";
import { EvidenceBlock } from "../components/EvidenceViewer";
import { RiskGauge } from "../components/RiskGauge";
import { ConfidenceBadge, ContextLoader, EmptyState, ErrorState, PageHeader, Pill, SeverityBadge, Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui";
import { WhyScore } from "../components/WhyScore";
import { deriveStages } from "../lib/scanEvents";
import { cn, duration, riskBand, SEV_RANK, timeAgo } from "../lib/utils";
import { api } from "../services/api";
import { useAnalysis, useScanDetail } from "../state/queries";
import type { Finding, ScanDetail } from "../types";

const TABS = ["overview", "findings", "tools", "paths", "ml", "report"] as const;
type TabId = (typeof TABS)[number];

function Stages({ scan }: { scan: ScanDetail }) {
  const stages = deriveStages(scan.events, scan.status);
  return (
    <ol className="card divide-y divide-line" aria-label="Scan progress">
      {stages.map((s) => (
        <li key={s.id} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
          {s.state === "done" ? <Check className="h-4 w-4 text-ok" aria-label="done" />
            : s.state === "active" ? <Loader2 className="h-4 w-4 animate-spin text-brand" aria-label="running" />
            : s.state === "failed" ? <XCircle className="h-4 w-4 text-sev-critical" aria-label="failed" />
            : <Circle className="h-4 w-4 text-dim/50" aria-label="pending" />}
          <span className={cn("font-medium", s.state === "pending" && "text-dim")}>{s.label}</span>
          <span className="min-w-0 flex-1 truncate text-dim">{s.message}</span>
          {s.durationMs != null && <span className="mono text-[12px] text-dim">{s.durationMs} ms</span>}
        </li>
      ))}
    </ol>
  );
}

function FindingRowView({ f, tools, open, onToggle }: { f: Finding; tools: ScanDetail["tools"]; open: boolean; onToggle: () => void }) {
  return (
    <li id={`f-${f.id}`} className="card">
      <button className="flex w-full items-start gap-3 px-4 py-3 text-left" onClick={onToggle} aria-expanded={open}>
        {open ? <ChevronDown className="mt-1 h-4 w-4 shrink-0 text-dim" /> : <ChevronRight className="mt-1 h-4 w-4 shrink-0 text-dim" />}
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2"><SeverityBadge severity={f.severity} /><span className="font-medium">{f.title}</span></div>
          {!open && <p className="mt-1 line-clamp-2 text-[13px] text-dim">{f.description}</p>}
        </div>
      </button>
      {open && (
        <div className="space-y-4 border-t border-line px-4 py-4">
          <div className="flex flex-wrap gap-2"><Pill>{f.rule_id}</Pill><ConfidenceBadge value={f.confidence} /><Pill>{f.status}</Pill>{f.affected_tools.map((t) => <Pill key={t} tone="brand">{t}</Pill>)}</div>
          <p className="text-[13.5px]">{f.description}</p>
          <div>
            <div className="label mb-1.5">Evidence</div>
            {f.evidence.length === 0 ? <p className="text-dim">No evidence recorded.</p>
              : <div className="space-y-2">{f.evidence.map((e, i) => <EvidenceBlock key={i} ev={e} tools={tools} defaultOpen={i === 0} />)}</div>}
          </div>
          {f.impact && <div><div className="label mb-1">Impact</div><p className="text-[13.5px]">{f.impact}</p></div>}
          {f.remediation && <div><div className="label mb-1">How to fix</div><p className="text-[13.5px]">{f.remediation}</p></div>}
        </div>
      )}
    </li>
  );
}

export default function ScanPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const [sp, setSp] = useSearchParams();
  const tab: TabId = (TABS as readonly string[]).includes(sp.get("tab") ?? "") ? (sp.get("tab") as TabId) : "overview";
  const setTab = (t: string) => { const n = new URLSearchParams(sp); n.set("tab", t); setSp(n, { replace: true }); };
  const q = useScanDetail(id);
  const scan = q.data;
  const done = scan?.status === "completed";
  const analysis = useAnalysis(done ? id : undefined);
  const [openF, setOpenF] = useState<string | null>(null);
  const dl = useMutation({ mutationFn: (kind: "pdf" | "json") => api.downloadReport(id as string, kind) });

  const findings = useMemo(() => [...(scan?.findings ?? [])].sort((a, b) => (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0)), [scan]);
  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    findings.forEach((f) => { c[f.severity] = (c[f.severity] ?? 0) + 1; });
    return c;
  }, [findings]);

  if (q.isLoading) return <ContextLoader message="Loading scan…" />;
  if (q.error || !scan) return <ErrorState title="Scan not found" message={(q.error as Error | null)?.message ?? "It may have been deleted."} onRetry={() => void q.refetch()} />;

  const band = riskBand(scan.risk_score);
  const running = scan.status === "running" || scan.status === "queued";
  const jump = (fid: string) => { setOpenF(fid); setTab("findings"); };

  return (
    <div className="space-y-5">
      <PageHeader
        crumbs={<Link to="/history" className="text-[12px] text-dim hover:text-fg">← All scans</Link>}
        title={scan.target_label}
        sub={<>{timeAgo(scan.created_at)} · {scan.status}{scan.completed_at ? ` in ${duration(scan.started_at, scan.completed_at)}` : ""} · {scan.tools.length} tools · {findings.length} findings</>}
        actions={<>
          {running && <button className="btn-danger" onClick={() => void api.cancelScan(scan.id)}>Cancel</button>}
          <button className="btn" onClick={() => nav("/scan")}>New scan</button>
        </>}
      />

      {running && <Stages scan={scan} />}
      {(scan.status === "failed" || scan.status === "cancelled") && (
        <ErrorState title={scan.status === "failed" ? "The scan failed" : "The scan was cancelled"} message={scan.error ?? "No further detail was recorded."} />
      )}

      {done && (
        <Tabs value={tab} onValueChange={setTab}>
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="findings">Findings ({findings.length})</TabsTrigger>
            <TabsTrigger value="tools">Tools ({scan.tools.length})</TabsTrigger>
            <TabsTrigger value="paths">Attack paths</TabsTrigger>
            <TabsTrigger value="ml">ML advisory</TabsTrigger>
            <TabsTrigger value="report">Report</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-5">
            <div className="grid gap-5 lg:grid-cols-[320px_1fr]">
              <div className="card flex flex-col items-center p-5">
                <RiskGauge score={scan.risk_score} size={220} />
                <div className="mt-3 flex flex-wrap justify-center gap-1.5">
                  {["critical", "high", "medium", "low", "info"].filter((s) => counts[s]).map((s) => <span key={s} className="inline-flex items-center gap-1"><SeverityBadge severity={s} /><span className="text-[12px] text-dim">×{counts[s]}</span></span>)}
                </div>
              </div>
              <WhyScore score={scan.risk_score} breakdown={scan.risk_breakdown} />
            </div>
            <section aria-label="Top findings">
              <div className="mb-2 flex items-center justify-between"><h2 className="text-base font-semibold">Top findings</h2><button className="text-[13px] text-brand hover:underline" onClick={() => setTab("findings")}>See all {findings.length}</button></div>
              {findings.length === 0 ? <EmptyState title="No findings" body={`Nothing in this tool list matched a rule. The score is ${scan.risk_score ?? "-"} (${band.label.toLowerCase()}).`} />
                : <ul className="space-y-2">{findings.slice(0, 3).map((f) => <FindingRowView key={f.id} f={f} tools={scan.tools} open={openF === f.id} onToggle={() => setOpenF(openF === f.id ? null : f.id)} />)}</ul>}
            </section>
          </TabsContent>

          <TabsContent value="findings">
            {findings.length === 0 ? <EmptyState title="No findings" body="Nothing matched a rule in this scan." />
              : <ul className="space-y-2">{findings.map((f) => <FindingRowView key={f.id} f={f} tools={scan.tools} open={openF === f.id} onToggle={() => setOpenF(openF === f.id ? null : f.id)} />)}</ul>}
          </TabsContent>

          <TabsContent value="tools">
            <ul className="space-y-2">
              {scan.tools.map((t) => {
                const n = findings.filter((f) => f.affected_tools.includes(t.name));
                return (
                  <li key={t.name} className="card px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2"><span className="mono font-semibold">{t.name}</span>{t.capabilities.map((c) => <Pill key={c}>{c.replace(/_/g, " ")}</Pill>)}{n.length > 0 && <button className="ml-auto" onClick={() => jump(n[0].id)}><Pill tone="bad">{n.length} finding{n.length > 1 ? "s" : ""}</Pill></button>}</div>
                    <p className="mt-1 text-[13px] text-dim">{t.description}</p>
                  </li>
                );
              })}
            </ul>
          </TabsContent>

          <TabsContent value="paths">
            {analysis.isLoading ? <ContextLoader message="Building attack paths…" />
              : analysis.error ? <ErrorState title="Could not load attack paths" message={(analysis.error as Error).message} onRetry={() => void analysis.refetch()} />
              : (analysis.data?.attack_paths ?? []).length === 0 ? <EmptyState title="No attack paths" body="No chain of capabilities with supporting evidence was found." />
              : <div className="space-y-4">{analysis.data!.attack_paths.map((p, i) => <AttackPathView key={i} path={p} onFinding={jump} onTool={() => setTab("tools")} />)}</div>}
          </TabsContent>

          <TabsContent value="ml">
            <div className="card p-5">
              <h2 className="text-base font-semibold">ML advisory</h2>
              <p className="mt-1 text-dim">An offline, experimental model gives a second opinion. It never changes the score or the findings above.</p>
              <p className="mt-3">Status for this scan: <Pill tone={scan.ml_status === "completed" ? "ok" : "neutral"}>{scan.ml_status || "not run"}</Pill></p>
              <Link to="/ml" className="btn mt-4 inline-flex">Open ML analysis</Link>
            </div>
          </TabsContent>

          <TabsContent value="report">
            <div className="card p-5">
              <h2 className="text-base font-semibold">Report</h2>
              <p className="mt-1 text-dim">Everything on this page, with evidence, as a file you can share.</p>
              <div className="mt-4 flex flex-wrap gap-2">
                <button className="btn-primary" onClick={() => dl.mutate("pdf")} disabled={dl.isPending}><Download className="h-4 w-4" /> PDF report</button>
                <button className="btn" onClick={() => dl.mutate("json")} disabled={dl.isPending}><Download className="h-4 w-4" /> JSON</button>
              </div>
              {dl.error && <p role="alert" className="mt-3 text-sev-critical">{(dl.error as Error).message}</p>}
            </div>
          </TabsContent>
        </Tabs>
      )}
    </div>
  );
}
