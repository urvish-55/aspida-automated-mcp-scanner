import { motion } from "framer-motion";
import { Activity, Box, CheckCircle2, Info, PlayCircle, ShieldAlert, Wrench } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { Heatmap } from "../components/Heatmap";
import { MiniBar, RiskGauge } from "../components/RiskGauge";
import { ContextLoader, DemoBadge, EmptyState, ErrorState, PageHeader, SeverityBadge, Skeleton, Stat } from "../components/ui";
import { cn, fmtTime, isLocalTarget, riskBand, SEV_RANK, SEV_TEXT, SEVERITIES, timeAgo } from "../lib/utils";
import { useActiveScan, useActivity, useAnalysis, useDashboard, useScanDetail } from "../state/queries";

function ActivityStream() {
  const { data, isLoading, error } = useActivity(25);
  if (isLoading) return <div className="space-y-3">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-10" />)}</div>;
  if (error) return <p className="text-sev-critical">Could not load activity.</p>;
  const items = data?.items ?? [];
  if (items.length === 0) return <p className="py-6 text-center text-dim">No activity yet. Events from real scans appear here as they happen.</p>;
  return (
    <ol className="relative space-y-3 border-l border-line pl-5" aria-label="Live security activity">
      {items.map((e, i) => {
        const tone = e.level === "error" ? "bg-sev-critical" : e.level === "warning" ? "bg-warn" : e.event === "completed" ? "bg-ok" : "bg-brand";
        return (
          <li key={`${e.timestamp}-${i}`} className="relative">
            <span className={cn("absolute -left-[25px] top-1.5 h-2.5 w-2.5 rounded-full ring-4 ring-panel", tone)} />
            <Link to={`/scans/${e.scan_id}`} className="block rounded-md px-1 transition hover:bg-raised">
              <div className="truncate text-[13px]">{e.message || `${e.stage} ${e.event}`}</div>
              <div className="text-[11.5px] text-dim">{e.scan_label || "scan"} · {e.stage.replace(/_/g, " ")} · {timeAgo(e.timestamp)} <span className="text-dim">({fmtTime(e.timestamp)})</span></div>
            </Link>
          </li>
        );
      })}
    </ol>
  );
}

export default function Overview() {
  const nav = useNavigate();
  const dash = useDashboard();
  const { scan, loading, error, refetch } = useActiveScan();
  const detail = useScanDetail(scan?.id);
  const analysis = useAnalysis(scan?.id);

  if (error) return <ErrorState title="Unable to reach the API" message="The dashboard could not load scan data." causes={["the backend is not running", "the API key was rejected", "the request was blocked"]} onRetry={() => void refetch()} details={error.message} />;
  if (loading || dash.isLoading) return <div><PageHeader title="Overview" sub="Loading your security posture…" /><ContextLoader message="Loading scans…" /></div>;
  if (!dash.data || dash.data.total_scans === 0 || !scan) {
    return (
      <div>
        <PageHeader title="Overview" />
        <EmptyState icon={<PlayCircle className="h-6 w-6" />} title="No scans yet." body="Run your first MCP security scan to begin analyzing tools and capabilities." action={{ label: "Start New Scan", to: "/scan" }} />
      </div>
    );
  }

  const findings = (detail.data?.findings ?? []).filter((f) => f.status !== "informational" && f.category !== "engine" && f.status !== "not_tested" && f.status !== "not_applicable" && f.status !== "error");
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])) as Record<string, number>;
  const critical = findings.filter((f) => f.severity === "critical" || f.severity === "high").sort((a, b) => SEV_RANK[b.severity] - SEV_RANK[a.severity]).slice(0, 5);
  const band = riskBand(scan.risk_score);
  const topTools = (analysis.data?.tools ?? []).slice(0, 5);

  return (
    <div>
      <PageHeader title="Overview" sub={dash.data.security_status}
        actions={<><Link to={`/command?scan=${scan.id}`} className="btn"><Box className="h-4 w-4" aria-hidden /> Open 3D Investigation</Link><Link to="/scan" className="btn-primary"><PlayCircle className="h-4 w-4" /> New scan</Link></>} />

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,1fr)]">
        {/* HERO */}
        <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="card relative overflow-hidden p-6" aria-label="MCP security status">
          <div className="pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full bg-brand/10 blur-3xl" />
          <div className="flex items-center justify-between gap-3">
            <div className="label">MCP security status</div>
            <div className="flex items-center gap-2">{isLocalTarget(scan) && <DemoBadge />}<Link to={`/scans/${scan.id}`} className="text-[12px] text-dim hover:text-brand">{scan.target_label} · {timeAgo(scan.completed_at ?? scan.created_at)}</Link></div>
          </div>
          <div className="mt-4 flex flex-wrap items-center gap-8">
            <RiskGauge score={scan.risk_score} onClick={() => nav(`/risk?scan=${scan.id}`)} />
            <div className="min-w-[200px] flex-1">
              <div className={cn("text-[11px] font-bold tracking-[0.14em]", SEV_TEXT[band.sev])}>{band.label}</div>
              <div className="mt-1 text-3xl font-semibold tabular-nums">{findings.length} <span className="text-base font-normal text-dim">findings</span></div>
              <ul className="mt-4 space-y-2">
                {SEVERITIES.filter((s) => s !== "info").map((s) => (
                  <li key={s}>
                    <Link to={`/findings?scan=${scan.id}&severity=${s}`} className="group flex items-center gap-3 rounded-md px-1 py-0.5 transition hover:bg-raised">
                      <span className="w-16 text-[12px] capitalize text-dim">{s}</span>
                      <span className="flex-1"><MiniBar value={counts[s] ?? 0} max={Math.max(1, findings.length)} sev={s} /></span>
                      <span className={cn("w-6 text-right tabular-nums font-semibold", counts[s] ? SEV_TEXT[s] : "text-dim")}>{counts[s] ?? 0}</span>
                    </Link>
                  </li>
                ))}
              </ul>
              <p className="mt-3 text-[12px] text-dim">Click the gauge to see how the score is calculated. A low score does not mean the server is secure.</p>
            </div>
          </div>
        </motion.section>

        {/* STATS */}
        <div className="grid grid-cols-2 gap-4">
          <Stat label="Scans" value={dash.data.total_scans} hint={`${dash.data.scans_completed} completed · ${dash.data.scans_failed} failed`} to="/history" />
          <Stat label="High / critical" value={dash.data.high_critical_findings} tone={dash.data.high_critical_findings ? "text-sev-high" : undefined} hint="across all scans" to="/findings?severity=critical,high" />
          <Stat label="Tools analyzed" value={dash.data.tools_analyzed} hint="across all scans" to="/tools" />
          <Stat label="Dynamic tests" value={dash.data.tests_executed} hint={`${dash.data.tests_skipped} skipped (skipped ≠ passed)`} />
          <Stat label="Average risk" value={dash.data.average_risk_score ?? "-"} hint="completed scans only" to="/risk" />
          <Stat label="Last scan" value={<span className={cn("capitalize", scan.status === "failed" && "text-sev-critical")}>{scan.status}</span>} hint={timeAgo(scan.created_at)} to={`/scans/${scan.id}`} />
        </div>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <section className="card p-4" aria-label="Security heatmap">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="font-semibold">Security heatmap <span className="ml-1 font-normal text-dim">tool × risk category</span></h2>
            <Link to="/tools" className="text-[12px] text-brand hover:underline">Open tools</Link>
          </div>
          {analysis.isLoading ? <Skeleton className="h-40" /> : analysis.data && analysis.data.heatmap.rows.length > 0
            ? <Heatmap columns={analysis.data.heatmap.columns} rows={analysis.data.heatmap.rows.slice(0, 12)} onOpenTool={(t) => nav(`/tools?scan=${scan.id}&tool=${encodeURIComponent(t)}`)} />
            : <p className="py-8 text-center text-dim">No tools were recorded for this scan.</p>}
          {(analysis.data?.heatmap.rows.length ?? 0) > 12 && <p className="mt-2 text-[12px] text-dim">Showing 12 of {analysis.data?.heatmap.rows.length} tools. <Link className="text-brand hover:underline" to="/tools">See all</Link></p>}
        </section>

        <section className="card p-4" aria-label="Live security activity">
          <div className="mb-3 flex items-center gap-2"><Activity className="h-4 w-4 text-brand" /><h2 className="font-semibold">Live security activity</h2></div>
          <ActivityStream />
        </section>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="card p-4">
          <div className="mb-3 flex items-center justify-between"><h2 className="flex items-center gap-2 font-semibold"><ShieldAlert className="h-4 w-4 text-sev-high" /> Needs attention</h2><Link to={`/findings?scan=${scan.id}`} className="text-[12px] text-brand hover:underline">All findings</Link></div>
          {critical.length === 0 ? (
            <div className="flex items-start gap-3 py-4 text-dim"><CheckCircle2 className="mt-0.5 h-4 w-4 text-ok" /> No high or critical findings in the latest scan. This does not prove the server is secure.</div>
          ) : (
            <ul className="divide-y divide-line">
              {critical.map((f) => (
                <li key={f.id}>
                  <Link to={`/findings?scan=${scan.id}&open=${f.id}`} className="flex items-center gap-3 py-2.5 transition hover:bg-raised/60">
                    <SeverityBadge severity={f.severity} />
                    <span className="min-w-0 flex-1 truncate">{f.title}</span>
                    <span className="mono truncate text-dim">{f.affected_tools[0] ?? ""}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section className="card p-4">
          <div className="mb-3 flex items-center justify-between"><h2 className="flex items-center gap-2 font-semibold"><Wrench className="h-4 w-4 text-brand" /> Most exposed tools</h2><Link to="/tools" className="text-[12px] text-brand hover:underline">All tools</Link></div>
          {topTools.length === 0 ? <p className="py-4 text-dim">No tools recorded.</p> : (
            <ul className="space-y-3">
              {topTools.map((t) => (
                <li key={t.name}>
                  <Link to={`/tools?scan=${scan.id}&tool=${encodeURIComponent(t.name)}`} className="block rounded-md px-1 py-0.5 transition hover:bg-raised">
                    <div className="flex items-center justify-between"><span className="mono">{t.name}</span><span className={cn("tabular-nums text-[12px] font-semibold", SEV_TEXT[t.exposure.band])}>{t.exposure.score}</span></div>
                    <MiniBar value={t.exposure.score} sev={t.exposure.band} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 flex items-start gap-1.5 text-[11.5px] text-dim"><Info className="mt-0.5 h-3 w-3 shrink-0" /> Exposure ranks tools inside this scan (finding severity + capability weight). It is not the scan risk score.</p>
        </section>
      </div>
      {scan.status === "failed" && <div className="mt-4"><ErrorState title="The latest scan failed" message={scan.error ?? "No error detail was recorded."} /></div>}
    </div>
  );
}
