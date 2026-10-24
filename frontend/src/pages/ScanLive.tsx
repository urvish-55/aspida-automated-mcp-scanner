import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { motion } from "framer-motion";
import { CheckCircle2, Circle, Loader2, OctagonX, XCircle } from "lucide-react";
import { useEffect, useRef } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { RiskGauge } from "../components/RiskGauge";
import { ContextLoader, DemoBadge, ErrorState, PageHeader, Pill, Skeleton, SeverityBadge } from "../components/ui";
import { api } from "../services/api";
import { usePrefs } from "../state/prefs";
import { useScans, useScanDetail } from "../state/queries";
import { cn, duration, fmtTime, isLocalTarget, SEVERITIES } from "../lib/utils";

const STAGES: [string, string][] = [
  ["initializing", "Initializing"], ["parsing_target", "Parsing target"], ["enumerating_tools", "Tool discovery"],
  ["static_analysis", "Static analysis"], ["dynamic_testing", "Dynamic testing"], ["semantic_analysis", "Semantic analysis"],
  ["risk_aggregation", "Risk aggregation"], ["report_generation", "Report generation"],
];

export default function ScanLive() {
  const { id } = useParams<{ id: string }>();
  const nav = useNavigate();
  const qc = useQueryClient();
  const { setScanId } = usePrefs();
  const q = useScanDetail(id);
  const scans = useScans(200);
  const scan = q.data;
  const running = scan?.status === "running" || scan?.status === "queued";
  const cancel = useMutation({ mutationFn: () => api.cancelScan(id as string), onSuccess: () => void qc.invalidateQueries({ queryKey: ["scan", id] }) });
  const parent = useRef<HTMLDivElement>(null);
  const events = scan?.events ?? [];
  const virt = useVirtualizer({ count: events.length, getScrollElement: () => parent.current, estimateSize: () => 26, overscan: 20 });

  useEffect(() => { if (running && events.length) virt.scrollToIndex(events.length - 1, { align: "end" }); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [events.length, running]);
  useEffect(() => { if (scan && !running) setScanId(scan.id); }, [scan, running, setScanId]);

  if (q.isLoading) return <div><PageHeader title="Scan" /><ContextLoader message="Loading scan…" /></div>;
  if (q.error || !scan) return <ErrorState title="Scan not found" message={(q.error as Error | null)?.message ?? "This scan does not exist or was deleted."} onRetry={() => void q.refetch()} />;

  const started = new Set(events.filter((e) => e.event === "started").map((e) => e.stage));
  const done = new Set(events.filter((e) => e.event === "completed").map((e) => e.stage));
  // A stage is finished once any later stage has started (the first stage records no separate "completed" event).
  const order = STAGES.map(([sid]) => sid);
  const furthest = Math.max(-1, ...order.map((sid, i) => (started.has(sid) || done.has(sid) ? i : -1)));
  order.forEach((sid, i) => { if (i < furthest) done.add(sid); });
  const last = [...events].reverse().find((e) => e.progress != null)?.progress ?? 0;
  const pct = scan.status === "completed" ? 100 : Math.min(99, Math.round(last));
  const findings = scan.findings.filter((f) => f.status !== "informational" && f.category !== "engine" && !["not_tested", "not_applicable", "error"].includes(f.status));
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length])) as Record<string, number>;
  const previous = (scans.data?.items ?? []).filter((s) => s.id !== scan.id && s.status === "completed" && s.created_at < scan.created_at)[0];
  const failedStage = events.find((e) => e.event === "error")?.stage;

  return (
    <div>
      <PageHeader
        title={running ? "Scan in progress" : scan.status === "completed" ? "Scan complete" : scan.status === "cancelled" ? "Scan cancelled" : "Scan failed"}
        sub={<span className="inline-flex flex-wrap items-center gap-2"><span className="mono">{scan.target_label}</span>{isLocalTarget(scan) && <DemoBadge />}<Pill>{scan.id.slice(0, 8)}</Pill><Pill>Elapsed {duration(scan.started_at ?? scan.created_at, scan.completed_at)}</Pill></span>}
        actions={running ? <button className="btn-danger" onClick={() => cancel.mutate()} disabled={cancel.isPending}><OctagonX className="h-4 w-4" /> Cancel scan</button> : undefined}
      />

      <section className="card mb-4 p-5" aria-label="Scan progress">
        <div className="mb-2 flex items-end justify-between">
          <div className="label">{running ? "Scan in progress" : scan.status}</div>
          <div className="text-2xl font-semibold tabular-nums">{pct}%</div>
        </div>
        <div className="h-2.5 overflow-hidden rounded-full bg-line" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label="Scan progress">
          <motion.div className={cn("h-full rounded-full", scan.status === "failed" ? "bg-sev-critical" : scan.status === "cancelled" ? "bg-warn" : "bg-brand")} initial={false} animate={{ width: `${pct}%` }} transition={{ duration: 0.4 }} />
        </div>
        <ol className="mt-5 grid grid-cols-1 gap-x-8 gap-y-2.5 sm:grid-cols-2 lg:grid-cols-4">
          {STAGES.map(([sid, label]) => {
            const isDone = done.has(sid);
            const isRun = running && started.has(sid) && !isDone;
            const isErr = failedStage === sid;
            return (
              <li key={sid} className="flex items-center gap-2.5">
                {isErr ? <XCircle className="h-4 w-4 text-sev-critical" /> : isDone ? <CheckCircle2 className="h-4 w-4 text-ok" /> : isRun ? <Loader2 className="h-4 w-4 animate-spin text-brand" /> : <Circle className="h-4 w-4 text-dim" />}
                <span className={cn(isDone ? "text-fg" : isRun ? "font-medium text-brand" : "text-dim")}>{label}</span>
                <span className="ml-auto text-[11px] text-dim">{isErr ? "Error" : isDone ? "Done" : isRun ? "Running" : running ? "Waiting" : "-"}</span>
              </li>
            );
          })}
        </ol>
        {running && <p className="mt-4 text-[12px] text-dim">Progress and stages come from the scan's recorded events, updated every second.</p>}
      </section>

      {scan.status === "failed" && <div className="mb-4"><ErrorState title="Scan failed" message={scan.error ?? "No error detail was recorded."} causes={["the target could not be parsed or reached", "the server rejected the request", "the scan hit a time or request limit"]} /></div>}

      {scan.status === "completed" && (
        <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="card mb-4 flex flex-wrap items-center gap-8 p-6" aria-label="Scan result summary">
          <RiskGauge score={scan.risk_score} size={190} onClick={() => nav(`/risk?scan=${scan.id}`)} />
          <div className="min-w-[240px] flex-1">
            <div className="text-3xl font-semibold tabular-nums">{findings.length} <span className="text-base font-normal text-dim">findings · {scan.tools.length} tools</span></div>
            <div className="mt-3 flex flex-wrap gap-2">{SEVERITIES.filter((s) => counts[s]).map((s) => <Link key={s} to={`/findings?scan=${scan.id}&severity=${s}`}><SeverityBadge severity={s} className="cursor-pointer" /> <span className="tabular-nums">{counts[s]}</span></Link>)}{findings.length === 0 && <span className="text-dim">No findings from the enabled tests. This does not prove the target is secure.</span>}</div>
            <div className="mt-5 flex flex-wrap gap-2">
              <Link className="btn-primary" to={`/findings?scan=${scan.id}`}>Explore findings</Link>
              <Link className="btn" to={`/tools?scan=${scan.id}`}>Inspect tools</Link>
              <Link className="btn" to={`/attack-paths?scan=${scan.id}`}>Attack paths</Link>
              <Link className="btn" to={`/reports?scan=${scan.id}`}>Report</Link>
              {previous && <Link className="btn" to={`/compare?a=${previous.id}&b=${scan.id}`}>Compare with previous</Link>}
            </div>
          </div>
        </motion.section>
      )}

      <section className="card p-4" aria-label="Live event stream">
        <h2 className="mb-3 font-semibold">Live event stream <span className="font-normal text-dim">({events.length})</span></h2>
        {events.length === 0 ? <Skeleton className="h-24" /> : (
          <div ref={parent} className="mono max-h-[360px] overflow-auto rounded-lg bg-bg p-2" tabIndex={0} aria-label="Scan events" role="log" aria-live={running ? "polite" : "off"}>
            <div style={{ height: virt.getTotalSize(), position: "relative" }}>
              {virt.getVirtualItems().map((v) => {
                const e = events[v.index];
                return (
                  <div key={e.seq} className="absolute left-0 top-0 flex w-full gap-3 whitespace-nowrap px-1" style={{ transform: `translateY(${v.start}px)`, height: 26, lineHeight: "26px" }}>
                    <span className="text-dim">{fmtTime(e.timestamp)}</span>
                    <span className={cn("w-[150px] shrink-0 truncate", e.level === "error" ? "text-sev-critical" : e.level === "warning" ? "text-warn" : "text-brand")}>{e.stage.replace(/_/g, " ")}</span>
                    <span className="truncate">{e.message || e.event}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </section>
    </div>
  );
}
