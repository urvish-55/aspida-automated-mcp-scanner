import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Loader2, PlayCircle, Sparkles, Upload } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";
import { ErrorState, PageHeader, Skeleton, SeverityBadge } from "../components/ui";
import { SAMPLE_CONFIG } from "../lib/sample";
import { riskBand, SEV_TEXT, timeAgo } from "../lib/utils";
import { api } from "../services/api";
import { useDashboard, useScans } from "../state/queries";

export default function Home() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const scans = useScans(8);
  const dash = useDashboard();
  const sample = useMutation({
    mutationFn: () => api.createScan({ target_type: "config", target_config: SAMPLE_CONFIG, safe_mode: true, dynamic_enabled: false, semantic_enabled: false, authorization_confirmed: false }),
    onSuccess: (s) => { void qc.invalidateQueries({ queryKey: ["scans"] }); nav(`/scans/${s.id}`); },
  });
  const items = scans.data?.items ?? [];
  const first = !scans.isLoading && items.length === 0;

  return (
    <div className="space-y-6">
      <PageHeader title="Aspida" sub="Find prompt-injection, hidden-instruction and over-permissioned tools in an MCP server, with the evidence for every finding." />

      <section className="card relative overflow-hidden p-6 sm:p-8" aria-label="Start a scan">
        <div className="grid items-center gap-6 md:grid-cols-[1fr_auto]">
          <div>
            <div className="inline-flex items-center gap-1.5 rounded-full border border-brand/40 bg-brand/10 px-2.5 py-0.5 text-[11.5px] font-medium text-brand"><Sparkles className="h-3 w-3" aria-hidden /> {first ? "Start here" : "Quick demo"}</div>
            <h2 className="mt-3 text-2xl font-semibold tracking-tight">{first ? "See Aspida work in one click" : "Scan the sample server"}</h2>
            <p className="mt-2 max-w-xl text-dim">Scans a small built-in MCP server that contains a hidden exfiltration instruction. Static analysis only: nothing is executed or contacted, and it takes a few seconds.</p>
            <div className="mt-5 flex flex-wrap items-center gap-3">
              <button className="btn-primary" onClick={() => sample.mutate()} disabled={sample.isPending}>
                {sample.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <PlayCircle className="h-4 w-4" />} Scan sample server
              </button>
              <Link to="/scan" className="btn"><Upload className="h-4 w-4" /> Scan my own server</Link>
            </div>
            {sample.error && <p role="alert" className="mt-3 text-sev-critical">Could not start the scan: {(sample.error as Error).message}</p>}
          </div>
          <ol className="hidden w-60 space-y-2 text-[13px] text-dim md:block" aria-label="What happens">
            {["Read the tool list", "Look for hidden or hostile wording", "Score the risk, with evidence"].map((t, i) => (
              <li key={t} className="flex items-center gap-2.5"><span className="grid h-6 w-6 shrink-0 place-items-center rounded-full border border-brand/40 text-[11px] font-bold text-brand">{i + 1}</span>{t}</li>
            ))}
          </ol>
        </div>
      </section>

      {dash.data && dash.data.total_scans > 0 && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {[
            ["Scans", dash.data.total_scans],
            ["High / critical findings", dash.data.high_critical_findings],
            ["Tools analysed", dash.data.tools_analyzed],
            ["Average risk", dash.data.average_risk_score == null ? "-" : Math.round(dash.data.average_risk_score)],
          ].map(([l, v]) => (
            <div key={String(l)} className="card-pad"><div className="label">{l}</div><div className="mt-1 text-2xl font-semibold tabular-nums">{v}</div></div>
          ))}
        </div>
      )}

      <section aria-label="Recent scans">
        <div className="mb-2 flex items-center justify-between">
          <h2 className="text-base font-semibold">Recent scans</h2>
          {items.length > 0 && <Link to="/history" className="inline-flex items-center gap-1 text-[13px] text-brand hover:underline">All scans <ArrowRight className="h-3.5 w-3.5" /></Link>}
        </div>
        {scans.isLoading ? <div className="space-y-2"><Skeleton className="h-14" /><Skeleton className="h-14" /></div>
          : scans.error ? <ErrorState title="Could not load scans" message={(scans.error as Error).message} onRetry={() => void scans.refetch()} />
          : first ? <p className="card-pad text-dim">No scans yet. Your first one will show up here.</p>
          : (
            <ul className="card divide-y divide-line">
              {items.map((s) => {
                const band = riskBand(s.risk_score);
                return (
                  <li key={s.id}>
                    <Link to={`/scans/${s.id}`} className="flex items-center gap-4 px-4 py-3 transition hover:bg-raised">
                      <div className="w-12 text-center"><div className={`text-xl font-semibold tabular-nums ${SEV_TEXT[band.sev]}`}>{s.risk_score ?? "-"}</div><div className="text-[10px] text-dim">risk</div></div>
                      <div className="min-w-0 flex-1"><div className="truncate font-medium">{s.target_label}</div><div className="text-[12px] text-dim">{timeAgo(s.created_at)} · {s.status}</div></div>
                      {s.status === "completed" && <SeverityBadge severity={band.sev} />}
                      <ArrowRight className="h-4 w-4 text-dim" aria-hidden />
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
      </section>
    </div>
  );
}
