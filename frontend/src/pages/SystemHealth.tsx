import { CheckCircle2, MinusCircle, XCircle } from "lucide-react";
import { ContextLoader, ErrorState, PageHeader, Pill } from "../components/ui";
import { fmtTime } from "../lib/utils";
import { useSystemHealth } from "../state/queries";

const ICON = { healthy: CheckCircle2, degraded: MinusCircle, unavailable: XCircle };
const TONE = { healthy: "text-ok", degraded: "text-warn", unavailable: "text-sev-critical" };
const LABEL = { healthy: "Healthy", degraded: "Degraded", unavailable: "Unavailable" };

export default function SystemHealth() {
  const q = useSystemHealth();
  if (q.isLoading) return <ContextLoader message="Checking components…" />;
  if (q.error || !q.data) return <ErrorState title="Unable to reach the backend" message="The health endpoint did not respond." causes={["the backend is not running", "the API key was rejected"]} onRetry={() => void q.refetch()} details={(q.error as Error | null)?.message} />;
  const h = q.data;
  const OverallIcon = ICON[h.overall];
  return (
    <div>
      <PageHeader title="System health" sub="Live checks run by the backend. Optional components being off does not make the platform unhealthy." />
      <div className="card mb-4 flex items-center gap-4 p-5"><OverallIcon className={`h-9 w-9 ${TONE[h.overall]}`} /><div><div className="label">Overall</div><div className={`text-2xl font-semibold ${TONE[h.overall]}`}>{LABEL[h.overall]}</div></div><div className="ml-auto text-[12px] text-dim">Checked {fmtTime(h.time_utc)} · refreshes every 10s</div></div>
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {h.components.map((c) => { const I = ICON[c.status]; return (
          <li key={c.id} className="card flex items-start gap-3 p-4"><I className={`mt-0.5 h-5 w-5 shrink-0 ${TONE[c.status]}`} aria-hidden /><div className="min-w-0 flex-1"><div className="flex items-center gap-2"><span className="font-semibold">{c.label}</span><Pill tone={c.status === "healthy" ? "ok" : c.status === "degraded" ? "warn" : "bad"}>{LABEL[c.status]}</Pill></div><p className="mt-1 text-[13px] text-dim">{c.detail}</p></div></li>
        ); })}
      </ul>
    </div>
  );
}
