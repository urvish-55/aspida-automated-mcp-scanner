import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import { safeLabel } from "../../lib/safeText";
import { cn } from "../../lib/utils";
import { useInvestigation } from "../../state/investigation";
import type { ScanStageView } from "../../types/visualization";

const ICON = { done: CheckCircle2, active: Loader2, failed: XCircle, pending: Circle } as const;

/** Pipeline stages exactly as the backend events report them, with their last real message. */
export function ScanPanel({ stages, live, findingsReady, status }: { stages: ScanStageView[]; live: boolean; findingsReady: boolean; status: string }) {
  const select = useInvestigation((s) => s.select);
  return (
    <section aria-label="Scan pipeline" className="space-y-3">
      <h2 className="label">Pipeline · {live ? "live" : status}</h2>
      {!live && <p className="text-[12px] text-dim">No scan is running, so nothing animates. This is the recorded pipeline of the selected scan.</p>}
      {live && !findingsReady && <p className="rounded-lg border border-line bg-raised p-2 text-[12px] text-dim">Findings are saved when risk aggregation finishes, so none appear in the graph until then.</p>}
      <ol className="space-y-1">
        {stages.map((s) => {
          const Icon = ICON[s.state];
          return (
            <li key={s.id}><button className="flex w-full items-start gap-2 rounded px-1 py-1 text-left hover:bg-raised" onClick={() => select(`stage:${s.id}`)}>
              <Icon className={cn("mt-0.5 h-4 w-4 shrink-0", s.state === "done" && "text-ok", s.state === "active" && "animate-spin text-brand", s.state === "failed" && "text-sev-critical", s.state === "pending" && "text-dim")} aria-hidden />
              <span className="min-w-0 flex-1"><span className="block text-[13px]">{s.label} <span className="sr-only">— {s.state}</span></span>{s.message && <span className="block truncate text-[11.5px] text-dim">{safeLabel(s.message, 90)}</span>}</span>
              {s.durationMs != null && <span className="shrink-0 text-[11px] tabular-nums text-dim">{s.durationMs} ms</span>}
            </button></li>
          );
        })}
      </ol>
    </section>
  );
}
