import { Play } from "lucide-react";
import { safeLabel } from "../../lib/safeText";
import { cn } from "../../lib/utils";
import { useInvestigation } from "../../state/investigation";
import type { AttackPath } from "../../types";
import { Pill } from "../ui";

const STATUS = { evidenced: "Evidenced", potential: "Potential", missing: "Missing" } as const;

/** Attack-path investigation panel. Paths are backend candidates; the overall status is never stronger than "suspected". */
export function PathPanel({ paths }: { paths: AttackPath[] }) {
  const { activePathId, setActivePath, playTour, select } = useInvestigation();
  if (paths.length === 0) return <p className="text-[13px] text-dim">No attack path is supported by the stored evidence. That does not prove none exists.</p>;
  return (
    <section aria-label="Attack paths" className="space-y-3">
      <h2 className="label">Attack path candidates ({paths.length})</h2>
      <p className="rounded-lg border border-warn/40 bg-warn/5 p-2 text-[12px] text-dim">Every path is a <b>suspected</b> chain. Solid stages have stored evidence; outlined stages are potential or missing. No exploit was run.</p>
      <ul className="space-y-2">
        {paths.map((p) => {
          const on = activePathId === p.id;
          return (
            <li key={p.id} className={cn("rounded-lg border p-2.5", on ? "border-brand/60 bg-brand/5" : "border-line")}>
              <button className="w-full text-left" aria-pressed={on} onClick={() => setActivePath(on ? null : p.id)}>
                <div className="text-[13px] font-medium">{safeLabel(p.label, 70)}</div>
                <div className="mt-1 flex flex-wrap gap-1.5"><Pill tone="warn">Suspected</Pill><Pill>{Math.round(p.evidence_ratio * 100)}% evidenced</Pill><Pill>confidence {p.confidence}</Pill>{!p.complete && <Pill>{p.missing_stages.length} missing</Pill>}</div>
              </button>
              {on && (
                <>
                  <ol className="mt-2 space-y-1 text-[12.5px]">
                    {p.nodes.map((n, i) => (
                      <li key={i}><button className="flex w-full items-center gap-2 text-left hover:underline" onClick={() => select(`pathnode:${p.id}:${i}`)}>
                        <span className="w-4 text-dim">{i + 1}.</span><span className="min-w-0 flex-1 truncate">{safeLabel(n.label, 60)}</span><span className={cn("shrink-0 text-[11px]", n.status === "evidenced" ? "text-sev-high" : "text-dim")}>{STATUS[n.status]}</span>
                      </button></li>
                    ))}
                  </ol>
                  <button className="btn-primary mt-2 !py-1 text-[12px]" onClick={() => playTour(p.id)}><Play className="h-3.5 w-3.5" aria-hidden /> View Attack Path</button>
                </>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}
