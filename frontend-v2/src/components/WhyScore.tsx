import { Info } from "lucide-react";
import { riskBand, SEV_BG, SEV_TEXT } from "../lib/utils";

interface Part { label: string; value: number; cap: number; note: string }
type Rec = Record<string, unknown>;
const num = (v: unknown): number => (typeof v === "number" && isFinite(v) ? v : 0);

/** Explains the RISK-1 score from the stored breakdown only; nothing here is computed client-side except layout. */
export function WhyScore({ score, breakdown }: { score: number | null; breakdown: Rec | null }) {
  if (score == null || !breakdown) {
    return <div className="card-pad text-dim">No score yet. It appears when the scan finishes.</div>;
  }
  const st = (breakdown.static ?? {}) as Rec;
  const dy = (breakdown.dynamic ?? {}) as Rec;
  const cp = (breakdown.capability ?? {}) as Rec;
  const ca = (breakdown.confidence_adjustment ?? {}) as Rec;
  const parts: Part[] = [
    { label: "Static analysis", value: num(st.subtotal), cap: num(st.cap) || 40, note: `${num(st.findings_scored)} finding(s) scored from tool metadata` },
    { label: "Dynamic testing", value: num(dy.subtotal), cap: num(dy.cap) || 35, note: num(dy.findings_scored) ? `${num(dy.findings_scored)} finding(s) from live tests` : "no live tests were run" },
    { label: "Capability combinations", value: num(cp.subtotal), cap: num(cp.cap) || 20, note: `${num(cp.dangerous_combinations_seen)} dangerous combination(s) seen` },
  ];
  const adj = num(ca.adjustment_points);
  const band = riskBand(score);
  const total = num(breakdown.total_before_clamp) || score;
  return (
    <section className="card p-5" aria-label="Why this score">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-base font-semibold">Why this score?</h2>
        <span className={`text-[13px] font-semibold ${SEV_TEXT[band.sev]}`}>{score} / 100 · {band.label.toLowerCase()}</span>
      </div>
      <p className="mt-1 text-[13px] text-dim">The score is a sum of capped parts (formula {String(breakdown.formula_version ?? "RISK-1")}). A part can never contribute more than its cap.</p>
      <ul className="mt-4 space-y-3">
        {parts.map((p) => (
          <li key={p.label}>
            <div className="flex items-baseline justify-between text-[13px]">
              <span className="font-medium">{p.label}</span>
              <span className="mono tabular-nums">{p.value} <span className="text-dim">/ {p.cap}</span></span>
            </div>
            <div className="mt-1 h-2 overflow-hidden rounded-full bg-raised" role="img" aria-label={`${p.label}: ${p.value} of ${p.cap}`}>
              <div className={`h-full rounded-full ${SEV_BG[band.sev]}`} style={{ width: `${Math.min(100, (p.value / p.cap) * 100)}%` }} />
            </div>
            <div className="mt-0.5 text-[12px] text-dim">{p.note}</div>
          </li>
        ))}
        <li className="flex items-baseline justify-between text-[13px]">
          <span><span className="font-medium">Confidence adjustment</span> <span className="text-dim">· average evidence confidence {num(ca.average_confidence_weight).toFixed(2)}</span></span>
          <span className="mono tabular-nums">{adj >= 0 ? "+" : ""}{adj}</span>
        </li>
      </ul>
      <div className="mt-4 flex items-center justify-between border-t border-line pt-3 text-[13px]">
        <span className="font-medium">Total</span>
        <span className="mono tabular-nums">{parts.reduce((a, p) => a + p.value, 0)} {adj >= 0 ? "+" : "−"} {Math.abs(adj)} = {total}</span>
      </div>
      <p className="mt-3 flex gap-2 text-[12px] text-dim"><Info className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />Bands: 0–24 low, 25–49 moderate, 50–74 high, 75–100 critical. The score ranks risk; it is not a proof of exploitability.</p>
    </section>
  );
}
