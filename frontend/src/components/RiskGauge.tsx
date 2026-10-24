import { motion, useReducedMotion } from "framer-motion";
import { cn, riskBand, SEV_HEX_VAR, SEV_TEXT } from "../lib/utils";

/** Radial 0-100 gauge. Pass score=null for "not scored" (never a fake number). */
export function RiskGauge({ score, size = 220, onClick, label }: { score: number | null; size?: number; onClick?: () => void; label?: string }) {
  const reduce = useReducedMotion();
  const band = riskBand(score);
  const r = size / 2 - 16;
  const c = 2 * Math.PI * r;
  const arc = c * 0.75; // 270deg sweep
  const pct = score == null ? 0 : Math.min(100, Math.max(0, score)) / 100;
  const color = SEV_HEX_VAR[band.sev];
  const Wrapper: React.ElementType = onClick ? "button" : "div";
  return (
    <Wrapper
      type={onClick ? "button" : undefined}
      onClick={onClick}
      aria-label={score == null ? "Risk score: not scored" : `Risk score ${Math.round(score)} out of 100, ${band.label}`}
      className={cn("relative inline-flex items-center justify-center rounded-full", onClick && "cursor-pointer transition hover:scale-[1.02]")}
      style={{ width: size, height: size }}
    >
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-[225deg]" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="hsl(var(--line))" strokeWidth={12} strokeLinecap="round" strokeDasharray={`${arc} ${c}`} />
        <motion.circle
          cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={12} strokeLinecap="round"
          strokeDasharray={`${arc} ${c}`}
          initial={{ strokeDashoffset: arc }}
          animate={{ strokeDashoffset: arc * (1 - pct) }}
          transition={reduce ? { duration: 0 } : { duration: 0.9, ease: "easeOut" }}
          style={{ filter: `drop-shadow(0 0 8px ${color})` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <div className="label">{label ?? "Risk score"}</div>
        <div className={cn("text-5xl font-semibold tabular-nums", SEV_TEXT[band.sev])}>{score == null ? "-" : Math.round(score)}</div>
        <div className={cn("mt-1 text-[11px] font-bold tracking-[0.14em]", SEV_TEXT[band.sev])}>{band.label}</div>
      </div>
    </Wrapper>
  );
}

export function MiniBar({ value, max = 100, sev }: { value: number; max?: number; sev: string }) {
  const pct = Math.min(100, Math.max(0, (value / max) * 100));
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-line" role="img" aria-label={`${Math.round(value)} of ${max}`}>
      <div className="h-full rounded-full" style={{ width: `${pct}%`, background: SEV_HEX_VAR[sev] }} />
    </div>
  );
}
