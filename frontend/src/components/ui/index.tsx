import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import { AlertTriangle, Inbox, Loader2, RefreshCw, X } from "lucide-react";
import { motion } from "framer-motion";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { cn, humanize, SEV_SOFT } from "../../lib/utils";
import type { TriageStatus } from "../../types";
import { TRIAGE_LABELS } from "../../types";

export function SeverityBadge({ severity, className }: { severity: string; className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-bold uppercase tracking-wide", SEV_SOFT[severity] ?? SEV_SOFT.none, className)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" aria-hidden />
      {severity}
    </span>
  );
}

export function Pill({ children, tone = "neutral", className }: { children: ReactNode; tone?: "neutral" | "ok" | "warn" | "bad" | "brand"; className?: string }) {
  const tones = {
    neutral: "border-line bg-raised text-dim",
    ok: "border-ok/40 bg-ok/10 text-ok",
    warn: "border-warn/40 bg-warn/10 text-warn",
    bad: "border-sev-critical/40 bg-sev-critical/10 text-sev-critical",
    brand: "border-brand/40 bg-brand/10 text-brand",
  };
  return <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11.5px] font-medium", tones[tone], className)}>{children}</span>;
}

export function ConfidenceBadge({ value }: { value: string | null }) {
  if (!value) return null;
  const tone = value === "high" ? "ok" : value === "medium" ? "warn" : "neutral";
  return <Pill tone={tone}>Confidence: {value.toUpperCase()}</Pill>;
}

export function TriagePill({ status }: { status: TriageStatus }) {
  const tone = status === "resolved" ? "ok" : status === "open" ? "neutral" : status === "false_positive" || status === "accepted_risk" ? "warn" : "brand";
  return <Pill tone={tone}>{TRIAGE_LABELS[status] ?? humanize(status)}</Pill>;
}

export function DemoBadge({ title = "This scan targets a local test server (fixture/demo data)." }: { title?: string }) {
  return (
    <span title={title} className="inline-flex items-center rounded border border-warn/50 bg-warn/10 px-1.5 py-0.5 text-[10px] font-bold tracking-widest text-warn">
      DEMO DATA
    </span>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return (
    <div className={cn("relative overflow-hidden rounded-md bg-raised", className)} aria-hidden>
      <div className="absolute inset-0 -translate-x-full animate-shimmer bg-gradient-to-r from-transparent via-fg/5 to-transparent" />
    </div>
  );
}

export function ContextLoader({ message }: { message: string }) {
  return (
    <div role="status" className="flex items-center gap-3 rounded-xl border border-line bg-panel p-5 text-dim">
      <Loader2 className="h-4 w-4 animate-spin text-brand" aria-hidden />
      <span>{message}</span>
    </div>
  );
}

export function EmptyState({ icon, title, body, action }: { icon?: ReactNode; title: string; body: ReactNode; action?: { label: string; to: string } }) {
  return (
    <div className="card flex flex-col items-center justify-center gap-3 px-6 py-14 text-center">
      <div className="rounded-full border border-line bg-raised p-3 text-dim">{icon ?? <Inbox className="h-6 w-6" aria-hidden />}</div>
      <h3 className="text-base font-semibold">{title}</h3>
      <p className="max-w-md text-dim">{body}</p>
      {action && <Link to={action.to} className="btn-primary mt-1">{action.label}</Link>}
    </div>
  );
}

export function ErrorState({ title, message, causes, onRetry, details }: { title: string; message: string; causes?: string[]; onRetry?: () => void; details?: string }) {
  return (
    <div role="alert" className="card border-sev-critical/40 p-5">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-sev-critical" aria-hidden />
        <div className="min-w-0 flex-1">
          <h3 className="font-semibold">{title}</h3>
          <p className="mt-1 text-dim">{message}</p>
          {causes && causes.length > 0 && (
            <>
              <p className="mt-3 text-[12px] font-semibold text-dim">Possible causes:</p>
              <ul className="mt-1 list-disc pl-5 text-dim">{causes.map((c) => <li key={c}>{c}</li>)}</ul>
            </>
          )}
          <div className="mt-4 flex flex-wrap gap-2">
            {onRetry && <button className="btn" onClick={onRetry}><RefreshCw className="h-3.5 w-3.5" aria-hidden /> Retry</button>}
          </div>
          {details && (
            <details className="mt-3 text-[12px] text-dim">
              <summary className="cursor-pointer">View details</summary>
              <pre className="mono mt-2 whitespace-pre-wrap rounded-lg bg-bg p-3">{details}</pre>
            </details>
          )}
        </div>
      </div>
    </div>
  );
}

export function PageHeader({ title, sub, actions, crumbs }: { title: string; sub?: ReactNode; actions?: ReactNode; crumbs?: ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div className="min-w-0">
        {crumbs}
        <h1 className="text-[22px] font-semibold tracking-tight">{title}</h1>
        {sub && <p className="mt-1 max-w-3xl text-dim">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </header>
  );
}

export function Stat({ label, value, hint, tone, to }: { label: string; value: ReactNode; hint?: ReactNode; tone?: string; to?: string }) {
  const body = (
    <>
      <div className="label">{label}</div>
      <div className={cn("mt-1 text-2xl font-semibold tabular-nums", tone)}>{value}</div>
      {hint && <div className="mt-0.5 text-[12px] text-dim">{hint}</div>}
    </>
  );
  return to ? <Link to={to} className="card-pad block transition hover:border-brand/50">{body}</Link> : <div className="card-pad">{body}</div>;
}

// ---- Tabs (Radix) ----
export const Tabs = TabsPrimitive.Root;
export function TabsList({ children }: { children: ReactNode }) {
  return <TabsPrimitive.List className="mb-4 flex gap-1 border-b border-line">{children}</TabsPrimitive.List>;
}
export function TabsTrigger({ value, children }: { value: string; children: ReactNode }) {
  return (
    <TabsPrimitive.Trigger value={value} className="-mb-px border-b-2 border-transparent px-3 py-2 text-[13px] font-medium text-dim transition hover:text-fg data-[state=active]:border-brand data-[state=active]:text-fg">
      {children}
    </TabsPrimitive.Trigger>
  );
}
export const TabsContent = TabsPrimitive.Content;

// ---- Tooltip ----
export function Tip({ label, children, side = "right" }: { label: string; children: ReactNode; side?: "top" | "right" | "bottom" | "left" }) {
  return (
    <TooltipPrimitive.Root delayDuration={150}>
      <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
      <TooltipPrimitive.Portal>
        <TooltipPrimitive.Content side={side} sideOffset={8} className="z-[100] max-w-xs rounded-md border border-line bg-raised px-2.5 py-1.5 text-[12px] text-fg shadow-xl">
          {label}
        </TooltipPrimitive.Content>
      </TooltipPrimitive.Portal>
    </TooltipPrimitive.Root>
  );
}
export const TooltipProvider = TooltipPrimitive.Provider;

// ---- Drawer / Modal ----
export function Drawer({ open, onOpenChange, title, description, children, width = "max-w-2xl" }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; description?: string; children: ReactNode; width?: string }) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/50 backdrop-blur-[1px]" />
        <DialogPrimitive.Content
          className={cn("fixed right-0 top-0 z-50 flex h-full w-full flex-col border-l border-line bg-panel shadow-2xl outline-none", width)}
          aria-describedby={description ? undefined : undefined}
        >
          <motion.div initial={{ x: 40, opacity: 0 }} animate={{ x: 0, opacity: 1 }} transition={{ duration: 0.18 }} className="flex h-full min-h-0 flex-col">
            <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-4">
              <div className="min-w-0">
                <DialogPrimitive.Title className="truncate text-base font-semibold">{title}</DialogPrimitive.Title>
                {description ? <DialogPrimitive.Description className="mt-0.5 text-[12px] text-dim">{description}</DialogPrimitive.Description> : <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>}
              </div>
              <DialogPrimitive.Close className="btn-ghost -mr-2" aria-label="Close"><X className="h-4 w-4" /></DialogPrimitive.Close>
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
          </motion.div>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

export function Modal({ open, onOpenChange, title, children }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; children: ReactNode }) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-black/60" />
        <DialogPrimitive.Content className="fixed left-1/2 top-[12vh] z-50 w-[92vw] max-w-xl -translate-x-1/2 rounded-xl border border-line bg-panel p-0 shadow-2xl outline-none">
          <DialogPrimitive.Title className="sr-only">{title}</DialogPrimitive.Title>
          <DialogPrimitive.Description className="sr-only">{title}</DialogPrimitive.Description>
          {children}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
