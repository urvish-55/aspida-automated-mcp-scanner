import { motion } from "framer-motion";
import { AlertTriangle, ArrowDown, CheckCircle2, CircleDashed, HelpCircle } from "lucide-react";
import { useState } from "react";
import { cn } from "../lib/utils";
import type { AttackPath, PathNode } from "../types";
import { ConfidenceBadge, Pill } from "./ui";

const STAGE_LABEL: Record<string, string> = {
  untrusted_input: "Untrusted tool / prompt injection", tool_invocation: "Tool invocation", collection: "Filesystem / credential access",
  egress: "Network access", execution: "Command execution", outcome: "Potential outcome",
};

function NodeCard({ n, onFinding, onTool }: { n: PathNode; onFinding: (id: string) => void; onTool: (t: string) => void }) {
  const [open, setOpen] = useState(false);
  const style =
    n.status === "evidenced" ? "border-sev-high/60 bg-sev-high/5"
    : n.status === "potential" ? "border-dashed border-warn/60 bg-warn/5"
    : "border-dashed border-line bg-raised/40";
  const Icon = n.status === "evidenced" ? CheckCircle2 : n.status === "potential" ? HelpCircle : CircleDashed;
  return (
    <div className={cn("rounded-xl border", style)}>
      <button className="flex w-full items-start gap-3 px-4 py-3 text-left" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        <Icon className={cn("mt-0.5 h-5 w-5 shrink-0", n.status === "evidenced" ? "text-sev-high" : n.status === "potential" ? "text-warn" : "text-dim")} aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="label block">{STAGE_LABEL[n.stage] ?? n.stage}</span>
          <span className="block font-medium">{n.label}</span>
        </span>
        <span className="shrink-0">{n.status === "evidenced" ? <Pill tone="bad">Evidence</Pill> : n.status === "potential" ? <Pill tone="warn">Potential</Pill> : <Pill>No evidence</Pill>}</span>
      </button>
      {open && (
        <div className="space-y-2 border-t border-line/60 px-4 py-3 text-[13px]">
          <div className="flex flex-wrap gap-2">
            <ConfidenceBadge value={n.confidence} />
            {n.category && <Pill>Category: {n.category}</Pill>}
            {n.tools.map((t) => <button key={t} className="chip hover:border-brand/60 hover:text-fg" onClick={() => onTool(t)}>Tool: {t}</button>)}
            {n.finding_ids.filter(Boolean).map((id) => <button key={id} className="chip hover:border-brand/60 hover:text-fg" onClick={() => onFinding(id)}>Open finding</button>)}
          </div>
          <ul className="list-disc space-y-1 pl-5 text-dim">{n.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul>
        </div>
      )}
    </div>
  );
}

export function AttackPathView({ path, onFinding, onTool }: { path: AttackPath; onFinding: (id: string) => void; onTool: (t: string) => void }) {
  return (
    <div className="card p-4">
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {path.complete ? <Pill tone="bad"><AlertTriangle className="h-3 w-3" /> {path.label}</Pill> : <Pill tone="warn"><CircleDashed className="h-3 w-3" /> {path.label}</Pill>}
        <Pill>{path.kind.replace(/_/g, " ")}</Pill>
        <ConfidenceBadge value={path.confidence} />
        {!path.complete && path.missing_stages.length > 0 && <span className="text-[12px] text-dim">Missing: {path.missing_stages.map((s) => STAGE_LABEL[s] ?? s).join(", ")}</span>}
      </div>
      <ol className="space-y-1.5">
        {path.nodes.map((n, i) => (
          <motion.li key={`${n.stage}-${i}`} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}>
            <NodeCard n={n} onFinding={onFinding} onTool={onTool} />
            {i < path.nodes.length - 1 && <div className="flex justify-center py-0.5 text-dim" aria-hidden><ArrowDown className="h-4 w-4" /></div>}
          </motion.li>
        ))}
      </ol>
    </div>
  );
}
