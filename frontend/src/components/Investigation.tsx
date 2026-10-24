import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Box, ExternalLink, Wrench } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../services/api";
import { useAnalysis, useScanDetail } from "../state/queries";
import { usePrefs } from "../state/prefs";
import { humanize } from "../lib/utils";
import type { Finding, TriageStatus } from "../types";
import { TRIAGE_LABELS } from "../types";
import { AttackPathView } from "./AttackPathView";
import { CodeViewer } from "./CodeViewer";
import { EvidenceBlock } from "./EvidenceViewer";
import { ConfidenceBadge, ContextLoader, Drawer, Pill, SeverityBadge } from "./ui";

const TRIAGE_ORDER: TriageStatus[] = ["open", "acknowledged", "in_progress", "resolved", "false_positive", "accepted_risk"];

export function TriageControl({ finding, onSaved }: { finding: Finding; onSaved?: () => void }) {
  const qc = useQueryClient();
  const [status, setStatus] = useState<TriageStatus>(finding.triage_status);
  const [note, setNote] = useState(finding.triage_note);
  useEffect(() => { setStatus(finding.triage_status); setNote(finding.triage_note); }, [finding.id, finding.triage_status, finding.triage_note]);
  const m = useMutation({
    mutationFn: () => api.setTriage(finding.id, status, note),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["findings"] });
      void qc.invalidateQueries({ queryKey: ["scan"] });
      onSaved?.();
    },
  });
  const dirty = status !== finding.triage_status || note !== finding.triage_note;
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1.5" role="radiogroup" aria-label="Remediation status">
        {TRIAGE_ORDER.map((s) => (
          <button key={s} role="radio" aria-checked={status === s} onClick={() => setStatus(s)}
            className={status === s ? "btn-primary !py-1" : "btn !py-1"}>{TRIAGE_LABELS[s]}</button>
        ))}
      </div>
      <textarea className="input min-h-[64px]" value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} placeholder="Optional note (who is fixing it, ticket link, why accepted…)" aria-label="Remediation note" />
      <div className="flex items-center gap-3">
        <button className="btn-primary" disabled={!dirty || m.isPending} onClick={() => m.mutate()}>{m.isPending ? "Saving…" : "Save status"}</button>
        {m.isSuccess && !dirty && <span className="text-[12px] text-ok" role="status">Saved to the database.</span>}
        {m.isError && <span className="text-[12px] text-sev-critical" role="alert">{(m.error as Error).message}</span>}
      </div>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="mb-6"><h3 className="label mb-2">{title}</h3>{children}</section>;
}

function isUrl(s: string) { return /^https?:\/\//i.test(s); }

export function InvestigationDrawer({ finding, scanId, onClose }: { finding: Finding | null; scanId: string | null; onClose: () => void }) {
  const nav = useNavigate();
  const { setScanId } = usePrefs();
  const scan = useScanDetail(finding ? scanId ?? undefined : undefined);
  const analysis = useAnalysis(finding ? scanId ?? undefined : undefined);
  const tools = scan.data?.tools ?? [];
  const paths = (analysis.data?.attack_paths ?? []).filter((p) =>
    p.nodes.some((n) => finding && (n.finding_ids.includes(finding.id) || n.tools.some((t) => finding.affected_tools.includes(t)))));
  const openTool = (t: string) => { if (scanId) setScanId(scanId); onClose(); nav(`/tools?tool=${encodeURIComponent(t)}`); };

  return (
    <Drawer open={!!finding} onOpenChange={(o) => { if (!o) onClose(); }} title={finding?.title ?? ""} description={finding ? `${finding.rule_id} · ${humanize(finding.category)}` : undefined} width="max-w-3xl">
      {finding && (
        <>
          <Section title="Summary">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={finding.severity} />
              <ConfidenceBadge value={finding.confidence} />
              <Pill tone={finding.status === "confirmed" ? "bad" : "neutral"}>Detector status: {finding.status}</Pill>
              <Pill>Evidence blocks: {finding.evidence.length}</Pill>
            </div>
            {finding.status !== "confirmed" && <p className="mt-2 text-[12px] text-dim">Not confirmed by a live test. Treat as a lead that needs verification.</p>}
          </Section>

          <Section title="Why it was detected"><p className="whitespace-pre-wrap leading-relaxed">{finding.description}</p>{finding.impact && <p className="mt-2 text-dim"><b className="text-fg">Potential impact:</b> {finding.impact}</p>}</Section>

          <div className="mb-5"><button className="btn" onClick={() => { if (scanId) setScanId(scanId); onClose(); nav(`/command?scan=${scanId}&focus=${encodeURIComponent(`finding:${finding.id}`)}`); }}><Box className="h-3.5 w-3.5" aria-hidden /> View in 3D</button></div>
          <Section title="Affected tool">
            {finding.affected_tools.length === 0 ? <p className="text-dim">This finding applies to the scan as a whole, not one tool.</p> : (
              <div className="flex flex-wrap gap-2">{finding.affected_tools.map((t) => <button key={t} className="btn" onClick={() => openTool(t)}><Wrench className="h-3.5 w-3.5" aria-hidden /> {t}</button>)}</div>
            )}
          </Section>

          <Section title={`Evidence (${finding.evidence.length})`}>
            {scan.isLoading && <ContextLoader message="Loading tool definitions for evidence highlighting…" />}
            <div className="space-y-2">{finding.evidence.map((e, i) => <EvidenceBlock key={i} ev={e} tools={tools.filter((t) => finding.affected_tools.includes(t.name))} defaultOpen={i === 0} />)}</div>
            {finding.evidence.length === 0 && <p className="text-dim">No evidence blocks were recorded.</p>}
          </Section>

          <Section title="Attack path">
            {analysis.isLoading ? <ContextLoader message="Building capability graph…" /> : paths.length === 0 ? (
              <p className="text-dim">No attack path is supported by the evidence for this finding. Paths are shown only when stored findings and capabilities support them.</p>
            ) : <div className="space-y-3">{paths.slice(0, 3).map((p) => <AttackPathView key={p.id} path={p} onFinding={() => undefined} onTool={openTool} />)}</div>}
          </Section>

          {Object.keys(finding.reproduction ?? {}).length > 0 && (
            <Section title="Safe reproduction"><CodeViewer value={finding.reproduction} maxHeight={260} title="Reproduction" /></Section>
          )}

          <Section title="Remediation"><p className="whitespace-pre-wrap leading-relaxed">{finding.remediation || "No remediation text recorded."}</p></Section>

          {finding.references.length > 0 && (
            <Section title="References">
              <ul className="space-y-1">{finding.references.map((r) => <li key={r}>{isUrl(r) ? <a className="inline-flex items-center gap-1 text-brand hover:underline" href={r} target="_blank" rel="noopener noreferrer">{r}<ExternalLink className="h-3 w-3" /></a> : <span>{r}</span>}</li>)}</ul>
            </Section>
          )}

          <Section title="Track remediation"><TriageControl finding={finding} /></Section>
        </>
      )}
    </Drawer>
  );
}
