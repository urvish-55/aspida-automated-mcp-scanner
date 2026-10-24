import { useMutation, useQueryClient } from "@tanstack/react-query";
import { GitCompare, History, Trash2 } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { DemoBadge, EmptyState, ErrorState, Modal, PageHeader, Pill, Skeleton } from "../components/ui";
import { api } from "../services/api";
import { useScans } from "../state/queries";
import { cn, fmtDateTime, isLocalTarget, riskBand, SEV_TEXT } from "../lib/utils";

export default function ScanHistory() {
  const nav = useNavigate();
  const qc = useQueryClient();
  const { data, isLoading, error, refetch } = useScans(200);
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const del = useMutation({ mutationFn: (id: string) => api.deleteScan(id), onSuccess: () => void qc.invalidateQueries() });
  const items = useMemo(() => (data?.items ?? []).filter((s) => (!status || s.status === status) && (!q || `${s.target_label} ${s.id}`.toLowerCase().includes(q.toLowerCase()))), [data, q, status]);
  const toggle = (id: string) => setPicked((p) => (p.includes(id) ? p.filter((x) => x !== id) : [...p.slice(-1), id]));

  if (error) return <ErrorState title="Could not load scan history" message={(error as Error).message} onRetry={() => void refetch()} />;
  return (
    <div>
      <PageHeader title="Scan history" sub="Every scan stored in this installation."
        actions={<button className="btn-primary" disabled={picked.length !== 2} onClick={() => nav(`/compare?a=${picked[0]}&b=${picked[1]}`)}><GitCompare className="h-4 w-4" /> Compare selected ({picked.length}/2)</button>} />
      <div className="mb-4 flex flex-wrap gap-3">
        <input className="input max-w-xs" placeholder="Filter by target or scan ID" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Filter scans" />
        <select className="input !w-auto" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status">
          <option value="">All statuses</option>{["completed", "running", "queued", "failed", "cancelled"].map((s) => <option key={s}>{s}</option>)}
        </select>
      </div>
      {isLoading ? <Skeleton className="h-48" /> : items.length === 0 ? (
        <EmptyState icon={<History className="h-6 w-6" />} title={data?.items.length ? "No scans match these filters." : "No scans yet."} body={data?.items.length ? "Clear the filters to see every scan." : "Run your first MCP security scan to begin analyzing tools and capabilities."} action={data?.items.length ? undefined : { label: "Start New Scan", to: "/scan" }} />
      ) : (
        <div className="card overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead><tr className="border-b border-line text-dim"><th className="w-10 px-3 py-2.5"><span className="sr-only">Select</span></th>{["Target", "Status", "Risk", "Started", ""].map((h) => <th key={h} className="px-3 py-2.5 font-medium">{h}</th>)}</tr></thead>
            <tbody>
              {items.map((s) => {
                const band = riskBand(s.risk_score);
                return (
                  <tr key={s.id} className="border-b border-line/60 transition last:border-0 hover:bg-raised/50">
                    <td className="px-3 py-2.5"><input type="checkbox" className="accent-[hsl(var(--brand))]" checked={picked.includes(s.id)} onChange={() => toggle(s.id)} aria-label={`Select scan ${s.id.slice(0, 8)} for comparison`} disabled={s.status !== "completed"} /></td>
                    <td className="px-3 py-2.5"><Link to={`/scans/${s.id}`} className="font-medium hover:text-brand">{s.target_label || s.id}</Link> {isLocalTarget(s) && <DemoBadge />}<div className="mono text-[11px] text-dim">{s.id.slice(0, 12)}</div></td>
                    <td className="px-3 py-2.5"><Pill tone={s.status === "completed" ? "ok" : s.status === "failed" ? "bad" : s.status === "cancelled" ? "warn" : "brand"}>{s.status}</Pill></td>
                    <td className={cn("px-3 py-2.5 tabular-nums font-semibold", SEV_TEXT[band.sev])}>{s.risk_score != null ? `${Math.round(s.risk_score)} · ${band.label.split(" ")[0]}` : "-"}</td>
                    <td className="px-3 py-2.5 text-dim">{fmtDateTime(s.created_at)}</td>
                    <td className="px-3 py-2.5 text-right"><button className="btn-ghost" aria-label={`Delete scan ${s.id.slice(0, 8)}`} onClick={() => setConfirmId(s.id)}><Trash2 className="h-4 w-4" /></button></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <Modal open={!!confirmId} onOpenChange={(o) => { if (!o) setConfirmId(null); }} title="Delete scan">
        <div className="p-5">
          <h2 className="text-base font-semibold">Delete this scan?</h2>
          <p className="mt-2 text-dim">The scan, its findings, tool inventory and remediation notes are removed permanently. This cannot be undone.</p>
          <div className="mt-5 flex justify-end gap-2">
            <button className="btn" onClick={() => setConfirmId(null)}>Cancel</button>
            <button className="btn-danger" onClick={() => { if (confirmId) del.mutate(confirmId); setConfirmId(null); }}>Delete scan</button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
