import { useActiveScan } from "../state/queries";
import { fmtDateTime, riskBand } from "../lib/utils";
import { DemoBadge } from "./ui";
import { isLocalTarget } from "../lib/utils";

export function ScanPicker({ label = "Scan" }: { label?: string }) {
  const { scan, scans, setScanId } = useActiveScan();
  const finished = scans.filter((s) => s.status !== "queued" && s.status !== "running");
  if (finished.length === 0) return null;
  return (
    <div className="flex min-w-0 max-w-full flex-wrap items-center gap-2">
      <label className="label" htmlFor="scan-picker">{label}</label>
      <select id="scan-picker" className="input !w-auto max-w-[200px] min-w-0 sm:max-w-[320px] !py-1.5" value={scan?.id ?? ""} onChange={(e) => setScanId(e.target.value || null)}>
        {finished.map((s) => <option key={s.id} value={s.id}>{(s.target_label || s.id.slice(0, 8)).slice(0, 40)} · {fmtDateTime(s.created_at)} · {s.risk_score != null ? `${Math.round(s.risk_score)} ${riskBand(s.risk_score).sev}` : s.status}</option>)}
      </select>
      {scan && isLocalTarget(scan) && <DemoBadge />}
    </div>
  );
}
