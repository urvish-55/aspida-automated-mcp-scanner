import { Radar } from "lucide-react";
import { Link } from "react-router-dom";
import { EmptyState, PageHeader, Pill, Skeleton } from "../components/ui";
import { timeAgo } from "../lib/utils";
import { useScans } from "../state/queries";

export default function ActiveScans() {
  const { data, isLoading } = useScans(100);
  const active = (data?.items ?? []).filter((s) => s.status === "running" || s.status === "queued");
  return (
    <div>
      <PageHeader title="Active scans" sub="Scans that are queued or running right now." actions={<Link to="/scan" className="btn-primary">New scan</Link>} />
      {isLoading ? <Skeleton className="h-24" /> : active.length === 0 ? (
        <EmptyState icon={<Radar className="h-6 w-6" />} title="No scans running." body="Start a scan to watch it live. Finished scans are in Scan History." action={{ label: "Start New Scan", to: "/scan" }} />
      ) : (
        <ul className="space-y-3">
          {active.map((s) => (
            <li key={s.id}>
              <Link to={`/scans/${s.id}`} className="card flex items-center gap-4 p-4 transition hover:border-brand/60">
                <span className="h-2.5 w-2.5 animate-pulseDot rounded-full bg-brand" aria-hidden />
                <span className="min-w-0 flex-1"><span className="block truncate font-medium">{s.target_label}</span><span className="text-[12px] text-dim">{s.id.slice(0, 8)} · started {timeAgo(s.started_at ?? s.created_at)}</span></span>
                <Pill tone="brand">{s.status}</Pill>
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
