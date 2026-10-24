import { FileSearch } from "lucide-react";
import { useMemo, useState } from "react";
import { EvidenceBlock } from "../components/EvidenceViewer";
import { ScanPicker } from "../components/ScanPicker";
import { ContextLoader, EmptyState, PageHeader, Pill, SeverityBadge } from "../components/ui";
import { cn } from "../lib/utils";
import { useActiveScan, useScanDetail } from "../state/queries";

export default function Evidence() {
  const { scan, loading } = useActiveScan();
  const d = useScanDetail(scan?.id);
  const [sel, setSel] = useState<string | null>(null);
  const [kind, setKind] = useState("");
  const withEv = useMemo(() => (d.data?.findings ?? []).filter((f) => f.evidence.length > 0 && f.category !== "engine"), [d.data]);
  const kinds = useMemo(() => [...new Set(withEv.flatMap((f) => f.evidence.map((e) => e.kind)))].sort(), [withEv]);
  const list = withEv.filter((f) => !kind || f.evidence.some((e) => e.kind === kind));
  const current = list.find((f) => f.id === sel) ?? list[0];

  if (loading || d.isLoading) return <ContextLoader message="Loading evidence…" />;
  if (!scan) return <div><PageHeader title="Evidence" /><EmptyState icon={<FileSearch className="h-6 w-6" />} title="No scans yet." body="Run your first MCP security scan to begin analyzing tools and capabilities." action={{ label: "Start New Scan", to: "/scan" }} /></div>;
  return (
    <div>
      <PageHeader title="Evidence" sub="Every piece of evidence recorded for the scan, with the exact suspicious text highlighted." actions={<ScanPicker />} />
      {withEv.length === 0 ? <EmptyState icon={<FileSearch className="h-6 w-6" />} title="No evidence recorded." body="This scan has no findings with evidence blocks." /> : (
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-[340px_minmax(0,1fr)]">
          <aside className="card h-fit p-3 lg:sticky lg:top-20">
            <select className="input mb-3" value={kind} onChange={(e) => setKind(e.target.value)} aria-label="Filter by evidence type"><option value="">All evidence types</option>{kinds.map((k) => <option key={k} value={k}>{k.replace(/_/g, " ")}</option>)}</select>
            <ul className="max-h-[70vh] space-y-1 overflow-y-auto">{list.map((f) => <li key={f.id}><button onClick={() => setSel(f.id)} className={cn("w-full rounded-lg border px-3 py-2 text-left transition", current?.id === f.id ? "border-brand bg-brand/10" : "border-transparent hover:bg-raised")}><div className="flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="text-[11.5px] text-dim">{f.evidence.length} block(s)</span></div><div className="mt-1 truncate text-[13px]">{f.title}</div></button></li>)}</ul>
          </aside>
          <section className="min-w-0">
            {current && <>
              <div className="mb-3"><h2 className="text-lg font-semibold">{current.title}</h2><div className="mt-1 flex flex-wrap gap-2"><Pill>{current.rule_id}</Pill>{current.affected_tools.map((t) => <Pill key={t} tone="brand">{t}</Pill>)}</div></div>
              <div className="space-y-2">{current.evidence.filter((e) => !kind || e.kind === kind).map((e, i) => <EvidenceBlock key={`${current.id}-${i}`} ev={e} tools={(d.data?.tools ?? []).filter((t) => current.affected_tools.includes(t.name))} defaultOpen={i === 0} />)}</div>
            </>}
          </section>
        </div>
      )}
    </div>
  );
}
