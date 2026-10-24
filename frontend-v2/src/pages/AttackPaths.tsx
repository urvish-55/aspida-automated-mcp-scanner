import { Workflow } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { AttackPathView } from "../components/AttackPathView";
import { ScanPicker } from "../components/ScanPicker";
import { ContextLoader, EmptyState, ErrorState, PageHeader, Stat } from "../components/ui";
import { usePrefs } from "../state/prefs";
import { useActiveScan, useAnalysis } from "../state/queries";

export default function AttackPaths() {
  const nav = useNavigate();
  const { scan, loading } = useActiveScan();
  const { setScanId } = usePrefs();
  const a = useAnalysis(scan?.id);
  if (loading) return <ContextLoader message="Loading scans…" />;
  if (!scan) return <div><PageHeader title="Attack paths" /><EmptyState icon={<Workflow className="h-6 w-6" />} title="No scans yet." body="Run your first MCP security scan to begin analyzing tools and capabilities." action={{ label: "Start New Scan", to: "/scan" }} /></div>;
  const paths = a.data?.attack_paths ?? [];
  const complete = paths.filter((p) => p.complete);
  const openTool = (t: string) => { setScanId(scan.id); nav(`/tools?scan=${scan.id}&tool=${encodeURIComponent(t)}`); };
  return (
    <div>
      <PageHeader title="Attack paths" sub="Chains are drawn only where stored findings and tool capabilities support them. Anything the evidence does not cover is marked, never invented." actions={<ScanPicker />} />
      {a.isLoading ? <ContextLoader message="Building attack paths from evidence…" /> : a.error ? <ErrorState title="Attack paths unavailable" message={(a.error as Error).message} onRetry={() => void a.refetch()} /> : paths.length === 0 ? (
        <EmptyState icon={<Workflow className="h-6 w-6" />} title="No attack path is supported by this scan's evidence." body="A path needs a prompt-injection or hidden-text finding to start from. None was recorded, so nothing is shown. That does not prove no path exists." action={{ label: "View findings", to: `/findings?scan=${scan.id}` }} />
      ) : (
        <>
          <div className="mb-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Stat label="Candidate paths" value={paths.length} />
            <Stat label="Complete evidence" value={complete.length} tone={complete.length ? "text-sev-high" : undefined} hint="every non-potential stage has evidence" />
            <Stat label="Incomplete evidence" value={paths.length - complete.length} hint="missing stages are listed on each path" />
          </div>
          <p className="mb-4 rounded-lg border border-warn/40 bg-warn/5 p-3 text-[13px] text-dim">“Potential” stages (tool invocation, final outcome) describe the documented tool-poisoning mechanism. They are not observed behaviour and no exploit was run.</p>
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">{paths.map((p) => <AttackPathView key={p.id} path={p} onFinding={(id) => nav(`/findings?scan=${scan.id}&open=${id}`)} onTool={openTool} />)}</div>
        </>
      )}
    </div>
  );
}
