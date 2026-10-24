import { useQuery } from "@tanstack/react-query";
import { Box } from "lucide-react";
import { Component, lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { Fallback2D } from "../components/security/Fallback2D";
import { FilterPanel } from "../components/security/FilterPanel";
import { Inspector } from "../components/security/Inspector";
import { ObjectList } from "../components/security/ObjectList";
import { PathPanel } from "../components/security/PathPanel";
import { SceneControls } from "../components/security/SceneControls";
import { ScanPanel } from "../components/security/ScanPanel";
import { InvestigationDrawer } from "../components/Investigation";
import { ScanPicker } from "../components/ScanPicker";
import { ContextLoader, EmptyState, ErrorState, PageHeader, Pill, SeverityBadge } from "../components/ui";
import { useIsNarrow, useReducedMotion, useWebGLSupport } from "../hooks/useWebGL";
import { computeHighlight } from "../lib/highlight";
import { resolveQuality } from "../lib/quality";
import { deriveStages, findingsAvailable, isLive } from "../lib/scanEvents";
import { buildCapabilityScene, buildGalaxyScene, buildGraphScene, buildPathScene, buildScanScene, buildTerrainScene, type SceneModel } from "../lib/sceneModel";
import { buildSecurityGraph, filterGraph, findingId, toolId } from "../lib/securityGraph";
import { safeLabel } from "../lib/safeText";
import { cn, riskBand } from "../lib/utils";
import { api } from "../services/api";
import { useShallow } from "zustand/react/shallow";
import { useInvestigation } from "../state/investigation";
import { usePrefs } from "../state/prefs";
import { useActiveScan, useAnalysis, useScanDetail, useScans } from "../state/queries";
import type { Finding } from "../types";
import { VIZ_MODES, type VizMode } from "../types/visualization";

const SceneCanvas = lazy(() => import("../components/3d/SceneCanvas"));

class SceneBoundary extends Component<{ onError: (m: string) => void; children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch(err: Error) { this.props.onError(err.message); }
  render() { return this.state.failed ? null : this.props.children; }
}

const MODE_NOTE: Record<VizMode, string> = {
  graph: "Spheres are tools, cubes are capabilities, octahedra are findings (larger = more severe). The hexagonal core is the server.",
  paths: "Solid = stored evidence. Outlined or dashed = potential or missing evidence. These are suspected chains, not observed attacks.",
  galaxy: "Findings grouped by category. Position inside a cluster has no meaning; size and colour show severity.",
  capabilities: "Tools (upper ring) linked to the capabilities they were inferred to have. Orange links appear only where the backend reported a dangerous capability combination.",
  terrain: "Bar height is the raw RISK-1 points for each category and severity, before the section caps. It is not the scan score.",
  scan: "The real pipeline stages. Only the stage the backend reports as active pulses, and only while a scan is running.",
};

export default function CommandCenter() {
  const { theme, setScanId } = usePrefs();
  const [params, setParams] = useSearchParams();
  const { scan: activeScan, loading: scansLoading } = useActiveScan();
  const allScans = useScans(200);
  const st = useInvestigation(useShallow((s) => ({
    mode: s.mode, filters: s.filters, selectedId: s.selectedId, activePathId: s.activePathId, isolateId: s.isolateId, force2D: s.force2D, quality: s.quality, effects: s.effects,
    select: s.select, isolate: s.isolate, setActivePath: s.setActivePath, resetFilters: s.resetFilters, setMode: s.setMode, focus: s.focus, escape: s.escape,
  })));
  const webgl = useWebGLSupport();
  const narrow = useIsNarrow();
  const reduced = useReducedMotion();
  const [ctxLost, setCtxLost] = useState(false);
  const [sceneError, setSceneError] = useState<string | null>(null);
  const [openFinding, setOpenFinding] = useState<Finding | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [compareId, setCompareId] = useState("");
  const [showCompare, setShowCompare] = useState(true);
  const box = useRef<HTMLDivElement>(null);

  // deep link: ?scan=…&focus=tool:x
  const qScan = params.get("scan");
  useEffect(() => { if (qScan) setScanId(qScan); }, [qScan, setScanId]);

  const running = (allScans.data?.items ?? []).find((s) => s.status === "running");
  const watchLive = st.mode === "scan" && !!running;
  const scanId = watchLive ? running!.id : qScan ?? activeScan?.id;
  const detail = useScanDetail(scanId);
  const analysis = useAnalysis(scanId);
  const scan = detail.data;

  const graph = useMemo(() => (scan ? buildSecurityGraph(scan, analysis.data) : null), [scan, analysis.data]);
  const categories = useMemo(() => [...new Set((scan?.findings ?? []).map((f) => f.category))].sort(), [scan]);
  const filtered = useMemo(() => (graph ? filterGraph(graph, st.filters) : null), [graph, st.filters]);
  const stages = useMemo(() => (scan ? deriveStages(scan.events, scan.status) : []), [scan]);
  const live = isLive(scan?.status);

  const model: SceneModel | null = useMemo(() => {
    if (!scan || !graph || !filtered) return null;
    switch (st.mode) {
      case "paths": return buildPathScene(analysis.data?.attack_paths ?? []);
      case "galaxy": return buildGalaxyScene(filtered.nodes);
      case "capabilities": return buildCapabilityScene(graph.nodes, graph.edges, scan.findings);
      case "terrain": return buildTerrainScene(scan.findings);
      case "scan": return buildScanScene(stages, live, scan, analysis.data);
      default: return buildGraphScene(filtered.nodes, filtered.edges);
    }
  }, [scan, graph, filtered, st.mode, analysis.data, stages, live]);

  // reset view state when the scan changes
  useEffect(() => { st.select(null); st.isolate(null); st.setActivePath(null); setCompareId(""); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [scanId]);

  // deep-link focus once the node exists
  const qFocus = params.get("focus");
  useEffect(() => {
    if (!qFocus || !graph) return;
    if (!graph.nodes.some((n) => n.id === qFocus)) return;
    st.resetFilters(); st.setMode("graph"); st.focus(qFocus);
    const next = new URLSearchParams(params); next.delete("focus"); setParams(next, { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qFocus, graph]);

  // Esc steps back; ignored while typing
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      if (e.key !== "Escape" || (t && /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) || document.querySelector("[role=dialog]")) return;
      st.escape();
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [st]);

  useEffect(() => {
    const h = () => setFullscreen(document.fullscreenElement === box.current);
    document.addEventListener("fullscreenchange", h);
    return () => document.removeEventListener("fullscreenchange", h);
  }, []);
  const toggleFullscreen = useCallback(() => {
    if (document.fullscreenElement) void document.exitFullscreen();
    else void box.current?.requestFullscreen?.();
  }, []);

  const compare = useQuery({ queryKey: ["compare", compareId, scanId], queryFn: () => api.compare(compareId, scanId as string), enabled: !!compareId && !!scanId && compareId !== scanId });
  const marked = useMemo(() => {
    const c = compare.data;
    if (!c || !showCompare) return undefined;
    return new Set<string>([...c.new_findings.map((f) => findingId(f.id)), ...c.changed_severity.map((f) => findingId(f.id)), ...c.tools_added.map(toolId), ...c.tools_changed.map((t) => toolId(t.name))]);
  }, [compare.data, showCompare]);

  if (scansLoading) return <ContextLoader message="Loading scans…" />;
  if (!scanId) return <div><PageHeader title="3D Command Center" /><EmptyState icon={<Box className="h-6 w-6" />} title="No scans yet." body="Run a scan to investigate its tools, capabilities, findings and attack paths in 3D." action={{ label: "Start New Scan", to: "/scan" }} /></div>;
  if (detail.isLoading) return <ContextLoader message="Loading scan data…" />;
  if (detail.error || !scan || !graph || !filtered || !model) return <div><PageHeader title="3D Command Center" /><ErrorState title="Scan data unavailable" message={(detail.error as Error | null)?.message ?? "The scan could not be loaded."} onRetry={() => void detail.refetch()} causes={["The backend is not running", "The scan was deleted"]} /></div>;

  const can3D = webgl && !ctxLost && !sceneError && !narrow;
  const use2D = !can3D || st.force2D;
  const reason2D = !webgl ? "WebGL is not available in this browser, so the 2D view is shown." : ctxLost ? "The graphics context was lost, so the 2D view is shown." : sceneError ? `The 3D scene failed to start (${sceneError}). Showing 2D.` : narrow ? "Showing the 2D view on small screens." : undefined;
  const quality = resolveQuality(st.quality, model.items.length, st.effects, { cores: navigator.hardwareConcurrency || 4, dpr: window.devicePixelRatio || 1, prefersReducedMotion: reduced });
  const band = riskBand(scan.risk_score);
  const sevCounts = (["critical", "high", "medium", "low", "info"] as const).map((s) => [s, scan.findings.filter((f) => f.severity === s && f.status !== "informational").length] as const);
  const selected = st.selectedId;
  const selectedItem = model.items.find((i) => i.id === selected);
  const otherScans = (allScans.data?.items ?? []).filter((s) => s.id !== scanId && s.status === "completed");
  const hl = computeHighlight(model, { selectedId: st.selectedId, hoveredId: null, activePathId: st.activePathId, isolateId: st.isolateId, markedIds: marked });

  const left = st.mode === "paths" ? <PathPanel paths={analysis.data?.attack_paths ?? []} />
    : st.mode === "scan" ? <ScanPanel stages={stages} live={live} status={scan.status} findingsReady={findingsAvailable(scan.events, scan.status)} />
    : st.mode === "graph" || st.mode === "galaxy" ? <FilterPanel categories={categories} hidden={filtered.hiddenCount} total={graph.nodes.length} />
    : <p className="text-[12.5px] text-dim">Filters apply to the Security Graph and Threat Galaxy. This view always shows the full scan.</p>;

  const inspector = <Inspector selectedId={selected} graph={graph} scan={scan} analysis={analysis.data} stages={stages} onOpenFinding={setOpenFinding} onClose={() => st.select(null)} />;

  return (
    <div>
      <PageHeader title="3D Command Center" sub="Investigate the scanned MCP server as a connected system. Every object is drawn from stored scan data; nothing is simulated." actions={<ScanPicker />} />

      <section aria-label="Risk overview" className="card mb-3 flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2.5 text-[13px]">
        <div><span className="label mr-2">Risk (RISK-1)</span><b className="text-lg tabular-nums">{scan.risk_score != null ? Math.round(scan.risk_score) : "–"}</b> <span className="text-dim">{band.label}</span></div>
        <div className="flex flex-wrap items-center gap-1.5"><span className="label mr-1">Findings</span>{sevCounts.map(([s, n]) => <span key={s} className="inline-flex items-center gap-1"><SeverityBadge severity={s} /><b className="tabular-nums">{n}</b></span>)}</div>
        <div><span className="label mr-2">Tools</span><b className="tabular-nums">{scan.tools.length}</b></div>
        <div><span className="label mr-2">Attack-path candidates</span><b className="tabular-nums">{analysis.data?.attack_paths.length ?? "–"}</b></div>
      </section>

      <div role="tablist" aria-label="Visualization mode" className="mb-3 flex gap-1 overflow-x-auto pb-1">
        {VIZ_MODES.map((m) => (
          <button key={m.id} role="tab" aria-selected={st.mode === m.id} title={m.hint} onClick={() => st.setMode(m.id)}
            className={cn("shrink-0 rounded-lg border px-3 py-1.5 text-[13px] transition", st.mode === m.id ? "border-brand/60 bg-brand/10 font-medium text-fg" : "border-line text-dim hover:text-fg")}>
            {m.label}{m.id === "scan" && running && <span className="ml-1.5 inline-block h-2 w-2 animate-pulseDot rounded-full bg-brand align-middle" aria-label="a scan is running" />}
          </button>
        ))}
      </div>

      {watchLive && <p className="mb-3 rounded-lg border border-brand/40 bg-brand/5 px-3 py-2 text-[13px]" role="status">Watching running scan <b>{safeLabel(scan.target_label)}</b>. The view updates from the backend event stream.</p>}
      {scan.status === "failed" && <p className="mb-3 rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-3 py-2 text-[13px] text-sev-critical" role="alert">This scan failed{scan.error ? `: ${safeLabel(scan.error, 200)}` : "."} Partial data may be missing.</p>}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[250px_minmax(0,1fr)] xl:grid-cols-[250px_minmax(0,1fr)_340px]">
        <aside aria-label="Filters and panels" className="order-2 min-w-0 space-y-4 lg:order-1">
          <div className="card-pad">{left}</div>
          {otherScans.length > 0 && (
            <div className="card-pad">
              <h2 className="label mb-2">Compare with earlier scan</h2>
              <select className="input" aria-label="Scan to compare against" value={compareId} onChange={(e) => setCompareId(e.target.value)}>
                <option value="">None</option>
                {otherScans.map((s) => <option key={s.id} value={s.id}>{(s.target_label || s.id.slice(0, 8)).slice(0, 28)} · {new Date(s.created_at).toLocaleDateString()}</option>)}
              </select>
              {compare.isLoading && <p className="mt-2 text-[12px] text-dim">Comparing…</p>}
              {compare.error && <p className="mt-2 text-[12px] text-sev-critical" role="alert">Comparison failed: {(compare.error as Error).message}</p>}
              {compare.data && (
                <div className="mt-2 space-y-1 text-[12.5px]">
                  <label className="flex items-center gap-2"><input type="checkbox" checked={showCompare} onChange={(e) => setShowCompare(e.target.checked)} /> Highlight changes in the scene</label>
                  <p><b>{compare.data.new_findings.length}</b> new finding(s)</p>
                  <p><b>{compare.data.changed_severity.length}</b> with changed severity</p>
                  <p><b>{compare.data.tools_added.length}</b> tool(s) added · <b>{compare.data.tools_changed.length}</b> changed</p>
                  <p><b>{compare.data.resolved_findings.length}</b> no longer detected <span className="text-dim">(not confirmed fixed; the tool or rule may have changed)</span></p>
                </div>
              )}
            </div>
          )}
        </aside>

        <div className="order-1 min-w-0 space-y-3 lg:order-2">
          <div ref={box} className={cn("relative overflow-hidden rounded-xl border border-line bg-panel", fullscreen ? "h-screen" : "h-[min(72vh,720px)] min-h-[380px]")} data-testid="scene-box" data-renderer={use2D ? "2d" : "3d"}>
            <SceneControls can3D={can3D} isFullscreen={fullscreen} onFullscreen={toggleFullscreen} nodeCount={model.items.length} />
            {model.items.length === 0 && model.empty && <div className="absolute inset-0 z-[5] grid place-items-center p-6 text-center text-dim">{model.empty}</div>}
            {use2D ? <Fallback2D model={model} theme={theme} markedIds={marked} reason={reason2D} /> : (
              <SceneBoundary onError={setSceneError}>
                <Suspense fallback={<div className="grid h-full place-items-center"><ContextLoader message="Loading 3D engine…" /></div>}>
                  <SceneCanvas model={model} theme={theme} quality={quality} markedIds={marked} frameKey={`${scanId}:${st.mode}`} onContextLost={() => setCtxLost(true)} />
                </Suspense>
              </SceneBoundary>
            )}
            <p className="pointer-events-none absolute bottom-2 left-2 right-2 z-10 max-w-[90%] rounded bg-panel/85 px-2 py-1 text-[11.5px] text-dim">{MODE_NOTE[st.mode]}</p>
          </div>
          <div className="sr-only" aria-live="polite">{selectedItem ? `Selected ${selectedItem.kind} ${selectedItem.label}` : "Nothing selected"}</div>

          <div className="flex flex-wrap items-center gap-2 text-[12px] text-dim">
            <Pill>{use2D ? "2D view" : `3D · ${quality.tier} quality`}</Pill>
            {marked && <Pill tone="brand">Showing changes vs earlier scan</Pill>}
            {st.isolateId && <button className="btn !py-0.5 text-[12px]" onClick={() => st.isolate(null)}>Showing isolation · show all</button>}
            <span>Orbit: drag · Pan: right-drag or arrows · Zoom: wheel · Isolate: double-click · Esc: step back</span>
          </div>

          <ObjectList items={model.items.filter((i) => !hl.hidden.has(i.id))} />
          <details className="text-[12px] text-dim"><summary className="cursor-pointer">What this view does not show</summary><ul className="mt-1 list-disc pl-5">{graph.notes.map((n) => <li key={n}>{n}</li>)}<li>Capabilities are inferred by static rules and show potential reach, not observed behaviour.</li></ul></details>
        </div>

        {!narrow && <aside aria-label="Inspector" className="order-3 hidden min-w-0 xl:block"><div className="card-pad sticky top-[72px] max-h-[calc(100vh-96px)] overflow-auto">{inspector}</div></aside>}
      </div>

      {/* inspector below xl: inline card on tablet, bottom sheet on phones */}
      {selected && !narrow && <section className="card-pad mt-4 xl:hidden" aria-label="Inspector (details)">{inspector}</section>}
      {selected && narrow && <div className="fixed inset-x-0 bottom-0 z-30 max-h-[58vh] overflow-auto rounded-t-2xl border-t border-line bg-panel p-4 shadow-2xl" role="dialog" aria-label="Inspector">{inspector}</div>}

      <InvestigationDrawer finding={openFinding} scanId={scanId ?? null} onClose={() => setOpenFinding(null)} />
    </div>
  );
}

