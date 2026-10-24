import { Suspense, lazy, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { InvestigationDrawer } from "../components/Investigation";
import { Fallback2D } from "../components/security/Fallback2D";
import { SectionBody, type StoryStatus } from "../components/story/StorySections";
import { useIsNarrow, useReducedMotion, useWebGLSupport } from "../hooks/useWebGL";
import { useScrollProgress } from "../hooks/useScrollProgress";
import { buildGraphScene } from "../lib/sceneModel";
import { buildSecurityGraph, buildStoryData, demoAnalysis, demoScan, capLabel, type StoryData } from "../lib/storyData";
import { resolveQuality } from "../lib/quality";
import { safeLabel } from "../lib/safeText";
import { SEV_RANK } from "../lib/severity";
import { SECTIONS, type SectionId, type StoryAnchors } from "../lib/storyTimeline";
import { cn, fmtDateTime } from "../lib/utils";
import { BootOverlay, CoreSvg } from "../components/story/BootOverlay";
import { findingId, toolId } from "../lib/securityGraph";
import { useInvestigation } from "../state/investigation";
import { usePrefs } from "../state/prefs";
import { useAnalysis, useActiveScan, useScanDetail } from "../state/queries";
import { useStory } from "../state/story";
import type { Finding, ScanDetail } from "../types";

const StoryScene = lazy(() => import("../components/story/StoryScene"));
const DEMO = "__demo__";
const NO_LABEL = "Illustrative example";

const blankScan = (): ScanDetail => ({ ...demoScan(), id: "none", target_label: "", findings: [], tools: [], tests: [], risk_score: null });

function ProgressIndicator({ onGo }: { onGo: (i: number) => void }) {
  const index = useStory((s) => s.index);
  return (
    <nav aria-label="Story sections" className="fixed bottom-4 right-4 z-30 flex flex-col items-end gap-2 sm:bottom-auto sm:right-5 sm:top-1/2 sm:-translate-y-1/2">
      <p className="rounded-full border border-line/70 bg-panel/70 px-3 py-1 font-mono text-[11px] tracking-widest backdrop-blur" aria-live="polite" data-testid="progress-label">
        {String(index + 1).padStart(2, "0")} / {SECTIONS.length}<span className="sr-only"> {SECTIONS[index]!.label}</span>
      </p>
      <ul className="hidden flex-col items-end gap-1.5 sm:flex">
        {SECTIONS.map((s, i) => (
          <li key={s.id}>
            <button type="button" onClick={() => onGo(i)} aria-label={`Go to section ${i + 1}: ${s.label}`} aria-current={i === index ? "step" : undefined} className="group flex items-center gap-2 outline-none">
              <span className={cn("text-[10px] uppercase tracking-widest opacity-0 transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100", i === index && "opacity-100")}>{s.label}</span>
              <span className={cn("block h-1.5 rounded-full bg-dim/50 transition-all group-focus-visible:ring-2 group-focus-visible:ring-brand motion-reduce:transition-none", i === index ? "w-6 bg-brand" : "w-1.5 group-hover:bg-fg")} />
            </button>
          </li>
        ))}
      </ul>
    </nav>
  );
}

function SelectionCard({ model, data, selectedId, scanId, onInvestigate, onClose }: { model: ReturnType<typeof buildGraphScene>; data: StoryData; selectedId: string; scanId: string; onInvestigate: (f: Finding) => void; onClose: () => void }) {
  const nav = useNavigate();
  const item = model.items.find((i) => i.id === selectedId);
  const tool = data.scan.tools.find((t) => toolId(t.name) === selectedId);
  const finding = data.scan.findings.find((f) => findingId(f.id) === selectedId);
  if (!item || (!tool && !finding)) return null;
  const real = data.source === "scan";
  return (
    <aside aria-label="Selected object" className="fixed bottom-16 left-3 right-3 z-30 max-h-[40vh] overflow-auto rounded-xl border border-line/70 bg-panel/85 p-4 text-[13px] backdrop-blur-md sm:bottom-6 sm:left-auto sm:right-24 sm:w-[340px]" data-testid="selection-card">
      <div className="flex items-start justify-between gap-2">
        <h3 className="min-w-0 break-words font-semibold">{safeLabel(tool ? tool.name : finding!.title, 90)}</h3>
        <button type="button" onClick={onClose} className="rounded px-1.5 text-dim hover:text-fg focus-visible:ring-2 focus-visible:ring-brand" aria-label="Close selection">×</button>
      </div>
      {tool && (
        <>
          <p className="mt-1 text-dim">{safeLabel(tool.description || "No description provided by the server.", 200)}</p>
          <p className="mt-2 text-[12px]">Capabilities: {tool.capabilities.length ? tool.capabilities.map(capLabel).join(", ") : "none inferred"}</p>
        </>
      )}
      {finding && (
        <>
          <p className="mt-1 text-dim">{finding.severity.toUpperCase()} · {finding.category.replace(/_/g, " ")} · {finding.evidence.length} evidence block{finding.evidence.length === 1 ? "" : "s"}</p>
          <button type="button" className="mt-3 rounded-md border border-line px-3 py-1.5 font-medium hover:border-brand/60 focus-visible:ring-2 focus-visible:ring-brand" onClick={() => onInvestigate(finding)}>Open investigation</button>
        </>
      )}
      {real ? (
        <button type="button" className="mt-3 block rounded-md bg-brand px-3 py-1.5 font-semibold text-bg focus-visible:ring-2 focus-visible:ring-fg" onClick={() => nav(`/command?scan=${encodeURIComponent(scanId)}&focus=${encodeURIComponent(selectedId)}`)}>Explore in Dashboard</button>
      ) : <p className="mt-3 text-[11px] text-sev-medium">Illustrative Example · not scan data</p>}
    </aside>
  );
}

export default function Journey() {
  const nav = useNavigate();
  const { setScanId } = usePrefs();
  const { scan: active, scans, loading: scansLoading, error: scansError, refetch } = useActiveScan();
  const [demo, setDemo] = useState(false);
  const detail = useScanDetail(demo ? undefined : active?.id);
  const analysisQ = useAnalysis(demo ? undefined : active?.id);
  const prev = useMemo(() => {
    if (!active) return null;
    return scans.filter((s) => s.status === "completed" && s.id !== active.id && s.target_identifier === active.target_identifier && s.created_at < active.created_at)
      .sort((a, b) => (b.created_at < a.created_at ? -1 : 1))[0] ?? null;
  }, [active, scans]);
  const prevDetail = useScanDetail(demo ? undefined : prev?.id);

  const status: StoryStatus = demo ? "demo"
    : scansLoading ? "loading"
    : scansError ? "error"
    : !active ? "empty"
    : detail.isLoading ? "loading"
    : detail.error || !detail.data ? "error"
    : "ready";

  const data = useMemo<StoryData>(() => {
    if (status === "demo") return buildStoryData(demoScan(), demoAnalysis(), "demo");
    if (status === "ready" && detail.data) return buildStoryData(detail.data, analysisQ.data, "scan", prevDetail.data ?? null);
    return buildStoryData(blankScan(), undefined, "scan");
  }, [status, detail.data, analysisQ.data, prevDetail.data]);

  const graph = useMemo(() => buildSecurityGraph(data.scan, data.analysis), [data]);
  const model = useMemo(() => buildGraphScene(graph.nodes, graph.edges), [graph]);

  const anchors = useMemo<StoryAnchors>(() => {
    const pos = new Map(model.items.map((i) => [i.id, i.pos]));
    const worst = model.items.filter((i) => i.kind === "finding").sort((a, b) => SEV_RANK[b.level === "none" ? "info" : b.level] - SEV_RANK[a.level === "none" ? "info" : a.level])[0];
    const topId = data.topFinding ? findingId(data.topFinding.id) : null;
    const threat = (topId && pos.get(topId)) || worst?.pos || null;
    const path: [number, number, number][] = [];
    for (const nd of data.topPath?.nodes ?? []) {
      const ids = [...nd.tools.map(toolId), ...nd.finding_ids.map(findingId)];
      const p = ids.map((i) => pos.get(i)).find(Boolean);
      if (p && !path.some((q) => q[0] === p[0] && q[1] === p[1] && q[2] === p[2])) path.push([p[0], p[1], p[2]]);
    }
    return { R: Math.max(model.radius, 3), threat: threat ? [threat[0], threat[1], threat[2]] : null, path };
  }, [model, data]);

  // Environment and rendering mode.
  const reduced = useReducedMotion();
  const narrow = useIsNarrow();
  const webgl = useWebGLSupport();
  const [lost, setLost] = useState(false);
  const quality = useMemo(() => resolveQuality("auto", model.items.length, "full", { cores: navigator.hardwareConcurrency || 4, dpr: window.devicePixelRatio || 1, prefersReducedMotion: reduced }), [model.items.length, reduced]);
  const [skip3D, setSkip3D] = useState(() => { try { return sessionStorage.getItem("story-skip3d") === "1"; } catch { return false; } });
  const toggleSkip = () => setSkip3D((v) => { const n = !v; try { sessionStorage.setItem("story-skip3d", n ? "1" : "0"); } catch { /* storage may be unavailable */ } return n; });
  const use3D = webgl && !narrow && !lost && !skip3D;
  const [engineReady, setEngineReady] = useState(false);
  const setFocus = useStory((s) => s.setFocus);

  useScrollProgress();
  const index = useStory((s) => s.index);

  // Section-driven emphasis through the shared investigation store (also what Fallback2D reads).
  const selectedId = useInvestigation((s) => s.selectedId);
  const hoveredId = useInvestigation((s) => s.hoveredId);
  const activePathId = useInvestigation((s) => s.activePathId);
  const select = useInvestigation((s) => s.select);
  const hover = useInvestigation((s) => s.hover);
  const setActivePath = useInvestigation((s) => s.setActivePath);
  const topId = data.topFinding ? findingId(data.topFinding.id) : null;
  const auto = useMemo(() => {
    const id = SECTIONS[index]!.id;
    return { sel: id === "threat" || id === "evidence" || id === "verify" || id === "remediation" ? topId : null, path: id === "path" ? data.topPath?.id ?? null : null };
  }, [index, topId, data.topPath]);
  useEffect(() => { select(auto.sel); setActivePath(auto.path); }, [auto, select, setActivePath]);
  useEffect(() => () => { select(null); hover(null); setActivePath(null); }, [select, hover, setActivePath]);

  // Page chrome: always dark, own title.
  useEffect(() => {
    const root = document.documentElement; const prevTheme = root.dataset.theme; const prevTitle = document.title;
    root.dataset.theme = "dark"; document.title = "MCP Pentester · Secure the MCP Ecosystem";
    return () => { if (prevTheme) root.dataset.theme = prevTheme; else delete root.dataset.theme; document.title = prevTitle; };
  }, []);

  const [drawer, setDrawer] = useState<Finding | null>(null);
  const onSelect = useCallback((id: string) => {
    select(id);
    const it = model.items.find((i) => i.id === id);
    if (it) setFocus([it.pos[0], it.pos[1], it.pos[2]]);
  }, [model, select, setFocus]);
  const goTo = useCallback((i: number) => {
    const el = document.getElementById(`story-${SECTIONS[i]!.id}`);
    el?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "start" });
  }, [reduced]);
  const goId = useCallback((id: SectionId) => goTo(SECTIONS.findIndex((s) => s.id === id)), [goTo]);

  const userSelected = selectedId && selectedId !== auto.sel ? selectedId : null;
  const hoverName = hoveredId ? model.items.find((i) => i.id === hoveredId)?.label : null;
  const scanId = data.source === "scan" ? data.scan.id : "";
  const finished = scans.filter((s) => s.status === "completed");
  const ctx = useMemo(() => ({ data, status, motion: quality.motion !== "none", onInvestigate: setDrawer, onFocusTool: (n: string) => onSelect(toolId(n)), onGo: goId, reload: () => void refetch() }), [data, status, quality.motion, goId, refetch, onSelect]);
  const wrapRef = useRef<HTMLDivElement>(null);

  return (
    <div ref={wrapRef} className="story-root relative bg-bg text-fg" data-testid="journey" data-mode={use3D ? "3d" : "2d"}>
      {/* World layer */}
      <div className="fixed inset-0 z-0" aria-hidden>
        {use3D ? (
          <Suspense fallback={null}>
            <StoryScene model={model} anchors={anchors} quality={quality} selectedId={selectedId} activePathId={activePathId} hoveredId={hoveredId} onHover={hover} onSelect={onSelect} onContextLost={() => setLost(true)} onReady={() => setEngineReady(true)} resolved={data.verify.state === "resolved"} />
          </Suspense>
        ) : (
          <><CoreSvg /><div className="absolute inset-0 opacity-60"><Fallback2D model={model} theme="dark" /></div></>
        )}
        <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_at_20%_50%,hsl(var(--bg)/0.85),transparent_60%),linear-gradient(to_bottom,hsl(var(--bg)/0.5),transparent_20%,transparent_80%,hsl(var(--bg)/0.6))]" />
      </div>

      {/* Navigation */}
      <header className="fixed inset-x-0 top-0 z-30 flex items-center justify-between gap-2 px-3 py-3 sm:px-6">
        <Link to="/journey" className="shrink-0 whitespace-nowrap font-mono text-[11px] font-semibold uppercase tracking-[0.14em] outline-none sm:text-[12px] sm:tracking-[0.2em] focus-visible:ring-2 focus-visible:ring-brand">MCP Pentester</Link>
        <div className="flex min-w-0 items-center gap-2 sm:gap-3">
          <label className="sr-only" htmlFor="story-scan">Scan shown in this story</label>
          <select id="story-scan" className="max-w-[30vw] truncate rounded-md border border-line/70 bg-panel/70 px-2 py-1 text-[12px] backdrop-blur sm:max-w-[260px]"
            value={demo ? DEMO : active?.id ?? ""} onChange={(e) => { if (e.target.value === DEMO) setDemo(true); else { setDemo(false); setScanId(e.target.value || null); } }}>
            {finished.length === 0 && !demo && <option value="">No scans yet</option>}
            {finished.map((s) => <option key={s.id} value={s.id}>{safeLabel(s.target_label || s.id.slice(0, 8), 30)} · {fmtDateTime(s.created_at)}</option>)}
            <option value={DEMO}>{NO_LABEL} (not a scan)</option>
          </select>
          {webgl && <button type="button" onClick={toggleSkip} aria-pressed={skip3D} className="rounded-md px-2 py-1 text-[11px] uppercase tracking-wider text-dim hover:text-fg focus-visible:ring-2 focus-visible:ring-brand" data-testid="skip3d">{skip3D ? "Enable 3D" : <><span className="sm:hidden">Skip 3D</span><span className="hidden sm:inline">Skip 3D experience</span></>}</button>}
          <Link to="/scan" className="hidden rounded-md px-2.5 py-1 text-[12px] uppercase tracking-wider hover:text-brand sm:inline">Start Scan</Link>
          <Link to="/" className="shrink-0 rounded-md border border-line/70 bg-panel/70 px-2 py-1 text-[12px] font-medium backdrop-blur uppercase tracking-wider hover:border-brand/60 sm:px-3">Dashboard</Link>
        </div>
      </header>

      <ProgressIndicator onGo={goTo} />
      <BootOverlay use3D={use3D} engineReady={engineReady} reduced={reduced} />

      {/* Status strip */}
      {(status !== "ready") && (
        <div className="fixed left-1/2 top-14 z-30 -translate-x-1/2 rounded-full border border-line/70 bg-panel/80 px-3 py-1 text-[11.5px] backdrop-blur" role="status" data-testid="status-strip">
          {status === "demo" ? "Demo Environment · Illustrative Example, not scan data" : status === "loading" ? "Loading scan data…" : status === "error" ? <>Data unavailable. <button type="button" className="underline" onClick={() => void refetch()}>Retry</button></> : "No scan has been performed."}
        </div>
      )}
      {!use3D && (
        <p className="fixed bottom-4 left-4 z-30 max-w-[60vw] rounded border border-line/70 bg-panel/80 px-2 py-1 text-[11px] text-dim backdrop-blur" role="note">
          {skip3D ? "3D skipped. Showing the 2D view of the same story." : !webgl ? "3D is unavailable in this browser. Showing the 2D view of the same story." : lost ? "The 3D context was lost. Showing the 2D view." : "Compact 2D view on small screens."}
        </p>
      )}

      {/* Story */}
      <main id="main" tabIndex={-1} className="relative z-10 outline-none">
        {SECTIONS.map((s, i) => (
          <section key={s.id} id={`story-${s.id}`} aria-label={s.label} style={{ height: `${s.weight * 100}vh` }} className="relative" data-section={s.id}>
            <div className="sticky top-0 flex h-screen items-center px-4 pb-16 pt-16 sm:px-10 lg:px-[7vw]">
              <div className={cn("max-h-[calc(100svh-7rem)] w-full overflow-y-auto rounded-2xl border border-line/50 bg-panel/55 p-5 backdrop-blur-md transition-opacity duration-500 motion-reduce:transition-none sm:max-w-[470px] sm:p-7", i === 0 && "border-transparent bg-transparent !backdrop-blur-0 sm:max-w-[640px]", index === i ? "opacity-100" : "opacity-30")}
                data-active={index === i}>
                <SectionBody id={s.id} ctx={ctx} />
              </div>
            </div>
          </section>
        ))}
      </main>

      {hoverName && <p className="pointer-events-none fixed bottom-4 left-1/2 z-30 -translate-x-1/2 rounded bg-panel/85 px-2 py-1 font-mono text-[11px]" aria-hidden data-testid="hover-label">{safeLabel(hoverName, 60)}</p>}
      {userSelected && <SelectionCard model={model} data={data} selectedId={userSelected} scanId={scanId} onInvestigate={setDrawer} onClose={() => select(auto.sel)} />}
      <InvestigationDrawer finding={drawer} scanId={scanId || null} onClose={() => setDrawer(null)} />
      {void nav}
    </div>
  );
}
