import { useEffect, useState } from "react";

/**
 * Frontend initialisation only. Each line reflects something that really happened in the browser:
 * the 3D chunk was loaded (Suspense resolved → canvas mounted), a WebGL context exists, and the first frame rendered.
 * It never reports backend scan progress.
 */
export function BootOverlay({ use3D, engineReady, reduced }: { use3D: boolean; engineReady: boolean; reduced: boolean }) {
  const [gone, setGone] = useState(false);
  const [canvasUp, setCanvasUp] = useState(false);
  useEffect(() => { if (!use3D) return; const t = setInterval(() => { if (document.querySelector("[data-testid=journey] canvas")) { setCanvasUp(true); clearInterval(t); } }, 60); return () => clearInterval(t); }, [use3D]);
  useEffect(() => { if (!engineReady) return; const t = setTimeout(() => setGone(true), reduced ? 0 : 700); return () => clearTimeout(t); }, [engineReady, reduced]);
  useEffect(() => { const t = setTimeout(() => setGone(true), 8000); return () => clearTimeout(t); }, []); // never trap the user behind the overlay
  if (!use3D || gone || reduced) return null;
  const steps = [{ l: "Loading 3D engine", d: canvasUp || engineReady }, { l: "Loading security core", d: engineReady }, { l: "Loading visual system", d: engineReady }];
  const done = steps.filter((x) => x.d).length + (engineReady ? 0 : 0);
  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-bg/95 transition-opacity duration-500" role="status" aria-live="polite" data-testid="boot">
      <div className="w-[min(86vw,420px)] font-mono text-[11px] uppercase tracking-[0.2em]">
        <p className="mb-4 text-fg">Initializing MCP security environment</p>
        <div className="h-1 w-full overflow-hidden rounded bg-line"><div className="h-full bg-brand transition-[width] duration-300" style={{ width: `${Math.round((done / steps.length) * 100)}%` }} /></div>
        <ul className="mt-4 space-y-1 text-dim">{steps.map((x) => <li key={x.l} className={x.d ? "text-fg" : ""}>{x.l} {x.d ? "· done" : "…"}</li>)}</ul>
        <p className="mt-4 h-4 text-brand">{engineReady ? "System ready" : ""}</p>
      </div>
    </div>
  );
}

/** Premium 2D background for the no-WebGL / skipped / mobile views: layered SVG rings, animated with CSS only (static under reduced motion). */
export function CoreSvg() {
  return (
    <svg className="pointer-events-none absolute left-1/2 top-1/2 h-[min(90vmin,760px)] w-[min(90vmin,760px)] -translate-x-1/2 -translate-y-1/2 opacity-70" viewBox="-200 -200 400 400" aria-hidden>
      <defs><radialGradient id="cg" r="1"><stop offset="0" stopColor="hsl(var(--brand))" stopOpacity="0.28" /><stop offset="1" stopColor="hsl(var(--brand))" stopOpacity="0" /></radialGradient></defs>
      <circle r="190" fill="url(#cg)" />
      {[60, 95, 130, 165].map((r, i) => <circle key={r} r={r} fill="none" stroke="hsl(var(--brand))" strokeOpacity={0.45 - i * 0.08} strokeWidth="0.8" strokeDasharray={i % 2 ? "2 7" : "40 10"} className={i % 2 ? "story-spin-rev" : "story-spin"} />)}
      <polygon points="0,-34 30,0 0,34 -30,0" fill="none" stroke="hsl(var(--fg))" strokeOpacity="0.5" strokeWidth="1" />
      <circle r="9" fill="hsl(var(--brand))" fillOpacity="0.6" />
    </svg>
  );
}
