import { Eye, EyeOff, Layers, Maximize2, Minimize2, Rotate3d, Square, X } from "lucide-react";
import { useInvestigation } from "../../state/investigation";

/** Floating scene controls. Every control is a real button / select with a text label for assistive tech. */
export function SceneControls({ can3D, isFullscreen, onFullscreen, nodeCount }: { can3D: boolean; isFullscreen: boolean; onFullscreen: () => void; nodeCount: number }) {
  const { labels, setLabels, resetView, selectedId, isolateId, isolate, select, quality, setQuality, effects, setEffects, force2D, setForce2D, focus } = useInvestigation();
  return (
    <div className="pointer-events-none absolute right-2 top-2 z-10 flex max-w-[calc(100%-1rem)] flex-wrap justify-end gap-1.5" role="toolbar" aria-label="Scene controls">
      <div className="pointer-events-auto flex items-center gap-0.5 rounded-lg border border-line bg-panel/90 p-0.5 backdrop-blur">
        {can3D && <button className="btn-ghost !p-1.5" onClick={resetView} aria-label="Reset camera"><Rotate3d className="h-4 w-4" /></button>}
        <button className="btn-ghost !p-1.5" onClick={() => setLabels(!labels)} aria-pressed={labels} aria-label={labels ? "Hide labels" : "Show labels"}>{labels ? <Eye className="h-4 w-4" /> : <EyeOff className="h-4 w-4" />}</button>
        <button className="btn-ghost !p-1.5" disabled={!selectedId} onClick={() => { if (selectedId) { isolate(isolateId ? null : selectedId); focus(selectedId); } }} aria-pressed={!!isolateId} aria-label={isolateId ? "Show all objects" : "Isolate selection"}><Layers className="h-4 w-4" /></button>
        <button className="btn-ghost !p-1.5" disabled={!selectedId} onClick={() => select(null)} aria-label="Clear selection"><X className="h-4 w-4" /></button>
        <button className="btn-ghost !p-1.5" onClick={onFullscreen} aria-label={isFullscreen ? "Exit full screen" : "Full screen"}>{isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}</button>
        <button className="btn-ghost !p-1.5" onClick={() => setForce2D(!force2D)} aria-pressed={force2D || !can3D} disabled={!can3D && !force2D} aria-label={force2D || !can3D ? "Switch to 3D" : "Switch to 2D"}><Square className="h-4 w-4" /></button>
      </div>
      {can3D && (
        <div className="pointer-events-auto flex items-center gap-1 rounded-lg border border-line bg-panel/90 px-1.5 py-0.5 text-[11.5px] backdrop-blur">
          <label className="text-dim" htmlFor="q3d">Quality</label>
          <select id="q3d" className="rounded bg-transparent py-0.5 text-fg" value={quality} onChange={(e) => setQuality(e.target.value as typeof quality)}>
            <option value="auto">Auto</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option>
          </select>
          <label className="ml-1 text-dim" htmlFor="fx3d">Effects</label>
          <select id="fx3d" className="rounded bg-transparent py-0.5 text-fg" value={effects} onChange={(e) => setEffects(e.target.value as typeof effects)}>
            <option value="full">Full</option><option value="reduced">Reduced</option><option value="off">Off</option>
          </select>
          <span className="ml-1 hidden text-dim sm:inline" title="Objects drawn">{nodeCount} obj</span>
        </div>
      )}
    </div>
  );
}
