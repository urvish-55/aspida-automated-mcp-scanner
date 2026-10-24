import { Canvas } from "@react-three/fiber";
import { useEffect, useMemo } from "react";
import * as THREE from "three";
import { computeHighlight } from "../../lib/highlight";
import type { QualitySettings } from "../../lib/quality";
import type { SceneModel, Shape } from "../../lib/sceneModel";
import { themeHex, type Theme } from "../../lib/severity";
import { useInvestigation } from "../../state/investigation";
import { usePageVisible } from "../../hooks/useWebGL";
import { CameraRig } from "./CameraRig";
import { Instanced } from "./Instanced";
import { Labels } from "./Labels";
import { Lines } from "./Lines";

const SHAPES: Shape[] = ["sphere", "octa", "box", "ico", "bar", "ring"];

/** The WebGL scene. Default-exported so the page can lazy-load three.js only when a 3D view is opened. */
export default function SceneCanvas({ model, theme, quality, markedIds, frameKey, onContextLost }: { model: SceneModel; theme: Theme; quality: QualitySettings; markedIds?: ReadonlySet<string>; frameKey: string; onContextLost: () => void }) {
  const visible = usePageVisible();
  const selectedId = useInvestigation((s) => s.selectedId);
  const hoveredId = useInvestigation((s) => s.hoveredId);
  const activePathId = useInvestigation((s) => s.activePathId);
  const isolateId = useInvestigation((s) => s.isolateId);
  const labelsOn = useInvestigation((s) => s.labels);
  const hover = useInvestigation((s) => s.hover);
  const select = useInvestigation((s) => s.select);
  const isolate = useInvestigation((s) => s.isolate);
  const focus = useInvestigation((s) => s.focus);

  const hl = useMemo(() => computeHighlight(model, { selectedId, hoveredId, activePathId, isolateId, markedIds }), [model, selectedId, hoveredId, activePathId, isolateId, markedIds]);
  const groups = useMemo(() => {
    const m = new Map<string, typeof model.items>();
    for (const i of model.items) { const k = `${i.shape}|${i.ghost ? 1 : 0}`; m.set(k, [...(m.get(k) ?? []), i]); }
    return m;
  }, [model]);
  const animate = quality.motion === "full";
  const needsLoop = animate && model.items.some((i) => i.pulse);
  const bg = themeHex(theme, "bg");
  useEffect(() => () => { document.body.style.cursor = ""; }, []);

  return (
    <Canvas
      frameloop={!visible ? "never" : needsLoop ? "always" : "demand"}
      dpr={quality.dpr}
      gl={{ antialias: quality.antialias, powerPreference: "high-performance", alpha: false }}
      camera={{ fov: 50, near: 0.1, far: 2000, position: [10, 14, 24] }}
      onCreated={({ gl }) => {
        gl.setClearColor(new THREE.Color(bg));
        gl.domElement.tabIndex = 0;
        gl.domElement.setAttribute("aria-label", "3D scene. Use arrow keys to pan, mouse or touch to orbit and zoom. A text list of the same objects follows.");
        gl.domElement.addEventListener("webglcontextlost", (e) => { e.preventDefault(); onContextLost(); });
      }}
      onPointerMissed={() => { /* background click keeps the current selection; Esc or the Clear button deselects */ }}
    >
      <color attach="background" args={[bg]} />
      <ambientLight intensity={theme === "dark" ? 0.75 : 1.0} />
      <hemisphereLight args={[theme === "dark" ? "#9fb6ff" : "#ffffff", theme === "dark" ? "#101522" : "#c9d3e6", 0.55]} />
      <directionalLight position={[20, 30, 20]} intensity={theme === "dark" ? 1.1 : 0.9} />
      {quality.grid && <gridHelper args={[model.radius * 2.6, 26, themeHex(theme, "line"), themeHex(theme, "line")]} position={[0, -model.radius * 0.45, 0]} />}
      <Lines lines={model.lines} items={model.items} emphasis={hl.line} hidden={hl.hidden} theme={theme} />
      {SHAPES.flatMap((shape) => [false, true].map((ghost) => {
        const items = groups.get(`${shape}|${ghost ? 1 : 0}`);
        return items ? (
          <Instanced key={`${shape}${ghost}`} shape={shape} ghost={ghost} items={items} emphasis={hl.item} hidden={hl.hidden} theme={theme} segments={quality.segments} animate={animate}
            onHover={hover} onSelect={select} onDeep={(id) => { isolate(id); focus(id); }} />
        ) : null;
      }))}
      <Labels items={model.items} labels={model.labels} emphasis={hl.item} hidden={hl.hidden} budget={quality.labelBudget} show={labelsOn} hoveredId={hoveredId} selectedId={selectedId} />
      <CameraRig items={model.items} radius={model.radius} motion={quality.motion} frameKey={frameKey} />
    </Canvas>
  );
}
