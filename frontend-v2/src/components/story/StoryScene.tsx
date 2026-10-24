import { Canvas, invalidate, useFrame, useThree } from "@react-three/fiber";
import { useEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import { Instanced } from "../3d/Instanced";
import { Lines } from "../3d/Lines";
import { Environment, Streams } from "./Environment";
import { SecurityCore } from "./SecurityCore";
import { computeHighlight } from "../../lib/highlight";
import type { QualitySettings } from "../../lib/quality";
import type { SceneItem, SceneLine, SceneModel } from "../../lib/sceneModel";
import { themeHex } from "../../lib/severity";
import { alongPath, cameraAt, reveal, sectionRange, SECTION_INDEX, smoothstep, staticPose, type StoryAnchors } from "../../lib/storyTimeline";
import { usePageVisible } from "../../hooks/useWebGL";
import { useStory } from "../../state/story";

interface Props {
  model: SceneModel; anchors: StoryAnchors; quality: QualitySettings;
  selectedId: string | null; activePathId: string | null; hoveredId: string | null;
  onHover: (id: string | null) => void; onSelect: (id: string) => void; onContextLost: () => void;
  /** Called once, after the first rendered frame (real frontend initialisation, not a fake timer). */
  onReady?: () => void;
  /** The backend confirmed the top finding is resolved: the threat markers are not drawn for the remediation/verify scenes. */
  resolved?: boolean;
}
const T = "dark" as const;
const sec = (id: Parameters<typeof sectionRange>[0]) => sectionRange(id);
const mix = (a: number, b: number, t: number) => a + (b - a) * t;

/** Camera driven entirely by scroll progress through the central timeline; smoothed so scroll jumps never cut. */
function ScrollCamera({ anchors, motion }: { anchors: StoryAnchors; motion: QualitySettings["motion"] }) {
  const camera = useThree((s) => s.camera);
  const pointer = useThree((s) => s.pointer);
  const look = useRef(new THREE.Vector3());
  const first = useRef(true);
  const focusW = useRef(0);
  const lastFocus = useRef<[number, number, number] | null>(null);
  useFrame(({ clock }, dt) => {
    const p = useStory.getState().progress;
    const pose = motion === "none" ? staticPose(anchors) : cameraAt(p, anchors);
    const sway = motion === "full" ? Math.sin(clock.elapsedTime * 0.25) * 0.015 * anchors.R : 0;
    const target = new THREE.Vector3(pose.position[0] + sway + (motion === "full" ? pointer.x * 0.02 * anchors.R : 0), pose.position[1] + (motion === "full" ? pointer.y * 0.015 * anchors.R : 0), pose.position[2]);
    const aim = new THREE.Vector3(...pose.target);
    const st = useStory.getState();
    // Optional click-to-focus: blend toward a close pose on the clicked object. Scrolling to another section clears it.
    focusW.current += ((st.focus && motion !== "none" ? 1 : 0) - focusW.current) * (1 - Math.exp(-dt * 4));
    if (st.focus) lastFocus.current = st.focus.pos;
    if (lastFocus.current && focusW.current > 0.001) {
      const fp = new THREE.Vector3(...lastFocus.current); const out = fp.clone().setY(fp.y + anchors.R * 0.1);
      if (out.lengthSq() < 1e-6) out.set(0, 0.2, 1); out.normalize().multiplyScalar(anchors.R * 0.55);
      target.lerp(fp.clone().add(out), focusW.current); aim.lerp(fp, focusW.current);
    }
    if (motion === "full" && st.id === "threat") { const a = 0.004 * anchors.R * Math.sin(st.local * Math.PI); target.x += Math.sin(clock.elapsedTime * 41) * a; target.y += Math.cos(clock.elapsedTime * 37) * a; } // extremely subtle
    if (first.current || motion === "none") { camera.position.copy(target); look.current.copy(aim); first.current = false; }
    else { const k = 1 - Math.exp(-dt * 5); camera.position.lerp(target, k); look.current.lerp(aim, k); }
    camera.lookAt(look.current);
  });
  return null;
}

function Particles({ count, R }: { count: number; R: number }) {
  const ref = useRef<THREE.Points>(null);
  const geo = useMemo(() => {
    const g = new THREE.BufferGeometry();
    const a = new Float32Array(count * 3);
    let s = 1234567; const rnd = () => { s = (s * 16807) % 2147483647; return s / 2147483647; }; // deterministic
    for (let i = 0; i < count; i++) {
      const r = R * (2.2 + rnd() * 4.5); const th = rnd() * Math.PI * 2; const ph = Math.acos(2 * rnd() - 1);
      a.set([r * Math.sin(ph) * Math.cos(th), r * Math.cos(ph) * 0.6, r * Math.sin(ph) * Math.sin(th)], i * 3);
    }
    g.setAttribute("position", new THREE.BufferAttribute(a, 3));
    return g;
  }, [count, R]);
  useEffect(() => () => geo.dispose(), [geo]);
  useFrame(() => { if (ref.current) ref.current.rotation.y = useStory.getState().progress * 0.9; }); // parallax tied to scroll
  return <points ref={ref} geometry={geo}><pointsMaterial color={themeHex(T, "none")} size={R * 0.012} sizeAttenuation transparent opacity={0.55} depthWrite={false} /></points>;
}

function World({ model, anchors, quality, selectedId, activePathId, hoveredId, onHover, onSelect, resolved }: Omit<Props, "onContextLost" | "onReady">) {
  const R = anchors.R;
  const reduced = quality.motion === "none";
  const hl = useMemo(() => computeHighlight(model, { selectedId, hoveredId, activePathId, isolateId: null }), [model, selectedId, hoveredId, activePathId]);
  const byKind = useMemo(() => {
    const m: Record<string, SceneItem[]> = { server: [], tool: [], capability: [], finding: [] };
    for (const i of model.items) (m[i.kind] ??= []).push(i);
    const kindOf = new Map(model.items.map((i) => [i.id, i.kind]));
    const l: Record<string, SceneLine[]> = { tool: [], capability: [], finding: [] };
    for (const ln of model.lines) { const k = kindOf.get(ln.b) === "capability" ? "capability" : kindOf.get(ln.a) === "finding" ? "finding" : "tool"; l[k].push(ln); }
    return { items: m, lines: l };
  }, [model]);

  const toolsRef = useRef<THREE.Group>(null); const capsRef = useRef<THREE.Group>(null); const findRef = useRef<THREE.Group>(null);
  const ring = useRef<THREE.Mesh>(null); const pulse = useRef<THREE.Mesh>(null); const light = useRef<THREE.Mesh>(null); const core = useRef<THREE.Group>(null);
  const capLineOp = useRef({ current: 0 }).current; const findLineOp = useRef({ current: 0 }).current; const pathOp = useRef({ current: 0 }).current;
  const toolLineOp = useRef({ current: 0 }).current;
  const pathGeo = useMemo(() => { const g = new THREE.BufferGeometry(); if (anchors.path.length > 1) g.setFromPoints(anchors.path.map((p) => new THREE.Vector3(...p))); return g; }, [anchors.path]);
  useEffect(() => () => pathGeo.dispose(), [pathGeo]);
  const speed = useRef({ current: 1 }).current; // global time scale: the world slows at the threat and freezes for evidence
  const scanner = useRef<THREE.Group>(null); const contain = useRef<THREE.Mesh>(null);
  const streamOp = useRef({ current: 0 }).current;
  const animate = !reduced && quality.motion === "full";

  useFrame(({ clock }) => {
    const p = reduced ? sec("surface")[0] + 1e-4 : useStory.getState().progress;
    const [e0, e1] = sec("ecosystem"); const [d0, d1] = sec("discovery"); const [t0, t1] = sec("threat"); const [p0, p1] = sec("path");
    const kt = reduced ? 1 : reveal(p, mix(e0, e1, 0.1), mix(e0, e1, 0.85));
    const kc = reduced ? 1 : reveal(p, mix(d0, d1, 0.25), mix(d0, d1, 0.85));
    const kf = reduced ? 1 : reveal(p, t0, mix(t0, t1, 0.5));
    const setK = (g: THREE.Group | null, k: number) => { if (!g) return; g.visible = k > 0.005; g.scale.setScalar(Math.max(0.001, k)); };
    setK(toolsRef.current, kt); setK(capsRef.current, kc); setK(findRef.current, kf);
    toolLineOp.current = smoothstep((kt - 0.85) / 0.15) ; capLineOp.current = smoothstep((kc - 0.85) / 0.15); findLineOp.current = smoothstep((kf - 0.85) / 0.15);
    pathOp.current = reduced ? 0 : reveal(p, p0, mix(p0, p1, 0.1));
    const [v0, v1] = sec("verify"); const [x0, x1] = sec("testing"); const [ev0] = sec("evidence");
    const target = p >= ev0 && p < sec("risk")[0] ? 0.04 : p >= t0 && p < p0 ? 0.25 : p >= p0 && p < ev0 ? 0.6 : 1; // threat: slow; evidence: nearly frozen
    speed.current += (target - speed.current) * 0.06;
    streamOp.current = Math.min(kt, 1);
    if (core.current) { core.current.rotation.y = reduced ? 0 : p * 0.6; const s = 1 + (reduced ? 0 : Math.sin(clock.elapsedTime * 1.2 * speed.current) * 0.01); core.current.scale.setScalar(s); }
    if (scanner.current) { // testing: three scroll-tied passes of a scanning field; verify: one pass to the finding. Visual metaphor only.
      const inTest = !reduced && p > x0 && p < x1; const inVer = !reduced && anchors.threat !== null && p > v0 && p < v1;
      scanner.current.visible = inTest || inVer;
      if (inTest) { const u = (p - x0) / (x1 - x0) * 3; const tri = Math.abs(((u % 2) + 2) % 2 - 1); scanner.current.position.set(mix(-R * 2.2, R * 2.2, tri), 0, 0); }
      else if (inVer && anchors.threat) scanner.current.position.set(mix(-R * 2.2, anchors.threat[0], smoothstep((p - v0) / (v1 - v0) * 1.2)), 0, 0);
    }
    if (contain.current) { // containment ring around the suspicious tool, from threat until the backend says it is resolved
      const on = !reduced && anchors.threat !== null && p >= t0 && p < sec("risk")[0] + 0.02 && !(resolved && p >= sec("remediation")[0]);
      contain.current.visible = on; if (on) { contain.current.rotation.z = clock.elapsedTime * 0.5 * speed.current; contain.current.rotation.x = Math.PI / 2.4; }
    }
    if (ring.current) { // discovery sweep: scroll-tied expanding ring (explanatory, not a scan result)
      const local = reduced ? 0 : smoothstep((p - d0) / Math.max(1e-6, d1 - d0)); const on = !reduced && p > d0 && p < d1;
      ring.current.visible = on; ring.current.scale.setScalar(R * mix(0.2, 1.5, local)); (ring.current.material as THREE.MeshBasicMaterial).opacity = 0.55 * Math.sin(Math.PI * local);
    }
    if (pulse.current) { // threat pulse: expands once through the threat section
      const local = smoothstep((p - t0) / Math.max(1e-6, t1 - t0)); const on = !reduced && anchors.threat !== null && p > t0 && p < t1 + 0.01;
      pulse.current.visible = on; (pulse.current.material as THREE.MeshBasicMaterial).opacity = 0.7 * (1 - local);
      pulse.current.scale.setScalar(R * mix(0.03, 0.4, local));
    }
    if (light.current) { // travelling light along the analysed path, position = scroll
      const on = !reduced && anchors.path.length > 1 && p >= p0 && p <= p1 + 0.02;
      light.current.visible = on;
      if (on) { const q = alongPath(anchors.path, smoothstep((p - p0) / Math.max(1e-6, p1 - p0))); light.current.position.set(...q); }
    }
    invalidate();
  });

  const th = anchors.threat;
  return (
    <>
      <Environment R={R} speed={speed} animate={animate} pylons={quality.tier === "high" ? 48 : quality.tier === "medium" ? 24 : 0} />
      <Particles count={quality.tier === "high" ? 1100 : quality.tier === "medium" ? 550 : 220} R={R} />
      <group ref={core}><SecurityCore R={R} speed={speed} animate={animate} traceCount={quality.tier === "high" ? 40 : quality.tier === "medium" ? 24 : 12} /></group>
      {animate && <Streams lines={byKind.lines.tool} items={model.items} speed={speed} count={60} opacity={streamOp} size={R * 0.012} />}
      {animate && <Streams lines={byKind.lines.finding} items={model.items} speed={speed} count={30} opacity={findLineOp} reverse size={R * 0.012} />}
      <group ref={toolsRef}>
        <Instanced shape="sphere" ghost={false} items={byKind.items.tool} emphasis={hl.item} hidden={hl.hidden} theme={T} segments={quality.segments} animate={false} onHover={onHover} onSelect={onSelect} onDeep={onSelect} />
        <Lines lines={byKind.lines.tool} items={model.items} emphasis={hl.line} hidden={hl.hidden} theme={T} opacityRef={toolLineOp} />
      </group>
      <group ref={capsRef}>
        <Instanced shape="box" ghost={false} items={byKind.items.capability} emphasis={hl.item} hidden={hl.hidden} theme={T} segments={quality.segments} animate={false} onHover={onHover} onSelect={onSelect} onDeep={onSelect} />
      </group>
      <Lines lines={byKind.lines.capability} items={model.items} emphasis={hl.line} hidden={hl.hidden} theme={T} opacityRef={capLineOp} />
      <group ref={findRef}>
        <Instanced shape="octa" ghost={false} items={byKind.items.finding} emphasis={hl.item} hidden={hl.hidden} theme={T} segments={quality.segments} animate={false} onHover={onHover} onSelect={onSelect} onDeep={onSelect} />
      </group>
      <Lines lines={byKind.lines.finding} items={model.items} emphasis={hl.line} hidden={hl.hidden} theme={T} opacityRef={findLineOp} />
      <mesh ref={ring} rotation={[-Math.PI / 2, 0, 0]} visible={false}><ringGeometry args={[0.985, 1, 128]} /><meshBasicMaterial color={themeHex(T, "brand")} transparent opacity={0} side={THREE.DoubleSide} depthWrite={false} /></mesh>
      <group ref={scanner} visible={false}>
        <mesh rotation={[0, Math.PI / 2, 0]}><circleGeometry args={[R * 2.4, 64]} /><meshBasicMaterial color={themeHex(T, "brand")} transparent opacity={0.05} side={THREE.DoubleSide} depthWrite={false} /></mesh>
        <mesh rotation={[0, Math.PI / 2, 0]}><ringGeometry args={[R * 2.38, R * 2.4, 96]} /><meshBasicMaterial color={themeHex(T, "brand")} transparent opacity={0.6} side={THREE.DoubleSide} depthWrite={false} /></mesh>
      </group>
      {th && <mesh ref={contain} position={th} visible={false}><torusGeometry args={[R * 0.1, R * 0.003, 6, 64]} /><meshBasicMaterial color={themeHex(T, "critical")} transparent opacity={0.8} depthWrite={false} /></mesh>}
      {th && <mesh ref={pulse} position={th} visible={false}><sphereGeometry args={[1, 24, 16]} /><meshBasicMaterial color={themeHex(T, "critical")} wireframe transparent opacity={0} depthWrite={false} /></mesh>}
      {anchors.path.length > 1 && <line><primitive object={pathGeo} attach="geometry" /><lineBasicMaterial color={themeHex(T, "brand")} transparent opacity={0.9} /></line>}
      <mesh ref={light} visible={false}><sphereGeometry args={[R * 0.012, 12, 8]} /><meshBasicMaterial color="#ffffff" /></mesh>
    </>
  );
}

function ReadySignal({ onReady }: { onReady?: () => void }) {
  const done = useRef(false);
  useFrame(() => { if (!done.current) { done.current = true; onReady?.(); } });
  return null;
}

export default function StoryScene(p: Props) {
  const visible = usePageVisible();
  const bg = themeHex(T, "bg");
  const R = p.anchors.R;
  const closing = useRef(false); // unmounting forces a context loss; that is not a failure
  useEffect(() => { closing.current = false; return () => { closing.current = true; }; }, []);
  return (
    <Canvas
      frameloop={!visible ? "never" : p.quality.motion === "none" ? "demand" : "always"}
      dpr={p.quality.dpr} gl={{ antialias: p.quality.antialias, powerPreference: "high-performance", alpha: false }}
      camera={{ fov: 48, near: 0.1, far: R * 40, position: [R, R, R * 2.6] }}
      onCreated={({ gl }) => { gl.setClearColor(new THREE.Color(bg)); gl.domElement.setAttribute("aria-hidden", "true"); gl.domElement.addEventListener("webglcontextlost", (e) => { e.preventDefault(); if (gl.domElement.isConnected && !closing.current) p.onContextLost(); }); }}
    >
      <color attach="background" args={[bg]} />
      <fog attach="fog" args={[bg, R * 3.5, R * 9]} />
      <ambientLight intensity={0.55} />
      <directionalLight position={[R, R * 1.6, R]} intensity={1.15} />
      <pointLight position={[-R * 1.4, R * 0.3, -R * 1.2]} intensity={R * 1.4} distance={R * 8} color={themeHex(T, "brand")} />
      <ScrollCamera anchors={p.anchors} motion={p.quality.motion} />
      <World {...p} />
      <ReadySignal onReady={p.onReady} />
    </Canvas>
  );
}
export { SECTION_INDEX };
