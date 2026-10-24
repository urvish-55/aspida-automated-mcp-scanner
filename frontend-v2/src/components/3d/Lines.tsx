import { invalidate, useFrame } from "@react-three/fiber";
import { useEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import type { Emphasis } from "../../lib/highlight";
import type { SceneItem, SceneLine } from "../../lib/sceneModel";
import { themeHex, type Theme } from "../../lib/severity";

function build(lines: SceneLine[], items: Map<string, SceneItem>, emphasis: Map<string, Emphasis>, hidden: Set<string>, theme: Theme) {
  const pos: number[] = [];
  const colors: number[] = [];
  const c = new THREE.Color();
  const bg = new THREE.Color(themeHex(theme, "bg"));
  for (const l of lines) {
    const a = items.get(l.a); const b = items.get(l.b);
    if (!a || !b || hidden.has(l.a) || hidden.has(l.b)) continue;
    const e = emphasis.get(l.id) ?? "normal";
    const base = l.kind === "path" ? themeHex(theme, "brand") : l.kind === "combo" ? themeHex(theme, "high") : l.kind === "affects" ? themeHex(theme, "medium") : themeHex(theme, "none");
    c.set(base);
    if (e === "dim") c.lerp(bg, 0.88);
    else if (e === "normal") c.lerp(bg, l.kind === "path" || l.kind === "combo" ? 0.1 : 0.55);
    pos.push(...a.pos, ...b.pos);
    colors.push(c.r, c.g, c.b, c.r, c.g, c.b);
  }
  return { pos: new Float32Array(pos), colors: new Float32Array(colors) };
}

function Segments({ data, dashed, opacityRef }: { data: { pos: Float32Array; colors: Float32Array }; dashed: boolean; opacityRef?: { current: number } }) {
  const geo = useMemo(() => new THREE.BufferGeometry(), []);
  const ref = useRef<THREE.LineSegments>(null);
  useEffect(() => {
    geo.setAttribute("position", new THREE.BufferAttribute(data.pos, 3));
    geo.setAttribute("color", new THREE.BufferAttribute(data.colors, 3));
    geo.computeBoundingSphere();
    if (dashed) ref.current?.computeLineDistances();
    invalidate();
  }, [geo, data, dashed]);
  useEffect(() => () => geo.dispose(), [geo]);
  useFrame(() => {
    const o = opacityRef?.current;
    const r = ref.current; if (o === undefined || !r) return;
    r.visible = o > 0.01;
    (r.material as THREE.Material).opacity = o;
  });
  if (data.pos.length === 0) return null;
  const fade = opacityRef !== undefined;
  return (
    <lineSegments ref={ref} geometry={geo} frustumCulled={false}>
      {dashed ? <lineDashedMaterial vertexColors dashSize={0.7} gapSize={0.45} transparent={fade} /> : <lineBasicMaterial vertexColors transparent={fade} />}
    </lineSegments>
  );
}

export function Lines({ lines, items, emphasis, hidden, theme, opacityRef }: { lines: SceneLine[]; items: SceneItem[]; emphasis: Map<string, Emphasis>; hidden: Set<string>; theme: Theme; opacityRef?: { current: number } }) {
  const byId = useMemo(() => new Map(items.map((i) => [i.id, i])), [items]);
  const solid = useMemo(() => build(lines.filter((l) => !l.dashed), byId, emphasis, hidden, theme), [lines, byId, emphasis, hidden, theme]);
  const dashed = useMemo(() => build(lines.filter((l) => l.dashed), byId, emphasis, hidden, theme), [lines, byId, emphasis, hidden, theme]);
  return <><Segments data={solid} dashed={false} opacityRef={opacityRef} /><Segments data={dashed} dashed opacityRef={opacityRef} /></>;
}
