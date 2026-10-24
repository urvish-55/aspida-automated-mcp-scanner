import { invalidate, useFrame, type ThreeEvent } from "@react-three/fiber";
import { useEffect, useLayoutEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import type { Emphasis } from "../../lib/highlight";
import type { SceneItem, Shape } from "../../lib/sceneModel";
import type { Theme } from "../../lib/severity";
import { baseColor } from "./colors";
import { emphasisColor } from "./emphasis";

interface Props {
  shape: Shape; ghost: boolean; items: SceneItem[]; emphasis: Map<string, Emphasis>; hidden: Set<string>;
  theme: Theme; segments: number; animate: boolean;
  onHover: (id: string | null) => void; onSelect: (id: string) => void; onDeep: (id: string) => void;
}

function makeGeometry(shape: Shape, seg: number): THREE.BufferGeometry {
  switch (shape) {
    case "sphere": return new THREE.SphereGeometry(1, seg, Math.max(6, Math.round(seg * 0.7)));
    case "octa": return new THREE.OctahedronGeometry(1.15);
    case "ico": return new THREE.IcosahedronGeometry(1, 1);
    case "ring": return new THREE.TorusGeometry(1, 0.16, 8, Math.max(16, seg * 2));
    default: return new THREE.BoxGeometry(1, 1, 1);
  }
}

const m4 = new THREE.Matrix4();
const q0 = new THREE.Quaternion();
const v = new THREE.Vector3();
const s = new THREE.Vector3();
const col = new THREE.Color();

export function Instanced({ shape, ghost, items, emphasis, hidden, theme, segments, animate, onHover, onSelect, onDeep }: Props) {
  const ref = useRef<THREE.InstancedMesh>(null);
  const geometry = useMemo(() => makeGeometry(shape, segments), [shape, segments]);
  const material = useMemo(() => new THREE.MeshStandardMaterial({
    color: "#ffffff", roughness: 0.55, metalness: 0.08, flatShading: shape === "octa" || shape === "ico",
    transparent: ghost, opacity: ghost ? 0.42 : 1, depthWrite: !ghost, wireframe: ghost && shape !== "ring",
  }), [shape, ghost]);
  useEffect(() => () => { geometry.dispose(); }, [geometry]);
  useEffect(() => () => { material.dispose(); }, [material]);

  const write = (i: number, time: number) => {
    const mesh = ref.current; if (!mesh) return;
    const it = items[i];
    const e = emphasis.get(it.id) ?? "normal";
    const k = hidden.has(it.id) ? 0.0001 : e === "focus" ? 1.25 : 1;
    const pulse = animate && it.pulse ? 1 + 0.18 * Math.sin(time * 3) : 1;
    v.set(...it.pos);
    s.set(it.scale[0] * k * pulse, it.scale[1] * k * pulse, it.scale[2] * k * pulse);
    if (it.shape === "ring") q0.setFromEuler(new THREE.Euler(Math.PI / 2, 0, 0)); else q0.identity();
    m4.compose(v, q0, s);
    mesh.setMatrixAt(i, m4);
  };

  useLayoutEffect(() => {
    const mesh = ref.current; if (!mesh) return;
    for (let i = 0; i < items.length; i++) {
      write(i, 0);
      mesh.setColorAt(i, emphasisColor(baseColor(items[i], theme), emphasis.get(items[i].id) ?? "normal", theme, col));
    }
    mesh.instanceMatrix.needsUpdate = true;
    if (mesh.instanceColor) mesh.instanceColor.needsUpdate = true;
    mesh.computeBoundingSphere();
    invalidate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, emphasis, hidden, theme, geometry]);

  const hasPulse = useMemo(() => items.some((i) => i.pulse), [items]);
  useFrame(({ clock }) => {
    if (!animate || !hasPulse || !ref.current) return;
    items.forEach((it, i) => { if (it.pulse) write(i, clock.elapsedTime); });
    ref.current.instanceMatrix.needsUpdate = true;
    invalidate();
  });

  if (items.length === 0) return null;
  const id = (e: ThreeEvent<unknown>) => { const i = e.instanceId; return i == null ? null : items[i]?.id ?? null; };
  return (
    <instancedMesh
      key={`${shape}-${ghost}-${items.length}`}
      ref={ref}
      args={[geometry, material, items.length]}
      onPointerMove={(e) => { e.stopPropagation(); const x = id(e); if (x && !hidden.has(x)) { onHover(x); document.body.style.cursor = "pointer"; } }}
      onPointerOut={() => { onHover(null); document.body.style.cursor = ""; }}
      onClick={(e) => { e.stopPropagation(); const x = id(e); if (x && !hidden.has(x)) onSelect(x); }}
      onDoubleClick={(e) => { e.stopPropagation(); const x = id(e); if (x && !hidden.has(x)) onDeep(x); }}
    />
  );
}
