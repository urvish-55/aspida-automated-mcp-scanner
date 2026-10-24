import { useFrame } from "@react-three/fiber";
import { useEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import { themeHex } from "../../lib/severity";

const T = "dark" as const;
const rng = (seed: number) => () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };

/** Layered depth: far atmospheric structures, mid-ground infrastructure pylons. Decorative only; it carries no data. */
export function Environment({ R, speed, animate, pylons }: { R: number; speed: { current: number }; animate: boolean; pylons: number }) {
  const far = useRef<THREE.Group>(null); const inst = useRef<THREE.InstancedMesh>(null);
  const line = themeHex(T, "line");
  useEffect(() => {
    const m = inst.current; if (!m) return; const r = rng(777); const d = new THREE.Object3D();
    for (let i = 0; i < pylons; i++) {
      const a = r() * Math.PI * 2; const dist = R * (3 + r() * 2.8); const h = R * (0.3 + r() * 1.6);
      d.position.set(Math.cos(a) * dist, -R * 0.95 + h / 2, Math.sin(a) * dist); d.scale.set(R * 0.03, h, R * 0.03); d.rotation.set(0, r() * 3, 0); d.updateMatrix(); m.setMatrixAt(i, d.matrix);
    }
    m.instanceMatrix.needsUpdate = true;
  }, [R, pylons]);
  useFrame((_, dt) => { if (far.current && animate) far.current.rotation.y += dt * 0.012 * speed.current; });
  return (
    <>
      <group ref={far}>
        <mesh position={[R * 6, R * 1.2, -R * 5]} scale={R * 2.2}><octahedronGeometry args={[1, 0]} /><meshBasicMaterial color={line} wireframe transparent opacity={0.22} /></mesh>
        <mesh position={[-R * 7, -R * 0.4, -R * 4]} scale={R * 2.8} rotation={[0.6, 0.2, 0]}><torusGeometry args={[1, 0.01, 6, 96]} /><meshBasicMaterial color={line} transparent opacity={0.4} /></mesh>
        <mesh position={[-R * 2, R * 3, -R * 8]} scale={R * 3.4}><icosahedronGeometry args={[1, 1]} /><meshBasicMaterial color={line} wireframe transparent opacity={0.12} /></mesh>
      </group>
      {pylons > 0 && <instancedMesh ref={inst} args={[undefined, undefined, pylons]}><boxGeometry args={[1, 1, 1]} /><meshStandardMaterial color="#1b2636" metalness={0.8} roughness={0.5} /></instancedMesh>}
    </>
  );
}

/** Flowing light along structural connections (tool/capability/finding lines). Positions are updated on the CPU in one buffer. */
export function Streams({ lines, items, speed, count, opacity, reverse, size }: {
  lines: { a: string; b: string }[]; items: { id: string; pos: readonly [number, number, number] }[];
  speed: { current: number }; count: number; opacity: { current: number }; reverse?: boolean; size: number;
}) {
  const ref = useRef<THREE.Points>(null);
  const pairs = useMemo(() => {
    const by = new Map(items.map((i) => [i.id, i.pos])); const out: [readonly [number, number, number], readonly [number, number, number]][] = [];
    for (const l of lines) { const a = by.get(l.a); const b = by.get(l.b); if (a && b) out.push(reverse ? [b, a] : [a, b]); }
    return out.slice(0, count);
  }, [lines, items, count, reverse]);
  const geo = useMemo(() => { const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.Float32BufferAttribute(new Float32Array(Math.max(1, pairs.length) * 3), 3)); return g; }, [pairs.length]);
  const t = useRef(0);
  useEffect(() => () => geo.dispose(), [geo]);
  useFrame((_, dt) => {
    const p = ref.current; if (!p) return;
    p.visible = opacity.current > 0.3 && pairs.length > 0; if (!p.visible) return;
    t.current += dt * speed.current * 0.28;
    const pos = geo.getAttribute("position") as THREE.BufferAttribute;
    pairs.forEach(([a, b], i) => { const u = ((t.current + i * 0.173) % 1 + 1) % 1; pos.setXYZ(i, a[0] + (b[0] - a[0]) * u, a[1] + (b[1] - a[1]) * u, a[2] + (b[2] - a[2]) * u); });
    pos.needsUpdate = true;
  });
  return <points ref={ref} geometry={geo}><pointsMaterial color="#d8f7f0" size={size} sizeAttenuation transparent opacity={0.85} depthWrite={false} /></points>;
}
