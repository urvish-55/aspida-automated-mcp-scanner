import { useFrame } from "@react-three/fiber";
import { useEffect, useMemo, useRef } from "react";
import * as THREE from "three";
import { themeHex } from "../../lib/severity";

const T = "dark" as const;

/** Deterministic PRNG so the core looks the same on every load (and in tests). */
const rng = (seed: number) => () => { seed = (seed * 16807) % 2147483647; return seed / 2147483647; };

/** Circuit traces: stepped (Manhattan-style) paths over a sphere surface, subdivided so they hug the shell. */
export function buildTraces(count: number, radius: number): THREE.Vector3[][] {
  const r = rng(424242); const traces: THREE.Vector3[][] = [];
  const at = (th: number, ph: number) => new THREE.Vector3(radius * Math.sin(ph) * Math.cos(th), radius * Math.cos(ph), radius * Math.sin(ph) * Math.sin(th));
  for (let i = 0; i < count; i++) {
    let th = r() * Math.PI * 2; let ph = 0.35 + r() * (Math.PI - 0.7);
    const pts = [at(th, ph)];
    const steps = 3 + Math.floor(r() * 3);
    for (let s = 0; s < steps; s++) {
      const alongTheta = s % 2 === 0; const d = (0.18 + r() * 0.35) * (r() < 0.5 ? -1 : 1);
      for (let k = 1; k <= 6; k++) {
        const t = k / 6;
        pts.push(alongTheta ? at(th + d * t, ph) : at(th, Math.min(Math.PI - 0.2, Math.max(0.2, ph + d * t))));
      }
      if (alongTheta) th += d; else ph = Math.min(Math.PI - 0.2, Math.max(0.2, ph + d));
    }
    traces.push(pts);
  }
  return traces;
}

/**
 * MCP SECURITY CORE: a layered, procedural structure (glass shell, metallic frame, nucleus, scanning rings, circuit traces with
 * travelling pulses, base platform). Purely decorative geometry: it encodes no scan data. `speed` slows it in threat/evidence scenes.
 */
export function SecurityCore({ R, speed, animate, traceCount }: { R: number; speed: { current: number }; animate: boolean; traceCount: number }) {
  const rings = [useRef<THREE.Mesh>(null), useRef<THREE.Mesh>(null), useRef<THREE.Mesh>(null)];
  const frame = useRef<THREE.Mesh>(null); const shell = useRef<THREE.Mesh>(null); const ticks = useRef<THREE.InstancedMesh>(null);
  const pulses = useRef<THREE.Points>(null);
  const brand = themeHex(T, "brand");

  const traces = useMemo(() => buildTraces(traceCount, 0.82), [traceCount]);
  const traceGeo = useMemo(() => {
    const g = new THREE.BufferGeometry(); const v: number[] = [];
    for (const t of traces) for (let i = 0; i < t.length - 1; i++) v.push(t[i]!.x, t[i]!.y, t[i]!.z, t[i + 1]!.x, t[i + 1]!.y, t[i + 1]!.z);
    g.setAttribute("position", new THREE.Float32BufferAttribute(v, 3)); return g;
  }, [traces]);
  const shellEdges = useMemo(() => new THREE.EdgesGeometry(new THREE.IcosahedronGeometry(1, 1)), []);
  const pulseGeo = useMemo(() => { const g = new THREE.BufferGeometry(); g.setAttribute("position", new THREE.Float32BufferAttribute(new Float32Array(traces.length * 3), 3)); return g; }, [traces.length]);
  const state = useRef({ t: 0 });
  useEffect(() => () => { traceGeo.dispose(); shellEdges.dispose(); pulseGeo.dispose(); }, [traceGeo, shellEdges, pulseGeo]);

  // Tick marks around the middle ring, set once.
  useEffect(() => {
    const m = ticks.current; if (!m) return;
    const d = new THREE.Object3D(); const n = 72;
    for (let i = 0; i < n; i++) { const a = (i / n) * Math.PI * 2; d.position.set(Math.cos(a) * 1.32, 0, Math.sin(a) * 1.32); d.rotation.set(0, -a, 0); d.scale.set(1, 1, i % 6 === 0 ? 2.4 : 1); d.updateMatrix(); m.setMatrixAt(i, d.matrix); }
    m.instanceMatrix.needsUpdate = true;
  }, []);

  useFrame((_, dt) => {
    const s = animate ? speed.current : 0; state.current.t += dt * s;
    const t = state.current.t;
    rings[0]!.current && (rings[0]!.current!.rotation.z = t * 0.35);
    rings[1]!.current && (rings[1]!.current!.rotation.y = -t * 0.22);
    rings[2]!.current && (rings[2]!.current!.rotation.x = t * 0.16);
    if (frame.current) { frame.current.rotation.y = t * 0.12; frame.current.rotation.x = t * 0.07; }
    if (shell.current) shell.current.rotation.y = -t * 0.05;
    const pos = pulseGeo.getAttribute("position") as THREE.BufferAttribute;
    traces.forEach((tr, i) => {
      const u = ((t * 0.35 + i * 0.137) % 1 + 1) % 1; const f = u * (tr.length - 1); const k = Math.min(tr.length - 2, Math.floor(f)); const a = tr[k]!; const b = tr[k + 1]!; const w = f - k;
      pos.setXYZ(i, a.x + (b.x - a.x) * w, a.y + (b.y - a.y) * w, a.z + (b.z - a.z) * w);
    });
    pos.needsUpdate = true;
  });

  return (
    <group scale={R * 0.24} name="mcp-security-core">
      {/* glass shell + fine edge lines */}
      <mesh ref={shell}><icosahedronGeometry args={[1, 1]} /><meshStandardMaterial color="#12303a" metalness={0.6} roughness={0.2} transparent opacity={0.14} side={THREE.DoubleSide} depthWrite={false} /></mesh>
      <lineSegments geometry={shellEdges} scale={1.001}><lineBasicMaterial color={brand} transparent opacity={0.3} /></lineSegments>
      {/* metallic inner frame */}
      <mesh ref={frame} scale={0.58}><octahedronGeometry args={[1, 0]} /><meshStandardMaterial color="#9aa8b8" metalness={0.85} roughness={0.35} flatShading /></mesh>
      <mesh scale={0.3}><icosahedronGeometry args={[1, 1]} /><meshBasicMaterial color={brand} transparent opacity={0.85} /></mesh>
      {/* circuit traces + pulses */}
      <lineSegments geometry={traceGeo}><lineBasicMaterial color={brand} transparent opacity={0.45} /></lineSegments>
      <points ref={pulses} geometry={pulseGeo}><pointsMaterial color="#ffffff" size={0.009 * R} sizeAttenuation transparent opacity={0.9} depthWrite={false} /></points>
      {/* concentric scanning rings */}
      <mesh ref={rings[0]!} rotation={[Math.PI / 2, 0, 0]}><torusGeometry args={[1.18, 0.008, 6, 128]} /><meshBasicMaterial color={brand} transparent opacity={0.7} /></mesh>
      <mesh ref={rings[1]!} rotation={[Math.PI / 2.6, 0, 0.3]}><torusGeometry args={[1.32, 0.006, 6, 128]} /><meshBasicMaterial color="#9fb4c2" transparent opacity={0.45} /></mesh>
      <instancedMesh ref={ticks} args={[undefined, undefined, 72]} rotation={[Math.PI / 2.6, 0, 0.3]}><boxGeometry args={[0.012, 0.012, 0.035]} /><meshBasicMaterial color="#9fb4c2" transparent opacity={0.7} /></instancedMesh>
      <mesh ref={rings[2]!} rotation={[0.4, 0, Math.PI / 2]}><torusGeometry args={[1.48, 0.005, 6, 128]} /><meshBasicMaterial color={brand} transparent opacity={0.3} /></mesh>
      {/* base platform */}
      <group position={[0, -1.75, 0]}>
        {[1.6, 2.4, 3.4].map((r, i) => <mesh key={r} rotation={[-Math.PI / 2, 0, 0]}><ringGeometry args={[r - 0.012, r, 128]} /><meshBasicMaterial color={brand} transparent opacity={0.34 - i * 0.08} side={THREE.DoubleSide} /></mesh>)}
      </group>
    </group>
  );
}
