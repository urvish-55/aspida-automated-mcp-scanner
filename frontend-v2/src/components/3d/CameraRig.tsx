import { OrbitControls } from "@react-three/drei";
import { invalidate, useFrame, useThree } from "@react-three/fiber";
import { useEffect, useRef } from "react";
import * as THREE from "three";
import type { OrbitControls as OrbitControlsImpl } from "three-stdlib";
import type { Vec3 } from "../../lib/graphLayout";
import type { SceneItem } from "../../lib/sceneModel";
import { useInvestigation } from "../../state/investigation";

interface Move { fromPos: THREE.Vector3; toPos: THREE.Vector3; fromTarget: THREE.Vector3; toTarget: THREE.Vector3; t: number; dur: number }
const ease = (t: number) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);

export function homePosition(radius: number): Vec3 { return [radius * 0.45, radius * 1.0, radius * 2.1]; }

/**
 * Camera control: damped orbit, fly-to on focus, reset, and the attack-path tour.
 * motion "none" (prefers-reduced-motion or Effects: Off) jumps instantly instead of gliding.
 */
export function CameraRig({ items, radius, motion, frameKey }: { items: SceneItem[]; radius: number; motion: "none" | "reduced" | "full"; frameKey: string }) {
  const camera = useThree((s) => s.camera);
  const gl = useThree((s) => s.gl);
  const controls = useRef<OrbitControlsImpl>(null);
  const queue = useRef<Move[]>([]);
  const cur = useRef<Move | null>(null);
  const focusTick = useInvestigation((s) => s.focusTick);
  const resetTick = useInvestigation((s) => s.resetTick);
  const tourTick = useInvestigation((s) => s.tourTick);
  const itemsRef = useRef(items); itemsRef.current = items;

  const plan = (target: THREE.Vector3, dist: number, dur: number) => {
    const c = controls.current; if (!c) return;
    const dir = camera.position.clone().sub(c.target);
    if (dir.lengthSq() < 1e-6) dir.set(0.3, 0.6, 1);
    dir.normalize();
    const mv: Move = { fromPos: camera.position.clone(), toPos: target.clone().add(dir.multiplyScalar(dist)), fromTarget: c.target.clone(), toTarget: target.clone(), t: 0, dur };
    if (motion === "none") { camera.position.copy(mv.toPos); c.target.copy(mv.toTarget); c.update(); invalidate(); return; }
    queue.current.push(mv);
    invalidate();
  };
  const dur = (base: number) => (motion === "reduced" ? base * 0.4 : base);

  // initial / mode change framing
  useEffect(() => {
    const [x, y, z] = homePosition(radius);
    camera.position.set(x, y, z);
    controls.current?.target.set(0, 0, 0);
    controls.current?.update();
    queue.current = []; cur.current = null;
    invalidate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [frameKey, camera]);

  useEffect(() => { // fly to the focused node
    const id = useInvestigation.getState().focusId;
    if (!id || focusTick === 0) return;
    const it = itemsRef.current.find((i) => i.id === id);
    if (it) plan(new THREE.Vector3(...it.pos), Math.max(5, radius * 0.38), dur(0.85));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [focusTick]);

  useEffect(() => { // reset view
    if (resetTick === 0) return;
    queue.current = [];
    const [x, y, z] = homePosition(radius);
    const c = controls.current; if (!c) return;
    if (motion === "none") { camera.position.set(x, y, z); c.target.set(0, 0, 0); c.update(); invalidate(); return; }
    queue.current.push({ fromPos: camera.position.clone(), toPos: new THREE.Vector3(x, y, z), fromTarget: c.target.clone(), toTarget: new THREE.Vector3(), t: 0, dur: dur(0.8) });
    invalidate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resetTick]);

  useEffect(() => { // attack-path tour: visit each stage the backend returned, in order
    if (tourTick === 0) return;
    const pid = useInvestigation.getState().activePathId; if (!pid) return;
    const stops = itemsRef.current.filter((i) => i.pathIds.includes(pid)).sort((a, b) => a.pos[0] - b.pos[0]);
    if (stops.length === 0) return;
    if (motion === "none") {
      const centre = new THREE.Vector3(); stops.forEach((s) => centre.add(new THREE.Vector3(...s.pos))); centre.divideScalar(stops.length);
      plan(centre, Math.max(12, radius * 0.7), 0);
      return;
    }
    queue.current = [];
    stops.forEach((s) => plan(new THREE.Vector3(...s.pos), 9, dur(1.1)));
    const centre = new THREE.Vector3(); stops.forEach((s) => centre.add(new THREE.Vector3(...s.pos))); centre.divideScalar(stops.length);
    plan(centre, Math.max(16, radius * 1.6), dur(1.2)); // finish on the whole chain
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tourTick]);

  useFrame((_, dt) => {
    const c = controls.current; if (!c) return;
    if (!cur.current && queue.current.length) {
      const next = queue.current.shift() as Move;
      next.fromPos.copy(camera.position); next.fromTarget.copy(c.target); // chain from wherever we are
      cur.current = next;
    }
    const m = cur.current;
    if (m) {
      m.t = Math.min(1, m.t + dt / Math.max(0.01, m.dur));
      const k = ease(m.t);
      camera.position.lerpVectors(m.fromPos, m.toPos, k);
      c.target.lerpVectors(m.fromTarget, m.toTarget, k);
      c.update();
      if (m.t >= 1) cur.current = null;
      invalidate();
    }
  });

  useEffect(() => { // keyboard orbit/pan on the canvas element
    const el = gl.domElement;
    controls.current?.listenToKeyEvents(el);
  }, [gl]);

  return <OrbitControls ref={controls} makeDefault enableDamping={motion !== "none"} dampingFactor={0.09} minDistance={3} maxDistance={Math.max(60, radius * 5)} keyPanSpeed={18} />;
}
