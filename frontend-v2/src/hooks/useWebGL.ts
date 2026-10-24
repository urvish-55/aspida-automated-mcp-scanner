import { useEffect, useState } from "react";

export function detectWebGL(): boolean {
  try {
    const c = document.createElement("canvas");
    return !!(c.getContext("webgl2") || c.getContext("webgl"));
  } catch { return false; }
}

export function useWebGLSupport(): boolean {
  const [ok] = useState(() => (typeof document === "undefined" ? false : detectWebGL()));
  return ok;
}

function useMedia(q: string): boolean {
  const [m, setM] = useState(() => typeof window !== "undefined" && window.matchMedia?.(q).matches === true);
  useEffect(() => {
    if (!window.matchMedia) return;
    const mq = window.matchMedia(q);
    const h = () => setM(mq.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, [q]);
  return m;
}
export const useReducedMotion = () => useMedia("(prefers-reduced-motion: reduce)");
export const useIsNarrow = () => useMedia("(max-width: 767px)");

export function usePageVisible(): boolean {
  const [v, setV] = useState(() => typeof document === "undefined" || document.visibilityState !== "hidden");
  useEffect(() => {
    const h = () => setV(document.visibilityState !== "hidden");
    document.addEventListener("visibilitychange", h);
    return () => document.removeEventListener("visibilitychange", h);
  }, []);
  return v;
}
