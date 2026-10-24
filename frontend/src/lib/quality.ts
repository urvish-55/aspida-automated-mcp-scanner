import type { EffectsPref, QualityPref } from "../types/visualization";

export interface QualityEnv { cores: number; dpr: number; prefersReducedMotion: boolean }
export interface QualitySettings {
  tier: "low" | "medium" | "high";
  dpr: number;
  antialias: boolean;
  labelBudget: number;
  segments: number;
  /** none = no animation at all (instant camera, no pulses); reduced = short glides; full = glides + pulses + floor grid. */
  motion: "none" | "reduced" | "full";
  grid: boolean;
}

export function resolveQuality(pref: QualityPref, nodeCount: number, effects: EffectsPref, env: QualityEnv): QualitySettings {
  let tier: QualitySettings["tier"];
  if (pref !== "auto") tier = pref;
  else if (nodeCount > 400 || env.cores <= 2) tier = "low";
  else if (nodeCount > 150 || env.cores <= 4) tier = "medium";
  else tier = "high";
  const dprCap = tier === "low" ? 1 : tier === "medium" ? 1.5 : 2;
  const motion: QualitySettings["motion"] = env.prefersReducedMotion || effects === "off" ? "none" : effects === "reduced" ? "reduced" : "full";
  return {
    tier,
    dpr: Math.max(1, Math.min(env.dpr, dprCap)),
    antialias: tier !== "low",
    labelBudget: tier === "low" ? 8 : tier === "medium" ? 20 : 40,
    segments: tier === "low" ? 8 : tier === "medium" ? 14 : 22,
    motion,
    grid: motion === "full" && tier !== "low",
  };
}
