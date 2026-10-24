import * as THREE from "three";
import type { Emphasis } from "../../lib/highlight";
import { themeHex, type Theme } from "../../lib/severity";

const tmp = new THREE.Color();
export function emphasisColor(hex: string, e: Emphasis, theme: Theme, out: THREE.Color): THREE.Color {
  out.set(hex);
  if (e === "dim") out.lerp(tmp.set(themeHex(theme, "bg")), 0.82);
  else if (e === "focus") out.lerp(tmp.set(theme === "dark" ? "#ffffff" : "#000000"), 0.22);
  return out;
}
