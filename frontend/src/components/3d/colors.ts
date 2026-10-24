import { sevColor, themeHex, type Theme } from "../../lib/severity";
import type { SceneItem } from "../../lib/sceneModel";

export function baseColor(item: SceneItem, theme: Theme): string {
  if (item.level !== "none") return sevColor(item.level, theme);
  if (item.kind === "server") return themeHex(theme, "server");
  if (item.kind === "capability") return themeHex(theme, "cap");
  if (item.kind === "stage") return item.stageState === "done" ? themeHex(theme, "brand") : item.stageState === "active" ? themeHex(theme, "high") : themeHex(theme, "none");
  return themeHex(theme, "none");
}
