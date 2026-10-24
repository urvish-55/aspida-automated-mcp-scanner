import { describe, expect, it } from "vitest";
import { resolveQuality } from "./quality";
import { hasHiddenChars, safeLabel } from "./safeText";

const env = { cores: 8, dpr: 2, prefersReducedMotion: false };
describe("quality", () => {
  it("auto lowers quality as node count grows (10/100/500)", () => {
    expect(resolveQuality("auto", 10, "full", env).tier).toBe("high");
    expect(resolveQuality("auto", 200, "full", env).tier).toBe("medium");
    expect(resolveQuality("auto", 500, "full", env).tier).toBe("low");
  });
  it("explicit tier wins and caps device pixel ratio", () => {
    const q = resolveQuality("low", 10, "full", env);
    expect(q).toMatchObject({ tier: "low", dpr: 1, antialias: false, labelBudget: 8 });
    expect(resolveQuality("high", 10, "full", env).dpr).toBe(2);
  });
  it("prefers-reduced-motion disables motion regardless of the effects setting", () => {
    expect(resolveQuality("high", 10, "full", { ...env, prefersReducedMotion: true }).motion).toBe("none");
    expect(resolveQuality("high", 10, "off", env).motion).toBe("none");
    expect(resolveQuality("high", 10, "reduced", env).motion).toBe("reduced");
    expect(resolveQuality("high", 10, "reduced", env).grid).toBe(false);
  });
});
describe("safeLabel", () => {
  it("makes bidi / zero-width characters visible", () => {
    expect(safeLabel("read‮file​")).toBe("read⟦U+202E⟧file⟦U+200B⟧");
    expect(hasHiddenChars("a​b")).toBe(true);
    expect(hasHiddenChars("plain")).toBe(false);
  });
  it("truncates and flattens whitespace", () => {
    expect(safeLabel("a\n\n b".repeat(1))).toBe("a b");
    expect(safeLabel("x".repeat(200), 20)).toHaveLength(20);
  });
  it("leaves markup as inert text", () => {
    expect(safeLabel("<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
  });
});

import { hslToHex, SEV_COLORS_DARK } from "./severity";
describe("severity colours", () => {
  it("convert the CSS tokens to hex", () => {
    expect(hslToHex([0, 0, 100])).toBe("#ffffff");
    expect(hslToHex([0, 100, 50])).toBe("#ff0000");
    expect(SEV_COLORS_DARK.critical).toMatch(/^#[0-9a-f]{6}$/);
  });
});
