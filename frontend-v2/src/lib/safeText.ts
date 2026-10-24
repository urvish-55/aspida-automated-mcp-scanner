/**
 * MCP tool names, descriptions and finding titles are attacker-controlled. Before putting any of it in a 3D label,
 * make invisible and direction-changing characters visible instead of letting them reorder or hide text.
 */
const INVISIBLE = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f­؜᠎​-‏‪-‮⁠-⁤⁦-⁯﻿￹-￻]/g;

export function safeLabel(text: string, max = 90): string {
  const out = String(text ?? "").replace(INVISIBLE, (c) => `⟦U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}⟧`);
  const flat = out.replace(/\s+/g, " ").trim();
  return flat.length > max ? `${flat.slice(0, max - 1)}…` : flat;
}

export const hasHiddenChars = (text: string): boolean => { INVISIBLE.lastIndex = 0; return INVISIBLE.test(text); };
