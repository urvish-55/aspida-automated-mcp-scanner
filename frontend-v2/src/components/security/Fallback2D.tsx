import { useMemo } from "react";
import { computeHighlight } from "../../lib/highlight";
import type { SceneModel } from "../../lib/sceneModel";
import { SEV_GLYPH, SEV_LABEL, themeHex, type Theme } from "../../lib/severity";
import { baseColor } from "../3d/colors";
import { useInvestigation } from "../../state/investigation";

const W = 900;
const H = 620;

/** Full 2D rendering of any scene model (top-down projection). Used when WebGL is unavailable, on small screens, or when chosen. */
export function Fallback2D({ model, theme, markedIds, reason }: { model: SceneModel; theme: Theme; markedIds?: ReadonlySet<string>; reason?: string }) {
  const st = useInvestigation();
  const hl = useMemo(() => computeHighlight(model, { selectedId: st.selectedId, hoveredId: st.hoveredId, activePathId: st.activePathId, isolateId: st.isolateId, markedIds }), [model, st.selectedId, st.hoveredId, st.activePathId, st.isolateId, markedIds]);
  const proj = useMemo(() => {
    let maxX = 1; let maxZ = 1;
    for (const i of model.items) { maxX = Math.max(maxX, Math.abs(i.pos[0]) + i.scale[0]); maxZ = Math.max(maxZ, Math.abs(i.pos[2]) + i.scale[2]); }
    const k = Math.min((W / 2 - 60) / maxX, (H / 2 - 50) / maxZ);
    return (p: readonly [number, number, number]) => [W / 2 + p[0] * k, H / 2 + p[2] * k + (model.mode === "graph" || model.mode === "capabilities" ? -p[1] * k * 0.35 : 0)] as const;
  }, [model]);
  const byId = useMemo(() => new Map(model.items.map((i) => [i.id, i])), [model]);
  const dimOpacity = (e?: string) => (e === "dim" ? 0.18 : 1);
  const bg = themeHex(theme, "line");

  return (
    <div className="relative h-full w-full overflow-hidden">
      {reason && <p className="absolute left-3 top-3 z-10 max-w-[80%] rounded border border-line bg-panel/90 px-2 py-1 text-[11.5px] text-dim" role="status">{reason}</p>}
      <svg viewBox={`0 0 ${W} ${H}`} className="h-full w-full" role="group" aria-label={`2D ${model.mode} view. The same objects are listed as text below.`} preserveAspectRatio="xMidYMid meet">
        {model.lines.map((l) => {
          const a = byId.get(l.a); const b = byId.get(l.b);
          if (!a || !b || hl.hidden.has(l.a) || hl.hidden.has(l.b)) return null;
          const [x1, y1] = proj(a.pos); const [x2, y2] = proj(b.pos);
          const e = hl.line.get(l.id);
          return <line key={l.id} x1={x1} y1={y1} x2={x2} y2={y2} stroke={l.kind === "path" ? themeHex(theme, "brand") : l.kind === "combo" ? themeHex(theme, "high") : bg} strokeWidth={e === "related" ? 2 : 1} strokeDasharray={l.dashed ? "5 4" : undefined} opacity={e === "dim" ? 0.15 : 0.8} />;
        })}
        {model.items.map((i) => {
          if (hl.hidden.has(i.id)) return null;
          const [x, y] = proj(i.pos);
          const e = hl.item.get(i.id);
          const fill = baseColor(i, theme);
          const r = Math.max(5, i.scale[0] * 7);
          const sel = st.selectedId === i.id;
          const common = { fill: i.ghost ? "none" : fill, stroke: sel ? themeHex(theme, "brand") : i.ghost ? fill : "none", strokeWidth: sel ? 3 : 2, strokeDasharray: i.ghost ? "3 2" : undefined, opacity: dimOpacity(e) };
          return (
            <g key={i.id} role="button" tabIndex={0} aria-label={`${i.label}, ${i.kind}${i.level !== "none" ? `, ${SEV_LABEL[i.level]} severity` : ""}`} aria-pressed={sel}
              className="cursor-pointer outline-none focus-visible:[&>*:first-child]:stroke-[3px]"
              onClick={() => st.select(i.id)} onDoubleClick={() => { st.isolate(i.id); st.focus(i.id); }}
              onKeyDown={(ev) => { if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); st.select(i.id); } }}
              onMouseEnter={() => st.hover(i.id)} onMouseLeave={() => st.hover(null)} onFocus={() => st.hover(i.id)} onBlur={() => st.hover(null)}>
              {i.shape === "bar" ? <rect x={x - 22} y={y - 14} width={44} height={28} rx={4} {...common} />
                : i.shape === "box" ? <rect x={x - r} y={y - r} width={r * 2} height={r * 2} rx={3} {...common} />
                : i.shape === "octa" ? <polygon points={`${x},${y - r * 1.2} ${x + r * 1.2},${y} ${x},${y + r * 1.2} ${x - r * 1.2},${y}`} {...common} />
                : i.shape === "ring" ? <circle cx={x} cy={y} r={r} {...common} fill="none" stroke={fill} strokeDasharray="3 2" />
                : <circle cx={x} cy={y} r={r} {...common} />}
              {i.level !== "none" && i.shape !== "bar" && <text x={x} y={y + 3.5} textAnchor="middle" fontSize={9} fontWeight={700} fill={theme === "dark" ? "#0b0f17" : "#fff"} opacity={dimOpacity(e)} aria-hidden>{SEV_GLYPH[i.level]}</text>}
              {i.shape === "bar" && <text x={x} y={y + 4} textAnchor="middle" fontSize={11} fontWeight={700} fill={theme === "dark" ? "#0b0f17" : "#fff"} aria-hidden>{i.label.split(": ")[1]?.replace(" pts", "")}</text>}
              {(i.labelPriority >= 50 || sel || e === "focus" || e === "related") && i.shape !== "bar" && e !== "dim" && (
                <text x={x} y={y - r - 4} textAnchor="middle" fontSize={10.5} className="fill-fg" style={{ paintOrder: "stroke", stroke: themeHex(theme, "bg"), strokeWidth: 3 }}>{i.label.length > 28 ? `${i.label.slice(0, 27)}…` : i.label}</text>
              )}
            </g>
          );
        })}
        {model.labels.map((l) => { const [x, y] = proj(l.pos); return <text key={l.id} x={x} y={y} textAnchor="middle" fontSize={11} className="fill-dim">{l.text}</text>; })}
      </svg>
      {model.empty && <div className="absolute inset-0 grid place-items-center p-6 text-center text-dim">{model.empty}</div>}
    </div>
  );
}
