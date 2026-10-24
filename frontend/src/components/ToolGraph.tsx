import { useMemo, useState } from "react";
import { cn, SEV_HEX_VAR } from "../lib/utils";
import type { GraphEdge, GraphNode } from "../types";

const W = 760;
const H = 560;
const CX = W / 2;
const CY = H / 2;
const MAX_TOOLS = 60;

const capW = (label: string) => Math.max(68, label.length * 6.4 + 18);

interface Placed extends GraphNode { x: number; y: number }

function layout(nodes: GraphNode[], edges: GraphEdge[]): { placed: Placed[]; hidden: number } {
  const server = nodes.find((n) => n.kind === "server");
  const toolsAll = nodes.filter((n) => n.kind === "tool");
  const tools = toolsAll.slice(0, MAX_TOOLS);
  const caps = nodes.filter((n) => n.kind === "capability");
  const placed: Placed[] = [];
  if (server) placed.push({ ...server, x: CX, y: CY });
  const r1 = tools.length > 14 ? 150 : 130;
  const angleOf = new Map<string, number>();
  tools.forEach((t, i) => {
    const a = (i / Math.max(1, tools.length)) * Math.PI * 2 - Math.PI / 2;
    angleOf.set(t.id, a);
    placed.push({ ...t, x: CX + Math.cos(a) * r1, y: CY + Math.sin(a) * r1 });
  });
  // capabilities: outer ring at the circular mean angle of their tools, then spread apart
  const capAngles = caps.map((c) => {
    const ts = edges.filter((e) => e.target === c.id && angleOf.has(e.source)).map((e) => angleOf.get(e.source) as number);
    if (!ts.length) return { c, a: 0 };
    const sx = ts.reduce((s, a) => s + Math.cos(a), 0);
    const sy = ts.reduce((s, a) => s + Math.sin(a), 0);
    return { c, a: Math.atan2(sy, sx) };
  }).sort((p, q) => p.a - q.a);
  const minGap = (Math.PI * 2) / Math.max(8, capAngles.length * 1.4);
  for (let i = 1; i < capAngles.length; i++) if (capAngles[i].a - capAngles[i - 1].a < minGap) capAngles[i].a = capAngles[i - 1].a + minGap;
  const r2 = 235;
  capAngles.forEach(({ c, a }) => placed.push({ ...c, x: CX + Math.cos(a) * r2 * 1.35, y: CY + Math.sin(a) * r2 }));
  return { placed, hidden: toolsAll.length - tools.length };
}

export function ToolGraph({ nodes, edges, selected, onSelect }: { nodes: GraphNode[]; edges: GraphEdge[]; selected: string | null; onSelect: (id: string) => void }) {
  const { placed, hidden } = useMemo(() => layout(nodes, edges), [nodes, edges]);
  const pos = useMemo(() => new Map(placed.map((p) => [p.id, p])), [placed]);
  const [hover, setHover] = useState<string | null>(null);
  const focus = hover ?? selected;
  const linked = useMemo(() => {
    const s = new Set<string>();
    if (focus) { s.add(focus); edges.forEach((e) => { if (e.source === focus) s.add(e.target); if (e.target === focus) s.add(e.source); }); }
    return s;
  }, [focus, edges]);

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${W} ${H}`} className="h-auto w-full" role="group" aria-label="MCP tool and capability graph">
        {edges.map((e, i) => {
          const a = pos.get(e.source); const b = pos.get(e.target);
          if (!a || !b) return null;
          const on = !focus || (linked.has(e.source) && linked.has(e.target));
          return (
            <g key={i} opacity={on ? 1 : 0.12}>
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="hsl(var(--dim))" strokeWidth={e.verb === "invokes" ? 1 : 1.4} strokeDasharray={e.verb === "invokes" ? "3 4" : undefined} opacity={0.55} />
              {focus && on && e.source !== "server" && <text x={(a.x + b.x) / 2} y={(a.y + b.y) / 2 - 3} textAnchor="middle" className="fill-dim" fontSize={9}>{e.verb}</text>}
            </g>
          );
        })}
        {placed.map((n) => {
          const color = n.kind === "capability" ? SEV_HEX_VAR[n.level] ?? "hsl(var(--dim))" : n.kind === "server" ? "hsl(var(--brand))" : SEV_HEX_VAR[n.level] ?? SEV_HEX_VAR.none;
          const on = !focus || linked.has(n.id);
          const sel = selected === n.id;
          return (
            <g key={n.id} transform={`translate(${n.x},${n.y})`} opacity={on ? 1 : 0.2} tabIndex={0} role="button" aria-label={`${n.kind} ${n.label}${n.finding_count ? `, ${n.finding_count} findings` : ""}`}
              className="cursor-pointer outline-none" onClick={() => onSelect(n.id)} onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onSelect(n.id); } }}
              onMouseEnter={() => setHover(n.id)} onMouseLeave={() => setHover(null)} onFocus={() => setHover(n.id)} onBlur={() => setHover(null)}>
              {n.kind === "server" && <polygon points="0,-26 23,-13 23,13 0,26 -23,13 -23,-13" fill="hsl(var(--panel))" stroke={color} strokeWidth={sel ? 3 : 2} />}
              {n.kind === "tool" && <circle r={sel ? 17 : 14} fill="hsl(var(--panel))" stroke={color} strokeWidth={sel ? 3.5 : 2.2} />}
              {n.kind === "capability" && <rect x={-(capW(n.label) / 2)} y={-12} width={capW(n.label)} height={24} rx={6} fill="hsl(var(--raised))" stroke={color} strokeWidth={sel ? 3 : 1.6} strokeDasharray={n.level === "none" ? "3 3" : undefined} />}
              {n.kind === "tool" && (n.finding_count ?? 0) > 0 && <text textAnchor="middle" dy="4" fontSize={11} fontWeight={700} fill={color}>{n.finding_count}</text>}
              {n.kind === "server" && <text textAnchor="middle" dy="4" fontSize={10} fontWeight={700} className="fill-brand">MCP</text>}
              <text textAnchor="middle" dy={n.kind === "capability" ? 4 : n.kind === "server" ? 42 : 30} fontSize={n.kind === "capability" ? 10 : 10.5} className={cn(n.kind === "capability" ? "fill-fg" : "fill-fg")}>
                {n.label.length > 22 ? `${n.label.slice(0, 21)}…` : n.label}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11.5px] text-dim">
        <span><svg width="14" height="14" className="inline"><polygon points="7,1 13,4 13,10 7,13 1,10 1,4" fill="none" stroke="hsl(var(--brand))" strokeWidth="1.5" /></svg> server</span>
        <span><svg width="14" height="14" className="inline"><circle cx="7" cy="7" r="5" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg> tool (ring colour = highest finding severity, number = findings)</span>
        <span><svg width="16" height="14" className="inline"><rect x="1" y="3" width="14" height="8" rx="2" fill="none" stroke="currentColor" strokeWidth="1.5" /></svg> capability</span>
        {hidden > 0 && <span className="text-warn">{hidden} more tools not drawn (showing {MAX_TOOLS})</span>}
      </div>
    </div>
  );
}
