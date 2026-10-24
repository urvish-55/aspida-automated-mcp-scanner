import { useQuery } from "@tanstack/react-query";
import {
  BarChart3, Box, Brain, FileText, GitCompare, HeartPulse, LayoutDashboard, LogOut, Moon, PlayCircle, Search, Settings, ShieldAlert, Wrench,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ElementType } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api } from "../services/api";
import { usePrefs } from "../state/prefs";
import { cn } from "../lib/utils";
import { Modal, SeverityBadge } from "./ui";

interface Item { id: string; group: string; label: string; hint?: string; icon: ElementType; run: () => void; badge?: string }

function useDebounced<T>(v: T, ms: number): T {
  const [d, setD] = useState(v);
  useEffect(() => { const t = setTimeout(() => setD(v), ms); return () => clearTimeout(t); }, [v, ms]);
  return d;
}

export function CommandPalette({ open, onOpenChange, onSignOut }: { open: boolean; onOpenChange: (o: boolean) => void; onSignOut?: () => void }) {
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const nav = useNavigate();
  const onCommand = useLocation().pathname === "/command";
  const { toggleTheme, setScanId } = usePrefs();
  const dq = useDebounced(q.trim(), 200);
  const list = useRef<HTMLUListElement>(null);

  useEffect(() => { if (open) { setQ(""); setIdx(0); } }, [open]);

  const results = useQuery({ queryKey: ["search", dq], queryFn: () => api.search(dq), enabled: open && dq.length >= 2 });

  const go = (to: string) => () => { onOpenChange(false); nav(to); };
  const commands: Item[] = useMemo(() => [
    { id: "c-new", group: "Commands", label: "New Scan", icon: PlayCircle, run: go("/scan") },
    { id: "c-dash", group: "Commands", label: "Open Dashboard", icon: LayoutDashboard, run: go("/") },
    { id: "c-crit", group: "Commands", label: "View Critical Findings", icon: ShieldAlert, run: go("/findings?severity=critical") },
    { id: "c-tools", group: "Commands", label: "Open Tools", icon: Wrench, run: go("/tools") },
    { id: "c-cmp", group: "Commands", label: "Compare Scans", icon: GitCompare, run: go("/compare") },
    { id: "c-rep", group: "Commands", label: "Generate Report", icon: FileText, run: go("/reports") },
    { id: "c-3d", group: "Commands", label: "Open 3D Command Center", icon: Box, run: go("/command") },
    { id: "c-risk", group: "Commands", label: "Open Risk Analysis", icon: BarChart3, run: go("/risk") },
    { id: "c-ml", group: "Commands", label: "Open ML Analysis", icon: Brain, run: go("/ml") },
    { id: "c-health", group: "Commands", label: "Open System Health", icon: HeartPulse, run: go("/health") },
    { id: "c-theme", group: "Commands", label: "Toggle Theme", icon: Moon, run: () => { toggleTheme(); onOpenChange(false); } },
    { id: "c-set", group: "Commands", label: "Open Settings", icon: Settings, run: go("/settings") },
    ...(onSignOut ? [{ id: "c-out", group: "Commands", label: "Sign out", icon: LogOut, run: () => { onOpenChange(false); onSignOut(); } }] : []),
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], [onSignOut]);

  const items: Item[] = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const cmds = commands.filter((c) => !needle || c.label.toLowerCase().includes(needle));
    const r = results.data;
    const dyn: Item[] = [];
    if (r && dq.length >= 2) {
      r.tools.items.forEach((t) => dyn.push({ id: `t-${t.name}`, group: `Tools (${r.tools.total})`, label: t.name, hint: t.capabilities.join(", "), icon: Wrench, run: () => { setScanId(t.scan_id); if (onCommand) go(`/command?scan=${t.scan_id}&focus=${encodeURIComponent(`tool:${t.name}`)}`)(); else go(`/tools?tool=${encodeURIComponent(t.name)}`)(); } }));
      r.findings.items.forEach((f) => dyn.push({ id: `f-${f.id}`, group: `Findings (${r.findings.total})`, label: f.title, hint: f.tools.join(", "), icon: ShieldAlert, badge: f.severity, run: onCommand ? go(`/command?scan=${f.scan_id}&focus=${encodeURIComponent(`finding:${f.id}`)}`) : go(`/findings?scan=${f.scan_id}&open=${f.id}`) }));
      r.scans.items.forEach((s) => dyn.push({ id: `s-${s.id}`, group: `Scans (${r.scans.total})`, label: s.label || s.id, hint: `${s.id.slice(0, 8)} · ${s.status}`, icon: PlayCircle, run: go(`/scans/${s.id}`) }));
      r.reports.items.forEach((s) => dyn.push({ id: `r-${s.scan_id}`, group: `Reports (${r.reports.total})`, label: `Report: ${s.label || s.scan_id}`, icon: FileText, run: () => { setScanId(s.scan_id); go("/reports")(); } }));
    }
    return [...dyn, ...cmds];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q, commands, results.data, dq, onCommand]);

  useEffect(() => { setIdx(0); }, [q, results.data]);
  useEffect(() => { list.current?.querySelector(`[data-idx="${idx}"]`)?.scrollIntoView({ block: "nearest" }); }, [idx]);

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setIdx((i) => Math.min(items.length - 1, i + 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setIdx((i) => Math.max(0, i - 1)); }
    else if (e.key === "Enter") { e.preventDefault(); items[idx]?.run(); }
  };

  let lastGroup = "";
  return (
    <Modal open={open} onOpenChange={onOpenChange} title="Command palette">
      <div role="combobox" aria-expanded aria-haspopup="listbox" aria-controls="palette-list">
        <div className="flex items-center gap-2 border-b border-line px-4">
          <Search className="h-4 w-4 text-dim" aria-hidden />
          <input autoFocus value={q} onChange={(e) => setQ(e.target.value)} onKeyDown={onKey} aria-label="Search or run a command"
            aria-activedescendant={items[idx] ? `pal-${items[idx].id}` : undefined}
            placeholder="Search tools, findings, scans, reports, or run a command…" className="w-full bg-transparent py-3.5 text-[14px] outline-none placeholder:text-dim" />
          <span className="kbd">Esc</span>
        </div>
        <ul id="palette-list" role="listbox" ref={list} className="max-h-[52vh] overflow-y-auto p-2">
          {dq.length >= 2 && results.isFetching && <li className="px-3 py-2 text-[12px] text-dim">Searching…</li>}
          {items.length === 0 && <li className="px-3 py-8 text-center text-dim">No matches for “{q}”.</li>}
          {items.map((it, i) => {
            const header = it.group !== lastGroup ? it.group : null;
            lastGroup = it.group;
            return (
              <li key={it.id} role="presentation">
                {header && <div className="label px-3 pb-1 pt-2.5">{header}</div>}
                <button id={`pal-${it.id}`} role="option" aria-selected={i === idx} data-idx={i} onMouseMove={() => setIdx(i)} onClick={it.run}
                  className={cn("flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left", i === idx ? "bg-brand/10 text-fg" : "text-dim")}>
                  <it.icon className="h-4 w-4 shrink-0" aria-hidden />
                  <span className="min-w-0 flex-1"><span className="block truncate text-fg">{it.label}</span>{it.hint && <span className="block truncate text-[11.5px]">{it.hint}</span>}</span>
                  {it.badge && <SeverityBadge severity={it.badge} />}
                </button>
              </li>
            );
          })}
        </ul>
        <div className="flex items-center gap-4 border-t border-line px-4 py-2 text-[11px] text-dim">
          <span><span className="kbd">↑↓</span> navigate</span><span><span className="kbd">Enter</span> select</span><span><span className="kbd">Ctrl K</span> toggle</span>
        </div>
      </div>
    </Modal>
  );
}
