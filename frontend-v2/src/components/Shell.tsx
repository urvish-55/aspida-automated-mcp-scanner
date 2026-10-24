import { AnimatePresence, motion } from "framer-motion";
import {
  Activity, BarChart3, Bell, Brain, ChevronsLeft, ChevronsRight, FileText, GitCompare, HeartPulse, History,
  Box, Info, Sparkles, LayoutDashboard, Menu, X, LogOut, Moon, Network, PlayCircle, Radar, Search, Settings, ShieldAlert, Sun, Wrench, Workflow, FileSearch, Lightbulb,
} from "lucide-react";
import { Suspense, useEffect, useMemo, useRef, useState, type ElementType, type KeyboardEvent } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { auth } from "../services/api";
import { usePrefs } from "../state/prefs";
import { useNotifications, useScans, useSystemHealth } from "../state/queries";
import { cn, timeAgo } from "../lib/utils";
import type { NotificationItem } from "../types";
import { CommandPalette } from "./CommandPalette";
import { ContextLoader, Tip, TooltipProvider } from "./ui";

interface NavItem { to: string; label: string; icon: ElementType; end?: boolean }
const NAV: { group: string | null; items: NavItem[] }[] = [
  { group: null, items: [
    { to: "/", label: "Home", icon: LayoutDashboard, end: true },
    { to: "/scan", label: "New scan", icon: PlayCircle },
    { to: "/history", label: "Scans", icon: History },
    { to: "/findings", label: "Findings", icon: ShieldAlert },
  ] },
  { group: "More", items: [
    { to: "/tools", label: "Tools", icon: Wrench },
    { to: "/attack-paths", label: "Attack paths", icon: Workflow },
    { to: "/risk", label: "Risk analysis", icon: BarChart3 },
    { to: "/ml", label: "ML advisory", icon: Brain },
    { to: "/reports", label: "Reports", icon: FileText },
    { to: "/compare", label: "Compare scans", icon: GitCompare },
  ] },
  { group: "Classic pages", items: [
    { to: "/active", label: "Active scans", icon: Radar },
    { to: "/command", label: "3D command center", icon: Box },
    { to: "/journey", label: "3D journey", icon: Sparkles },
    { to: "/insights", label: "Security insights", icon: Lightbulb },
    { to: "/evidence", label: "Evidence", icon: FileSearch },
    { to: "/unicode", label: "Unicode inspector", icon: Search },
  ] },
  { group: "System", items: [
    { to: "/settings", label: "Settings", icon: Settings },
    { to: "/health", label: "System health", icon: HeartPulse },
    { to: "/about", label: "About", icon: Info },
  ] },
];

const TITLES: Record<string, string> = Object.fromEntries(NAV.flatMap((g) => g.items.map((i) => [i.to, i.label])));

function useIsMobile(): boolean {
  const q = "(max-width: 767px)";
  const [m, setM] = useState(() => typeof window !== "undefined" && window.matchMedia(q).matches);
  useEffect(() => {
    const mq = window.matchMedia(q);
    const h = () => setM(mq.matches);
    mq.addEventListener("change", h);
    return () => mq.removeEventListener("change", h);
  }, []);
  return m;
}

function Sidebar({ version, mobile = false, onClose }: { version: string; mobile?: boolean; onClose?: () => void }) {
  const prefs = usePrefs();
  const collapsed = prefs.collapsed && !mobile;
  const toggleCollapsed = prefs.toggleCollapsed;
  const ref = useRef<HTMLElement>(null);

  // Arrow-key navigation between links (roving focus without trapping Tab).
  const onKey = (e: KeyboardEvent) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp" && e.key !== "Home" && e.key !== "End") return;
    const links = Array.from(ref.current?.querySelectorAll<HTMLAnchorElement>("a[href]") ?? []);
    if (!links.length) return;
    const i = links.indexOf(document.activeElement as HTMLAnchorElement);
    let next = i;
    if (e.key === "ArrowDown") next = Math.min(links.length - 1, i + 1);
    if (e.key === "ArrowUp") next = Math.max(0, i - 1);
    if (e.key === "Home") next = 0;
    if (e.key === "End") next = links.length - 1;
    e.preventDefault();
    links[next]?.focus();
  };

  return (
    <aside aria-label="Sidebar" className={cn("flex h-screen shrink-0 flex-col border-r border-line backdrop-blur transition-[width] duration-200", mobile ? "fixed inset-y-0 left-0 z-50 w-[260px] bg-panel" : "sticky top-0 z-30 bg-panel/90", !mobile && (collapsed ? "w-[64px]" : "w-[236px]"))}>
      <div className={cn("flex h-14 items-center gap-2.5 border-b border-line px-3", collapsed && "justify-center")}>
        <div className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-brand/50 bg-brand/10 text-brand shadow-glow" aria-hidden>
          <Network className="h-4 w-4" />
        </div>
        {!collapsed && (
          <div className="min-w-0 leading-tight">
            <div className="truncate text-[13.5px] font-semibold tracking-tight">Aspida</div>
            <div className="text-[10.5px] text-dim">v{version || "…"} · MCP security</div>
          </div>
        )}
        {mobile && <button className="btn-ghost ml-auto" onClick={onClose} aria-label="Close navigation"><X className="h-4 w-4" /></button>}
      </div>
      <nav ref={ref} onKeyDown={onKey} aria-label="Primary" className="flex-1 overflow-y-auto px-2 py-3">
        {NAV.map((g, gi) => (
          <div key={gi} className={cn(gi > 0 && "mt-4")}>
            {g.group && !collapsed && <div className="label mb-1.5 px-2">{g.group}</div>}
            {g.group && collapsed && gi > 0 && <div className="mx-2 mb-2 border-t border-line" />}
            <ul className="space-y-0.5">
              {g.items.map((it) => {
                const link = (
                  <NavLink
                    to={it.to}
                    end={it.end}
                    aria-label={it.label}
                    className={({ isActive }) =>
                      cn("group relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] transition",
                        collapsed && "justify-center px-0",
                        isActive ? "bg-brand/10 font-medium text-fg" : "text-dim hover:bg-raised hover:text-fg")
                    }
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && <motion.span layoutId="nav-active" className="absolute left-0 top-1.5 h-[calc(100%-12px)] w-[3px] rounded-r bg-brand" />}
                        <it.icon className={cn("h-4 w-4 shrink-0", isActive && "text-brand")} aria-hidden />
                        {!collapsed && <span className="truncate">{it.label}</span>}
                      </>
                    )}
                  </NavLink>
                );
                return <li key={it.to}>{collapsed ? <Tip label={it.label}>{link}</Tip> : link}</li>;
              })}
            </ul>
          </div>
        ))}
      </nav>
      <div className={cn("border-t border-line p-2", mobile && "hidden")}>
        <button className={cn("btn-ghost w-full", collapsed && "justify-center px-0")} onClick={toggleCollapsed} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} aria-pressed={collapsed}>
          {collapsed ? <ChevronsRight className="h-4 w-4" /> : <><ChevronsLeft className="h-4 w-4" /> Collapse</>}
        </button>
      </div>
    </aside>
  );
}

const READ_KEY = "mcp-pentester-read-notifications";
function loadRead(): Set<string> {
  try { return new Set(JSON.parse(localStorage.getItem(READ_KEY) ?? "[]") as string[]); } catch { return new Set(); }
}

function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const [read, setRead] = useState<Set<string>>(loadRead);
  const [local, setLocal] = useState<NotificationItem[]>([]);
  const { data } = useNotifications();
  const navigate = useNavigate();
  const box = useRef<HTMLDivElement>(null);

  // Real client-side event: a report download that actually succeeded.
  useEffect(() => {
    const h = (e: Event) => {
      const d = (e as CustomEvent<{ id: string; kind: string; at: string }>).detail;
      setLocal((l) => [{ id: `rep-${d.at}`, kind: "report_generated", level: "info", title: "Report generated", message: `${d.kind.toUpperCase()} report for scan ${d.id.slice(0, 8)} downloaded`, scan_id: d.id, timestamp: d.at }, ...l].slice(0, 20));
    };
    window.addEventListener("mcp-pentester-report", h);
    return () => window.removeEventListener("mcp-pentester-report", h);
  }, []);
  useEffect(() => {
    if (!open) return;
    const h = (e: MouseEvent) => { if (box.current && !box.current.contains(e.target as Node)) setOpen(false); };
    const k = (e: globalThis.KeyboardEvent) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", h);
    document.addEventListener("keydown", k);
    return () => { document.removeEventListener("mousedown", h); document.removeEventListener("keydown", k); };
  }, [open]);

  const items = useMemo(() => [...local, ...(data?.items ?? [])].sort((a, b) => b.timestamp.localeCompare(a.timestamp)), [local, data]);
  const unread = items.filter((i) => !read.has(i.id)).length;
  const markAll = () => {
    const s = new Set(items.map((i) => i.id));
    setRead(s);
    try { localStorage.setItem(READ_KEY, JSON.stringify([...s].slice(-300))); } catch { /* ignore */ }
  };
  const dot: Record<string, string> = { critical: "bg-sev-critical", error: "bg-sev-high", warning: "bg-warn", info: "bg-brand" };

  return (
    <div className="relative" ref={box}>
      <button className="btn-ghost relative" aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`} aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <Bell className="h-4 w-4" />
        {unread > 0 && <span className="absolute -right-0.5 -top-0.5 grid h-4 min-w-4 place-items-center rounded-full bg-[#b91c1c] px-1 text-[10px] font-bold text-white">{unread > 9 ? "9+" : unread}</span>}
      </button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -6 }} transition={{ duration: 0.12 }}
            className="absolute right-0 z-50 mt-2 w-[360px] max-w-[90vw] overflow-hidden rounded-xl border border-line bg-panel shadow-2xl" role="dialog" aria-label="Notifications">
            <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
              <span className="font-semibold">Notifications</span>
              <button className="text-[12px] text-brand hover:underline disabled:text-dim" onClick={markAll} disabled={unread === 0}>Mark all read</button>
            </div>
            <ul className="max-h-[380px] overflow-y-auto">
              {items.length === 0 && <li className="px-4 py-8 text-center text-dim">No notifications. Events appear here when scans finish, fail or find critical issues.</li>}
              {items.map((n) => (
                <li key={n.id}>
                  <button className="flex w-full gap-3 border-b border-line/60 px-4 py-3 text-left transition hover:bg-raised"
                    onClick={() => { setOpen(false); navigate(n.kind === "critical_finding" ? `/findings?scan=${n.scan_id}&severity=critical` : `/scans/${n.scan_id}`); }}>
                    <span className={cn("mt-1.5 h-2 w-2 shrink-0 rounded-full", dot[n.level] ?? "bg-brand", read.has(n.id) && "opacity-30")} />
                    <span className="min-w-0 flex-1">
                      <span className={cn("block text-[13px]", !read.has(n.id) && "font-semibold")}>{n.title}</span>
                      <span className="block truncate text-[12px] text-dim">{n.message}</span>
                      <span className="text-[11px] text-dim/80">{timeAgo(n.timestamp)}</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function Topbar({ onSearch, authRequired, onSignOut, onMenu, mobile }: { onSearch: () => void; authRequired: boolean; onSignOut: () => void; onMenu: () => void; mobile: boolean }) {
  const { theme, toggleTheme } = usePrefs();
  const loc = useLocation();
  const health = useSystemHealth();
  const scans = useScans(50);
  const running = (scans.data?.items ?? []).filter((s) => s.status === "running" || s.status === "queued");
  const seg = "/" + (loc.pathname.split("/")[1] ?? "");
  const title = loc.pathname.startsWith("/scans/") ? "Scan" : TITLES[seg] ?? "Home";
  const overall = health.data?.overall;
  const healthTone = overall === "healthy" ? "bg-ok" : overall === "degraded" ? "bg-warn" : overall === "unavailable" ? "bg-sev-critical" : "bg-dim";

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-line bg-bg/85 px-3 sm:px-5 backdrop-blur">
      {mobile && <button className="btn-ghost -ml-1 shrink-0" onClick={onMenu} aria-label="Open navigation"><Menu className="h-4 w-4" /></button>}
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-2 text-[13px] text-dim">
        <span className="hidden sm:inline">Aspida</span><span aria-hidden className="hidden sm:inline">/</span><span className="truncate font-medium text-fg">{title}</span>
      </nav>
      <button onClick={onSearch} className="mx-auto hidden w-full max-w-md items-center gap-2 rounded-lg border border-line bg-panel px-3 py-1.5 text-left text-[13px] text-dim transition hover:border-brand/50 md:flex" aria-label="Search (Ctrl+K)">
        <Search className="h-3.5 w-3.5" /> <span className="flex-1">Search tools, findings, scans…</span><span className="kbd">Ctrl K</span>
      </button>
      <div className="ml-auto flex shrink-0 items-center gap-0.5 sm:gap-1.5 md:ml-0">
        <button className="btn-ghost md:hidden" onClick={onSearch} aria-label="Search"><Search className="h-4 w-4" /></button>
        {running.length > 0 && (
          <Link to="/active" className="btn-ghost text-brand" aria-label={`${running.length} active scan(s)`}>
            <Activity className="h-4 w-4 animate-pulseDot" /> <span className="hidden sm:inline">{running.length} running</span>
          </Link>
        )}
        <Tip label={health.data ? `System ${overall}` : "Checking system health"} side="bottom">
          <Link to="/health" className="btn-ghost" aria-label={`System health: ${overall ?? "unknown"}`}>
            <span className={cn("h-2.5 w-2.5 rounded-full", healthTone)} /> <span className="hidden lg:inline">{overall ?? "…"}</span>
          </Link>
        </Tip>
        <NotificationCenter />
        <button className="btn-ghost" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}>
          {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
        </button>
        <Link to="/settings" className="btn-ghost hidden sm:inline-flex" aria-label="Settings"><Settings className="h-4 w-4" /></Link>
        {authRequired && <button className="btn-ghost" onClick={onSignOut} aria-label="Sign out"><LogOut className="h-4 w-4" /></button>}
      </div>
    </header>
  );
}

export function Shell({ version, authRequired, onSignOut, apiDown }: { version: string; authRequired: boolean; onSignOut: () => void; apiDown: boolean }) {
  const [palette, setPalette] = useState(false);
  const [navOpen, setNavOpen] = useState(false);
  const isMobile = useIsMobile();
  const loc = useLocation();
  useEffect(() => { setNavOpen(false); }, [loc.pathname]);
  useEffect(() => {
    if (!navOpen) return;
    const h = (e: globalThis.KeyboardEvent) => { if (e.key === "Escape") setNavOpen(false); };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [navOpen]);

  useEffect(() => {
    const h = (e: globalThis.KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); setPalette((p) => !p); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, []);

  if (loc.pathname === "/journey") {
    // The story is a full-bleed page with its own navigation; it still sits inside the same auth, API client and query cache.
    return (
      <TooltipProvider>
        {apiDown && <div role="alert" className="fixed inset-x-0 top-0 z-[60] bg-sev-critical/20 px-4 py-2 text-center text-[12px] text-sev-critical">The API is not responding. Start the backend on port 8000 and reload.</div>}
        <Suspense fallback={<ContextLoader message="Loading the story…" />}><Outlet /></Suspense>
      </TooltipProvider>
    );
  }

  return (
    <TooltipProvider>
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-[200] focus:rounded focus:bg-brand focus:px-3 focus:py-1.5 focus:text-bg">Skip to content</a>
      <div className="flex min-h-screen">
        {!isMobile && <Sidebar version={version} />}
        {isMobile && navOpen && (
          <>
            <div className="fixed inset-0 z-40 bg-black/60" onClick={() => setNavOpen(false)} aria-hidden />
            <Sidebar version={version} mobile onClose={() => setNavOpen(false)} />
          </>
        )}
        <div className="flex min-w-0 flex-1 flex-col">
          <Topbar onSearch={() => setPalette(true)} authRequired={authRequired} onSignOut={onSignOut} onMenu={() => setNavOpen(true)} mobile={isMobile} />
          {apiDown && (
            <div role="alert" className="border-b border-sev-critical/40 bg-sev-critical/10 px-5 py-2 text-sev-critical">
              The API is not responding. Start the backend on port 8000 and reload.
            </div>
          )}
          <main id="main" tabIndex={-1} className="mx-auto w-full max-w-[1500px] flex-1 px-3 py-5 outline-none sm:px-5 sm:py-6">
            <AnimatePresence mode="wait" initial={false}>
              <motion.div key={loc.pathname} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.14 }}>
                <Suspense fallback={<ContextLoader message="Loading…" />}><Outlet /></Suspense>
              </motion.div>
            </AnimatePresence>
          </main>
        </div>
      </div>
      <CommandPalette open={palette} onOpenChange={setPalette} onSignOut={authRequired ? onSignOut : undefined} />
    </TooltipProvider>
  );
}
export { auth };
