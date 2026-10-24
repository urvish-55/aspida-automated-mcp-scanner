import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

type Theme = "dark" | "light";

interface Prefs {
  theme: Theme;
  toggleTheme: () => void;
  collapsed: boolean;
  toggleCollapsed: () => void;
  scanId: string | null; // explicitly chosen scan; null = latest
  setScanId: (id: string | null) => void;
}

const Ctx = createContext<Prefs | null>(null);
const KEY = "mcp-pentester-prefs";

function load(): { theme: Theme; collapsed: boolean; scanId: string | null } {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const p = JSON.parse(raw);
      return { theme: p.theme === "light" ? "light" : "dark", collapsed: !!p.collapsed, scanId: typeof p.scanId === "string" ? p.scanId : null };
    }
  } catch { /* storage blocked: defaults */ }
  return { theme: "dark", collapsed: false, scanId: null };
}

export function PrefsProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState(load);
  useEffect(() => {
    document.documentElement.dataset.theme = state.theme;
    try { localStorage.setItem(KEY, JSON.stringify(state)); } catch { /* ignore */ }
  }, [state]);
  const toggleTheme = useCallback(() => setState((s) => ({ ...s, theme: s.theme === "dark" ? "light" : "dark" })), []);
  const toggleCollapsed = useCallback(() => setState((s) => ({ ...s, collapsed: !s.collapsed })), []);
  const setScanId = useCallback((id: string | null) => setState((s) => ({ ...s, scanId: id })), []);
  const value = useMemo(() => ({ ...state, toggleTheme, toggleCollapsed, setScanId }), [state, toggleTheme, toggleCollapsed, setScanId]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function usePrefs(): Prefs {
  const v = useContext(Ctx);
  if (!v) throw new Error("PrefsProvider missing");
  return v;
}
