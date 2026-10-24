import { useQuery } from "@tanstack/react-query";
import { Moon, Sun } from "lucide-react";
import { ContextLoader, ErrorState, PageHeader, Pill } from "../components/ui";
import { api } from "../services/api";
import { usePrefs } from "../state/prefs";
import { useHealth } from "../state/queries";
import { useInvestigation } from "../state/investigation";

export default function Settings() {
  const h = useHealth();
  const v = useQuery({ queryKey: ["version"], queryFn: api.version });
  const { theme, toggleTheme, collapsed, toggleCollapsed } = usePrefs();
  const v3 = useInvestigation();
  if (h.isLoading || v.isLoading) return <ContextLoader message="Loading settings…" />;
  if (h.error || !h.data || !v.data) return <ErrorState title="Settings unavailable" message={((h.error ?? v.error) as Error | null)?.message ?? "The API did not respond."} onRetry={() => { void h.refetch(); void v.refetch(); }} />;
  const d = h.data;
  const row = (k: string, val: React.ReactNode, note?: string) => <tr className="border-b border-line/60 last:border-0"><td className="py-2.5 pr-4 text-dim">{k}</td><td className="py-2.5">{val}{note && <span className="ml-2 text-[12px] text-dim">{note}</span>}</td></tr>;
  return (
    <div>
      <PageHeader title="Settings" sub="Security behaviour is configured on the server with environment variables (see .env.example). This page is read-only and never shows secrets." />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="card p-4"><h2 className="mb-2 font-semibold">Server status</h2><table className="w-full text-[13px]"><tbody>
          {row("API", <Pill tone={d.status === "ok" ? "ok" : "warn"}>{d.status}</Pill>)}
          {row("Authentication", d.auth_required ? <Pill tone="ok">API key required</Pill> : <Pill tone="bad">DISABLED</Pill>, d.auth_required ? undefined : "anyone who can reach this port can run scans (AUTH_REQUIRED=false)")}
          {row("Database", <Pill tone={d.database === "ok" ? "ok" : "bad"}>{d.database}</Pill>)}
          {row("LLM provider", <Pill tone={d.llm_available ? "ok" : "neutral"}>{d.llm_provider}</Pill>, d.llm_available ? undefined : "semantic analysis will report “unavailable”")}
          {row("ML model", <Pill tone={d.ml_available ? "ok" : "neutral"}>{d.ml_available ? "present" : "not trained"}</Pill>)}
          {row("Safe mode default", <Pill tone={d.safe_mode_default ? "ok" : "bad"}>{String(d.safe_mode_default)}</Pill>)}
        </tbody></table></section>
        <section className="card p-4"><h2 className="mb-2 font-semibold">Versions</h2><table className="w-full text-[13px]"><tbody>
          {row("Application", <span className="mono">{v.data.version}</span>)}{row("Ruleset", <span className="mono">{v.data.ruleset_version}</span>)}{row("ML model", <span className="mono">{v.data.ml_model_version}</span>)}{row("Schema", <span className="mono">{v.data.scanner_schema_version}</span>)}
        </tbody></table></section>
        <section className="card p-4"><h2 className="mb-3 font-semibold">Interface</h2>
          <div className="flex flex-wrap gap-3"><button className="btn" onClick={toggleTheme}>{theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />} Switch to {theme === "dark" ? "light" : "dark"} theme</button><button className="btn" onClick={toggleCollapsed}>{collapsed ? "Expand" : "Collapse"} sidebar</button></div>
          <p className="mt-3 text-[12px] text-dim">Theme and sidebar state are saved in this browser only.</p></section>
        <section className="card p-4"><h2 className="mb-3 font-semibold">3D investigation</h2>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <label className="block text-[13px]"><span className="label mb-1 block">3D quality</span>
              <select className="input" value={v3.quality} onChange={(e) => v3.setQuality(e.target.value as typeof v3.quality)}><option value="auto">Auto (by object count and device)</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option></select></label>
            <label className="block text-[13px]"><span className="label mb-1 block">Effects</span>
              <select className="input" value={v3.effects} onChange={(e) => v3.setEffects(e.target.value as typeof v3.effects)}><option value="full">Full (camera glide, pulse on running scans, floor grid)</option><option value="reduced">Reduced (short glides, no pulse)</option><option value="off">Off (no animation)</option></select></label>
          </div>
          <label className="mt-3 flex items-center gap-2 text-[13px]"><input type="checkbox" checked={v3.force2D} onChange={(e) => v3.setForce2D(e.target.checked)} /> Always use the 2D view</label>
          <p className="mt-2 text-[12px] text-dim">Your operating system's “reduce motion” setting always turns animation off. 3D preferences are saved in this browser only.</p></section>
      </div>
    </div>
  );
}
