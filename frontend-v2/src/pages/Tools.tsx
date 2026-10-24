import { useQuery } from "@tanstack/react-query";
import { ArrowLeft, LayoutGrid, Network, Search, Table2, Wrench } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { CodeViewer } from "../components/CodeViewer";
import { EvidenceBlock } from "../components/EvidenceViewer";
import { Heatmap } from "../components/Heatmap";
import { InvestigationDrawer } from "../components/Investigation";
import { MiniBar } from "../components/RiskGauge";
import { ScanPicker } from "../components/ScanPicker";
import { ToolGraph } from "../components/ToolGraph";
import { ConfidenceBadge, ContextLoader, EmptyState, ErrorState, PageHeader, Pill, SeverityBadge, Skeleton, Tabs, TabsContent, TabsList, TabsTrigger } from "../components/ui";
import { api } from "../services/api";
import { useActiveScan, useAnalysis, useScanDetail } from "../state/queries";
import { cn, fmtDateTime, humanize, SEV_TEXT } from "../lib/utils";
import type { Finding, Tool } from "../types";

const CAP_LABEL = (c: string) => humanize(c);

function ToolCard({ name, caps, risk, band, findings, max, onOpen }: { name: string; caps: string[]; risk: number; band: string; findings: number; max: string; onOpen: () => void; desc: string }) {
  return (
    <button onClick={onOpen} className="card flex flex-col gap-2 p-4 text-left transition hover:border-brand/60" aria-label={`Tool ${name}, exposure ${risk}, ${findings} findings`}>
      <div className="flex items-center justify-between gap-2"><span className="mono truncate font-semibold">{name}</span>{findings > 0 && <SeverityBadge severity={max} />}</div>
      <div className="flex items-center gap-2"><MiniBar value={risk} sev={band} /><span className={cn("w-7 text-right text-[12px] font-semibold tabular-nums", SEV_TEXT[band])}>{risk}</span></div>
      <div className="flex min-h-[22px] flex-wrap gap-1">{caps.map((c) => <Pill key={c}>{CAP_LABEL(c)}</Pill>)}{caps.length === 0 && <span className="text-[12px] text-dim">No capabilities inferred</span>}</div>
      <div className="text-[12px] text-dim">{findings} security finding{findings === 1 ? "" : "s"}</div>
    </button>
  );
}

function ToolDetail({ name, scanId, onBack }: { name: string; scanId: string; onBack: () => void }) {
  const scan = useScanDetail(scanId);
  const analysis = useAnalysis(scanId);
  const hist = useQuery({ queryKey: ["tool-history", name], queryFn: () => api.toolHistory(name) });
  const [open, setOpen] = useState<Finding | null>(null);
  const tool: Tool | undefined = scan.data?.tools.find((t) => t.name === name);
  const exposure = analysis.data?.tools.find((t) => t.name === name);
  const findings = (scan.data?.findings ?? []).filter((f) => f.affected_tools.includes(name) && f.category !== "engine");
  const real = findings.filter((f) => f.status !== "informational");
  const tests = (scan.data?.tests ?? []).filter((t) => t.tool_name === name);
  const params = useMemo(() => {
    const props = (tool?.input_schema as { properties?: Record<string, { type?: string; description?: string }> } | undefined)?.properties ?? {};
    const req = new Set(((tool?.input_schema as { required?: string[] } | undefined)?.required) ?? []);
    return Object.entries(props).map(([k, v]) => ({ name: k, type: String(v?.type ?? "(none)"), required: req.has(k), description: v?.description }));
  }, [tool]);

  if (scan.isLoading) return <ContextLoader message="Inspecting tool…" />;
  if (!tool) return <ErrorState title="Tool not found in this scan" message={`“${name}” is not part of the selected scan.`} onRetry={onBack} />;
  const evCount = findings.reduce((n, f) => n + f.evidence.length, 0);

  return (
    <div>
      <button className="btn-ghost -ml-2 mb-3" onClick={onBack}><ArrowLeft className="h-4 w-4" /> All tools</button>
      <div className="card mb-4 p-5">
        <div className="label">Tool</div>
        <h1 className="mono mt-0.5 text-2xl font-semibold">{tool.name}</h1>
        <p className="mt-2 max-w-3xl whitespace-pre-wrap text-dim">{tool.description || "No description was provided."}</p>
        <div className="mt-4 grid grid-cols-1 gap-6 sm:grid-cols-3">
          <div><div className="label mb-1">Exposure</div><div className="flex items-center gap-3"><div className="flex-1"><MiniBar value={exposure?.exposure.score ?? 0} sev={exposure?.exposure.band ?? "none"} /></div><span className={cn("text-xl font-semibold tabular-nums", SEV_TEXT[exposure?.exposure.band ?? "none"])}>{exposure?.exposure.score ?? 0}</span></div><p className="mt-1 text-[11.5px] text-dim">Display ranking, not the scan risk score.</p></div>
          <div><div className="label mb-1">Capabilities</div><div className="flex flex-wrap gap-1.5">{tool.capabilities.map((c) => <Pill key={c} tone="warn">{CAP_LABEL(c)}</Pill>)}{tool.capabilities.length === 0 && <span className="text-dim">None inferred</span>}</div></div>
          <div><div className="label mb-1">Security findings</div><div className="text-xl font-semibold tabular-nums">{real.length}</div></div>
        </div>
      </div>

      <Tabs defaultValue="schema">
        <TabsList><TabsTrigger value="schema">Schema</TabsTrigger><TabsTrigger value="security">Security ({real.length})</TabsTrigger><TabsTrigger value="evidence">Evidence ({evCount})</TabsTrigger><TabsTrigger value="usage">Usage</TabsTrigger><TabsTrigger value="history">History</TabsTrigger></TabsList>
        <TabsContent value="schema">
          {Object.keys(tool.input_schema ?? {}).length === 0 ? <EmptyState title="No input schema declared." body="This tool does not declare an input schema, so every argument is unconstrained." /> : <CodeViewer value={tool.input_schema} title="inputSchema" maxHeight={520} />}
        </TabsContent>
        <TabsContent value="security">
          {exposure && exposure.exposure.reasons.length > 0 && <div className="card mb-4 p-4"><h3 className="mb-2 font-semibold">Why this exposure score</h3><ul className="space-y-1 text-[13px]">{exposure.exposure.reasons.map((r, i) => <li key={i} className="flex justify-between gap-3"><span>{r.label}</span><span className="tabular-nums text-dim">+{r.points}</span></li>)}</ul></div>}
          {real.length === 0 ? <EmptyState title="No findings for this tool." body="No enabled test flagged this tool. That does not prove it is safe." /> : (
            <ul className="space-y-2">{real.map((f) => <li key={f.id}><button className="card flex w-full items-center gap-3 p-3 text-left transition hover:border-brand/60" onClick={() => setOpen(f)}><SeverityBadge severity={f.severity} /><span className="min-w-0 flex-1 truncate">{f.title}</span><ConfidenceBadge value={f.confidence} /></button></li>)}</ul>
          )}
        </TabsContent>
        <TabsContent value="evidence">
          {evCount === 0 ? <EmptyState title="No evidence recorded." body="Findings for this tool have no evidence blocks, or there are no findings." /> : (
            <div className="space-y-4">{findings.filter((f) => f.evidence.length).map((f) => <div key={f.id}><div className="mb-1.5 flex items-center gap-2"><SeverityBadge severity={f.severity} /><span className="font-medium">{f.title}</span></div><div className="space-y-2">{f.evidence.map((e, i) => <EvidenceBlock key={i} ev={e} tools={[tool]} />)}</div></div>)}</div>
          )}
        </TabsContent>
        <TabsContent value="usage">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="card p-4"><h3 className="mb-2 font-semibold">Input parameters ({params.length})</h3>
              {params.length === 0 ? <p className="text-dim">No parameters declared.</p> : <ul className="divide-y divide-line">{params.map((p) => <li key={p.name} className="py-2"><div className="flex items-center gap-2"><span className="mono">{p.name}</span><Pill>{p.type}</Pill>{p.required && <Pill tone="warn">required</Pill>}</div>{p.description && <p className="mt-1 text-[12.5px] text-dim">{p.description}</p>}</li>)}</ul>}
            </div>
            <div className="card p-4"><h3 className="mb-2 font-semibold">Dynamic tests on this tool ({tests.length})</h3>
              {tests.length === 0 ? <p className="text-dim">No dynamic test touched this tool in this scan. Dynamic testing is optional and needs a live target.</p> : <ul className="divide-y divide-line">{tests.map((t) => <li key={t.test_id + t.detail} className="py-2"><div className="flex items-center gap-2"><span className="font-medium">{t.test_name}</span><Pill tone={t.status === "failed" ? "bad" : t.status === "passed" ? "ok" : "warn"}>{t.status}</Pill></div><p className="mt-0.5 text-[12.5px] text-dim">{t.detail}</p></li>)}</ul>}
            </div>
          </div>
        </TabsContent>
        <TabsContent value="history">
          {hist.isLoading ? <Skeleton className="h-24" /> : (hist.data?.items.length ?? 0) === 0 ? <EmptyState title="No history." body="This tool has not appeared in other scans." /> : (
            <div className="card overflow-x-auto"><table className="w-full text-left text-[13px]"><thead><tr className="border-b border-line text-dim"><th className="px-3 py-2">Scan</th><th className="px-3 py-2">When</th><th className="px-3 py-2">Findings</th><th className="px-3 py-2">Worst</th><th className="px-3 py-2">Definition hash</th></tr></thead><tbody>
              {hist.data?.items.map((h) => <tr key={h.scan_id} className="border-b border-line/60 last:border-0"><td className="px-3 py-2"><Link className="hover:text-brand" to={`/scans/${h.scan_id}`}>{h.scan_label}</Link></td><td className="px-3 py-2 text-dim">{fmtDateTime(h.created_at)}</td><td className="px-3 py-2 tabular-nums">{h.finding_count}</td><td className="px-3 py-2">{h.max_severity !== "none" ? <SeverityBadge severity={h.max_severity} /> : "-"}</td><td className="mono px-3 py-2 text-dim">{h.definition_hash}</td></tr>)}
            </tbody></table><p className="border-t border-line px-3 py-2 text-[12px] text-dim">A changed definition hash between scans means the description or schema changed.</p></div>
          )}
        </TabsContent>
      </Tabs>
      <InvestigationDrawer finding={open} scanId={scanId} onClose={() => setOpen(null)} />
    </div>
  );
}

export default function Tools() {
  const [sp, setSp] = useSearchParams();
  const { scan, loading } = useActiveScan();
  const scanId = sp.get("scan") ?? scan?.id;
  const toolName = sp.get("tool");
  const analysis = useAnalysis(scanId);
  const detail = useScanDetail(scanId);
  const [view, setView] = useState<"cards" | "graph" | "heatmap">("cards");
  const [q, setQ] = useState("");
  const [cap, setCap] = useState("");
  const [node, setNode] = useState<string | null>(null);

  const open = (t: string | null) => setSp((p) => { const n = new URLSearchParams(p); if (t) n.set("tool", t); else n.delete("tool"); return n; });
  const descOf = useMemo(() => new Map((detail.data?.tools ?? []).map((t) => [t.name, t.description])), [detail.data]);

  if (loading) return <ContextLoader message="Discovering MCP tools…" />;
  if (!scanId) return <div><PageHeader title="Tools" /><EmptyState title="No scans yet." body="Run your first MCP security scan to begin analyzing tools and capabilities." action={{ label: "Start New Scan", to: "/scan" }} /></div>;
  if (toolName) return <ToolDetail name={toolName} scanId={scanId} onBack={() => open(null)} />;

  const tools = analysis.data?.tools ?? [];
  const caps = [...new Set(tools.flatMap((t) => t.capabilities))].sort();
  const shown = tools.filter((t) => (!q || t.name.toLowerCase().includes(q.toLowerCase()) || (descOf.get(t.name) ?? "").toLowerCase().includes(q.toLowerCase())) && (!cap || t.capabilities.includes(cap)));
  const graphNode = analysis.data?.graph.nodes.find((n) => n.id === node);
  const connected = node && analysis.data ? analysis.data.graph.edges.filter((e) => e.source === node || e.target === node).map((e) => ({ other: e.source === node ? e.target : e.source, verb: e.verb, out: e.source === node })) : [];

  return (
    <div>
      <PageHeader title="Tools" sub="Every tool the scan discovered, with capabilities, exposure and findings." actions={<ScanPicker />} />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="relative"><Search className="pointer-events-none absolute left-2.5 top-2.5 h-3.5 w-3.5 text-dim" aria-hidden /><input className="input !w-64 !pl-8" placeholder="Search tools" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search tools" /></label>
        <select className="input !w-auto" value={cap} onChange={(e) => setCap(e.target.value)} aria-label="Filter by capability"><option value="">All capabilities</option>{caps.map((c) => <option key={c} value={c}>{CAP_LABEL(c)}</option>)}</select>
        <div className="ml-auto flex rounded-lg border border-line p-0.5" role="tablist" aria-label="View">
          {([["cards", "Cards", LayoutGrid], ["graph", "Graph", Network], ["heatmap", "Heatmap", Table2]] as const).map(([k, l, Icon]) => (
            <button key={k} role="tab" aria-selected={view === k} onClick={() => setView(k)} className={cn("flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[13px]", view === k ? "bg-brand/15 text-brand" : "text-dim hover:text-fg")}><Icon className="h-3.5 w-3.5" /> {l}</button>
          ))}
        </div>
      </div>

      {analysis.isLoading ? <ContextLoader message="Building capability graph…" /> : analysis.error ? <ErrorState title="Analysis unavailable" message={(analysis.error as Error).message} onRetry={() => void analysis.refetch()} />
        : tools.length === 0 ? <EmptyState icon={<Wrench className="h-6 w-6" />} title="No tools were recorded." body="This scan produced no tool inventory. If it failed, check the scan's event log." action={{ label: "Open scan", to: `/scans/${scanId}` }} />
        : view === "cards" ? (
          shown.length === 0 ? <EmptyState title="No tools match." body="Clear the search or capability filter." /> :
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">{shown.map((t) => <ToolCard key={t.name} name={t.name} caps={t.capabilities} risk={t.exposure.score} band={t.exposure.band} findings={t.finding_count} max={t.max_severity} desc={descOf.get(t.name) ?? ""} onOpen={() => open(t.name)} />)}</div>
        ) : view === "graph" && analysis.data ? (
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
            <div className="card p-4"><ToolGraph nodes={analysis.data.graph.nodes} edges={analysis.data.graph.edges} selected={node} onSelect={setNode} /></div>
            <aside className="card h-fit p-4" aria-label="Node details">
              {!graphNode ? <p className="text-dim">Select a node to see its details.</p> : (
                <div className="space-y-3">
                  <div><div className="label">{graphNode.kind}</div><div className="mono text-lg font-semibold">{graphNode.label}</div></div>
                  {graphNode.kind === "tool" && <><div className="text-dim">{graphNode.finding_count ?? 0} finding(s)</div><button className="btn-primary" onClick={() => open(graphNode.label)}>Open tool inspector</button></>}
                  {graphNode.kind === "capability" && <div className="text-dim">Used by {graphNode.tool_count} tool(s)</div>}
                  <ul className="space-y-1 text-[13px]">{connected.map((c, i) => <li key={i} className="flex justify-between gap-2 border-b border-line/50 py-1"><span className="mono truncate">{c.other.replace(/^(tool|cap):/, "")}</span><span className="text-dim">{c.out ? c.verb : `← ${c.verb}`}</span></li>)}</ul>
                </div>
              )}
            </aside>
          </div>
        ) : analysis.data ? (
          <div className="card p-4"><Heatmap columns={analysis.data.heatmap.columns} rows={analysis.data.heatmap.rows.filter((r) => shown.some((s) => s.name === r.tool))} onOpenTool={(t) => open(t)} /></div>
        ) : null}
    </div>
  );
}
