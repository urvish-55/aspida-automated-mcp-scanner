import { ExternalLink, Focus, Layers, Wrench, X } from "lucide-react";
import { useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { hasHiddenChars, safeLabel } from "../../lib/safeText";
import { terrainCells } from "../../lib/terrain";
import { capLabel, findingId, toolId } from "../../lib/securityGraph";
import { SEV_LABEL } from "../../lib/severity";
import { humanize } from "../../lib/utils";
import { useInvestigation } from "../../state/investigation";
import type { Analysis, Finding, ScanDetail } from "../../types";
import type { ScanStageView, SecurityGraph } from "../../types/visualization";
import { CodeViewer } from "../CodeViewer";
import { ConfidenceBadge, Pill, SeverityBadge } from "../ui";

function Sec({ title, children }: { title: string; children: React.ReactNode }) {
  return <section className="mb-4"><h3 className="label mb-1.5">{title}</h3>{children}</section>;
}
function Link2({ id, children }: { id: string; children: React.ReactNode }) {
  const focus = useInvestigation((s) => s.focus);
  return <button className="rounded border border-line bg-raised px-2 py-0.5 text-[12px] hover:border-brand/60" onClick={() => focus(id)}>{children}</button>;
}

export function Inspector({ selectedId, graph, scan, analysis, stages, onOpenFinding, onClose }: {
  selectedId: string | null; graph: SecurityGraph; scan: ScanDetail; analysis: Analysis | undefined; stages: ScanStageView[];
  onOpenFinding: (f: Finding) => void; onClose: () => void;
}) {
  const nav = useNavigate();
  const { isolate, focus, setActivePath, playTour, isolateId, setMode } = useInvestigation();
  const node = selectedId ? graph.nodes.find((n) => n.id === selectedId) : undefined;
  const findings = scan.findings;
  const cells = useMemo(() => terrainCells(findings), [findings]);

  const header = (title: string, kind: string, extra?: React.ReactNode) => (
    <div className="mb-3 flex items-start justify-between gap-2">
      <div className="min-w-0"><div className="label">{kind}</div><h2 className="break-words text-[15px] font-semibold leading-snug">{title}</h2>{extra}</div>
      <button className="btn-ghost shrink-0 !p-1" onClick={onClose} aria-label="Close inspector"><X className="h-4 w-4" /></button>
    </div>
  );
  const actions = (id: string) => (
    <div className="mb-4 flex flex-wrap gap-2">
      <button className="btn !py-1 text-[12px]" onClick={() => focus(id)}><Focus className="h-3.5 w-3.5" aria-hidden /> Focus</button>
      <button className="btn !py-1 text-[12px]" onClick={() => { isolate(isolateId === id ? null : id); focus(id); }}><Layers className="h-3.5 w-3.5" aria-hidden /> {isolateId === id ? "Show all" : "Isolate"}</button>
    </div>
  );

  if (!selectedId) {
    return (
      <div className="text-[13px] text-dim">
        <h2 className="label mb-2">Inspector</h2>
        <p>Select an object in the 3D scene, the list, or search (Ctrl+K) to see its definition, capabilities, findings and evidence here.</p>
        <p className="mt-2">Double-click an object to isolate it and its neighbours. Esc steps back.</p>
      </div>
    );
  }

  if (node?.kind === "server") {
    return (
      <div>{header(node.label, "MCP server")}{actions(node.id)}
        <Sec title="Stored data"><ul className="space-y-1 text-[13px]"><li>{scan.tools.length} tools enumerated</li><li>{findings.length} findings stored</li><li>{analysis?.attack_paths.length ?? 0} attack-path candidate(s)</li><li>Target type: {scan.target_type}</li>{scan.risk_score != null && <li>Scan risk score: <b>{Math.round(scan.risk_score)}</b> (RISK-1)</li>}</ul></Sec>
        <Sec title="Not analysed"><p className="text-[12.5px] text-dim">Resources and prompts are not inspected by the backend, so none are shown.</p></Sec>
      </div>
    );
  }

  if (node?.kind === "tool") {
    const tool = scan.tools.find((t) => toolId(t.name) === node.id);
    const fs = findings.filter((f) => f.affected_tools.includes(tool?.name ?? "") && f.status !== "informational");
    const tests = scan.tests.filter((t) => t.tool_name === tool?.name);
    const paths = (analysis?.attack_paths ?? []).filter((p) => node.pathIds.includes(p.id));
    return (
      <div>{header(node.label, "Tool", node.level !== "none" && <div className="mt-1"><SeverityBadge severity={node.level} /></div>)}{actions(node.id)}
        {tool?.description && (
          <Sec title="Description (untrusted text)">
            {hasHiddenChars(tool.description) && <p className="mb-1 rounded border border-sev-high/40 bg-sev-high/10 px-2 py-1 text-[12px] text-sev-high">Contains invisible or direction-changing characters. They are shown as ⟦U+XXXX⟧ below.</p>}
            <p className="max-h-40 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-raised p-2 text-[12.5px]">{safeLabel(tool.description, 1500)}</p>
          </Sec>
        )}
        <Sec title="Capabilities">{tool && tool.capabilities.length ? <div className="flex flex-wrap gap-1.5">{tool.capabilities.map((c) => <Link2 key={c} id={`cap:${c}`}>{capLabel(c)}</Link2>)}</div> : <p className="text-dim">None detected.</p>}</Sec>
        <Sec title={`Findings (${fs.length})`}>{fs.length ? <ul className="space-y-1">{fs.map((f) => <li key={f.id}><button className="flex w-full items-start gap-2 text-left text-[12.5px] hover:underline" onClick={() => focus(findingId(f.id))}><SeverityBadge severity={f.severity} /><span className="min-w-0 break-words">{safeLabel(f.title)}</span></button></li>)}</ul> : <p className="text-dim">No findings reference this tool.</p>}</Sec>
        <Sec title={`Dynamic tests (${tests.length})`}>{tests.length ? <ul className="space-y-1 text-[12.5px]">{tests.map((t) => <li key={t.test_id}><b>{safeLabel(t.test_name)}</b> · {t.status}{t.detail ? ` · ${safeLabel(t.detail, 140)}` : ""}</li>)}</ul> : <p className="text-dim">No dynamic tests ran against this tool (static analysis only, or dynamic testing was off).</p>}</Sec>
        <Sec title="Attack paths">{paths.length ? <div className="flex flex-wrap gap-2">{paths.map((p) => <button key={p.id} className="btn !py-1 text-[12px]" onClick={() => { setMode("paths"); setActivePath(p.id); }}>{safeLabel(p.label, 40)}</button>)}</div> : <p className="text-dim">No evidence-backed path includes this tool.</p>}</Sec>
        {tool && Object.keys(tool.input_schema ?? {}).length > 0 && <Sec title="Input schema"><CodeViewer value={tool.input_schema} maxHeight={220} title="Input schema" /></Sec>}
        <button className="btn !py-1 text-[12px]" onClick={() => nav(`/tools?scan=${scan.id}&tool=${encodeURIComponent(tool?.name ?? "")}`)}><Wrench className="h-3.5 w-3.5" aria-hidden /> Open tool page</button>
      </div>
    );
  }

  if (node?.kind === "capability") {
    const tools = scan.tools.filter((t) => t.capabilities.includes(node.capabilityId ?? ""));
    return (
      <div>{header(node.label, "Capability")}{actions(node.id)}
        <Sec title={`Tools with this capability (${tools.length})`}><div className="flex flex-wrap gap-1.5">{tools.map((t) => <Link2 key={t.name} id={toolId(t.name)}>{safeLabel(t.name, 40)}</Link2>)}</div></Sec>
        <p className="text-[12.5px] text-dim">Capabilities are inferred by static rules from tool names, descriptions and schemas. They show what a tool could reach, not what it did.</p>
      </div>
    );
  }

  if (node?.kind === "finding") {
    const f = findings.find((x) => x.id === node.findingId);
    if (!f) return <div>{header("Finding not found", "Finding")}</div>;
    return (
      <div>{header(safeLabel(f.title, 160), "Finding", <div className="mt-1 flex flex-wrap gap-1.5"><SeverityBadge severity={f.severity} /><ConfidenceBadge value={f.confidence} /><Pill>{f.status}</Pill></div>)}{actions(node.id)}
        <Sec title="Rule"><p className="text-[12.5px]">{f.rule_id} · {humanize(f.category)}</p></Sec>
        <Sec title="Why it was detected"><p className="whitespace-pre-wrap break-words text-[12.5px]">{safeLabel(f.description, 800)}</p></Sec>
        <Sec title="Affected tools">{f.affected_tools.length ? <div className="flex flex-wrap gap-1.5">{f.affected_tools.map((t) => <Link2 key={t} id={toolId(t)}>{safeLabel(t, 40)}</Link2>)}</div> : <p className="text-dim">Applies to the scan as a whole.</p>}</Sec>
        <Sec title={`Evidence (${f.evidence.length})`}><ul className="space-y-1 text-[12.5px]">{f.evidence.slice(0, 5).map((e, i) => <li key={i}><b>{e.kind}</b>: {safeLabel(e.summary, 200)}</li>)}{f.evidence.length === 0 && <li className="text-dim">No evidence blocks recorded.</li>}</ul></Sec>
        {f.status !== "confirmed" && <p className="mb-3 text-[12px] text-dim">Not confirmed by a live test. Treat as a lead that needs verification.</p>}
        <Sec title="Remediation status"><p className="text-[12.5px]">{f.triage_status.replace(/_/g, " ")}{f.triage_note ? ` · ${safeLabel(f.triage_note, 120)}` : ""}</p></Sec>
        <button className="btn-primary !py-1 text-[12px]" onClick={() => onOpenFinding(f)}><ExternalLink className="h-3.5 w-3.5" aria-hidden /> Open full investigation</button>
      </div>
    );
  }

  if (selectedId.startsWith("pathnode:")) {
    const [, pid, idx] = selectedId.split(":");
    const p = analysis?.attack_paths.find((x) => x.id === pid);
    const n = p?.nodes[Number(idx)];
    if (!p || !n) return <div>{header("Path stage not found", "Attack path")}</div>;
    return (
      <div>{header(safeLabel(n.label), `Attack path stage ${Number(idx) + 1} of ${p.nodes.length}`, <div className="mt-1"><Pill tone={n.status === "evidenced" ? "bad" : "neutral"}>{n.status === "evidenced" ? "Evidenced" : n.status === "potential" ? "Potential (not observed)" : "Missing evidence"}</Pill></div>)}
        <Sec title="Path"><p className="text-[12.5px]">{safeLabel(p.label)} · {Math.round(p.evidence_ratio * 100)}% evidenced · confidence {p.confidence}</p></Sec>
        {p.missing_stages.length > 0 && <Sec title="Missing stages"><p className="text-[12.5px]">{p.missing_stages.join(", ")}</p></Sec>}
        <Sec title="Tools">{n.tools.length ? <div className="flex flex-wrap gap-1.5">{n.tools.map((t) => <Link2 key={t} id={toolId(t)}>{safeLabel(t, 40)}</Link2>)}</div> : <p className="text-dim">No tool is associated with this stage.</p>}</Sec>
        <Sec title="Findings">{n.finding_ids.length ? <div className="flex flex-wrap gap-1.5">{n.finding_ids.map((id) => <Link2 key={id} id={findingId(id)}>{id.slice(0, 8)}</Link2>)}</div> : <p className="text-dim">No stored finding backs this stage.</p>}</Sec>
        <Sec title="Evidence">{n.evidence.length ? <ul className="list-disc pl-4 text-[12.5px]">{n.evidence.map((e, i) => <li key={i}>{safeLabel(e, 200)}</li>)}</ul> : <p className="text-dim">None.</p>}</Sec>
        <button className="btn !py-1 text-[12px]" onClick={() => playTour(p.id)}>View Attack Path</button>
      </div>
    );
  }

  if (selectedId.startsWith("cell:")) {
    const [cat, sev] = selectedId.slice(5).split("|");
    const cell = cells.find((c) => c.category === cat && c.severity === sev);
    return (
      <div>{header(`${humanize(cat)} · ${SEV_LABEL[sev as keyof typeof SEV_LABEL] ?? sev}`, "Risk terrain cell")}
        <Sec title="Raw RISK-1 points"><p className="text-[13px]"><b>{cell?.points ?? 0}</b> points from {cell?.findingIds.length ?? 0} finding(s). These are the points before the section caps are applied, so they do not add up to the scan score.</p></Sec>
        <Sec title="Findings"><div className="flex flex-wrap gap-1.5">{(cell?.findingIds ?? []).map((id) => <Link2 key={id} id={findingId(id)}>{id.slice(0, 8)}</Link2>)}</div></Sec>
      </div>
    );
  }

  if (selectedId.startsWith("stage:")) {
    const st = stages.find((s) => `stage:${s.id}` === selectedId);
    return (
      <div>{header(st?.label ?? "Stage", "Pipeline stage", st && <div className="mt-1"><Pill tone={st.state === "done" ? "ok" : st.state === "failed" ? "bad" : st.state === "active" ? "brand" : "neutral"}>{st.state}</Pill></div>)}
        <Sec title="Last backend event"><p className="text-[12.5px]">{st?.message ? safeLabel(st.message, 300) : "The backend has not reported this stage."}</p></Sec>
        {st?.durationMs != null && <Sec title="Duration"><p className="text-[12.5px]">{st.durationMs} ms (reported by the backend)</p></Sec>}
      </div>
    );
  }
  return <div>{header(selectedId, "Object")}<p className="text-dim">No details are available for this object.</p></div>;
}
