import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import type { Finding } from "../../types";
import type { StoryData } from "../../lib/storyData";
import { safeLabel } from "../../lib/safeText";
import { SEV_LABEL } from "../../lib/severity";
import { cn, humanize, fmtDateTime } from "../../lib/utils";
import { deriveStages } from "../../lib/scanEvents";
import { SECTION_INDEX, type SectionId } from "../../lib/storyTimeline";
import { useStory } from "../../state/story";
import { CodeViewer } from "../CodeViewer";
import { SeverityBadge } from "../ui";
import { UnicodeVisual } from "./UnicodeVisual";

export type StoryStatus = "ready" | "demo" | "loading" | "error" | "empty";
export interface SectionCtx {
  data: StoryData; status: StoryStatus; motion: boolean;
  onInvestigate: (f: Finding) => void; onFocusTool?: (name: string) => void; onGo: (id: SectionId) => void; reload: () => void;
}

const UNAVAILABLE = "Data unavailable";
const btn = "inline-flex items-center justify-center rounded-md px-4 py-2.5 text-[13px] font-semibold tracking-wide outline-none transition focus-visible:ring-2 focus-visible:ring-brand motion-reduce:transition-none";
const primary = `${btn} uppercase bg-brand text-bg hover:brightness-110`;
const ghost = `${btn} uppercase border border-line bg-panel/60 text-fg hover:border-brand/60`;

function Kicker({ n, children }: { n: number; children: ReactNode }) {
  return <p className="mb-3 font-mono text-[11px] uppercase tracking-[0.22em] text-brand">{String(n).padStart(2, "0")} · {children}</p>;
}
function Metric({ label, value, ok }: { label: string; value: ReactNode; ok: boolean }) {
  return (
    <div className="rounded-lg border border-line/70 bg-bg/50 p-3">
      <div className="text-[26px] font-semibold leading-none tabular-nums">{ok ? value : "—"}</div>
      <div className="mt-1.5 text-[11.5px] leading-snug text-dim">{label}{!ok && <span className="block text-[10.5px]">{UNAVAILABLE}</span>}</div>
    </div>
  );
}
const Note = ({ children }: { children: ReactNode }) => <p className="mt-3 text-[12px] leading-relaxed text-dim">{children}</p>;

/** How the numbers on screen should be described: a real scan, an illustrative example, or nothing. */
function Provenance({ status, scanLabel }: { status: StoryStatus; scanLabel: string }) {
  if (status === "ready") return <p className="mt-4 text-[11px] text-dim">Source: scan “{safeLabel(scanLabel, 48)}” (stored backend data)</p>;
  if (status === "demo") return <p className="mt-4 inline-block rounded border border-sev-medium/50 px-2 py-0.5 text-[11px] text-sev-medium">Illustrative Example · not scan data</p>;
  if (status === "loading") return <p className="mt-4 text-[11px] text-dim" role="status">Loading scan data…</p>;
  if (status === "error") return <p className="mt-4 text-[11px] text-sev-high" role="alert">{UNAVAILABLE}: the scan data could not be loaded.</p>;
  return <p className="mt-4 text-[11px] text-dim">No scan has been performed.</p>;
}

/** Count-up to the real score; subscribes to an integer percentage only, so it re-renders at most 100 times over the section. */
function RiskNumber({ score, motion }: { score: number; motion: boolean }) {
  const pct = useStory((s) => (s.index < SECTION_INDEX.risk ? 0 : s.index > SECTION_INDEX.risk ? 100 : Math.round(s.local * 100)));
  const shown = motion ? Math.round(score * Math.min(1, pct / 20)) : Math.round(score);
  return <span aria-label={`Risk score ${Math.round(score)} out of 100`} className="tabular-nums">{shown}</span>;
}

/** THREAT → ISOLATE → REMEDIATE → VERIFY, reached only as far as backend tracking and verification actually support. */
function Flow({ data }: { data: StoryData }) {
  const t = (data.verifyFinding ?? data.topFinding)?.triage_status;
  const reached = data.verify.state === "resolved" ? 3 : t === "in_progress" ? 2 : t === "acknowledged" ? 1 : data.topFinding ? 0 : -1;
  return (
    <ol className="mt-3 flex flex-wrap gap-1.5 font-mono text-[10.5px] uppercase tracking-wider" aria-label="Remediation progress">
      {["Threat", "Isolate", "Remediate", "Verify"].map((x, i) => <li key={x} className={cn("rounded border px-2 py-0.5", i <= reached ? "border-brand/60 text-brand" : "border-line text-dim")} aria-current={i === reached ? "step" : undefined}>{x}</li>)}
    </ol>
  );
}

function schemaOf(data: StoryData, f: Finding): string {
  const tool = data.scan.tools.find((t) => f.affected_tools.includes(t.name));
  if (!tool) return UNAVAILABLE;
  const props = Object.keys(((tool.input_schema as { properties?: Record<string, unknown> }).properties) ?? {});
  return props.length ? `inputs: ${props.slice(0, 6).map((x) => safeLabel(x, 20)).join(", ")}` : "No input schema declared";
}

const STATE_COPY = {
  resolved: { label: "RESOLVED", cls: "border-ok/60 text-ok" },
  still_present: { label: "STILL PRESENT", cls: "border-sev-high/60 text-sev-high" },
  not_verified: { label: "NOT VERIFIED", cls: "border-line text-dim" },
} as const;

function PathSteps({ data, motion, onFocusTool }: { data: StoryData; motion: boolean; onFocusTool?: (n: string) => void }) {
  const n = data.topPath?.nodes.length ?? 0;
  const active = useStory((s) => (s.index !== SECTION_INDEX.path || n === 0 ? -1 : Math.min(n - 1, Math.floor(s.local * n))));
  const path = data.topPath;
  if (!path) return <p className="text-dim">{data.analysis ? "ATTACK PATH NOT VERIFIED. No attack path was derived for this scan." : "Attack path data unavailable."}</p>;
  return (
    <>
      <ol className="space-y-2" aria-label="Suspected attack path stages">
        {path.nodes.map((nd, i) => (
          <li key={`${nd.stage}-${i}`} onClick={() => nd.tools[0] && onFocusTool?.(nd.tools[0])} className={cn(nd.tools[0] && onFocusTool && "cursor-pointer", "rounded-lg border p-2.5 transition-colors motion-reduce:transition-none", motion && i === active ? "border-brand bg-brand/10" : "border-line/70 bg-bg/40")}>
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-brand">{humanize(nd.stage)}</span>
              <span className={cn("rounded border px-1.5 text-[10.5px]", nd.status === "evidenced" ? "border-sev-high/60 text-sev-high" : "border-line text-dim")}>{nd.status === "evidenced" ? "Evidenced" : nd.status === "potential" ? "Potential" : "Not observed"}</span>
            </div>
            <div className="mt-0.5 text-[13px]">{safeLabel(nd.label, 90)}</div>
            {nd.tools.length > 0 && <div className="mt-0.5 break-words font-mono text-[11px] text-dim">{nd.tools.map((t) => safeLabel(t, 30)).join(", ")}</div>}
          </li>
        ))}
      </ol>
      <Note>Status: suspected path, not a proven exploit. {path.nodes.filter((x) => x.status === "evidenced").length} of {path.nodes.length} stages are backed by evidence{path.missing_stages.length ? `; not observed: ${path.missing_stages.map(humanize).join(", ")}` : ""}.</Note>
    </>
  );
}

export function SectionBody({ id, ctx }: { id: SectionId; ctx: SectionCtx }) {
  const { data, status, motion } = ctx;
  const has = status === "ready" || status === "demo";
  const st = data.stats;
  const f = data.topFinding;
  const prov = <Provenance status={status} scanLabel={data.scan.target_label} />;
  switch (id) {
    case "intro":
      return (
        <>
          <p className="mb-3 font-mono text-[11px] uppercase tracking-[0.22em] text-brand">MCP Pentester · The MCP security layer</p>
          <h1 className="text-balance text-[clamp(34px,6.2vw,76px)] font-semibold leading-[1.02] tracking-tight">SECURE THE MCP ECOSYSTEM</h1>
          <p className="mt-4 max-w-xl text-[clamp(15px,1.5vw,19px)] leading-relaxed text-dim">Automated security testing for Model Context Protocol environments.</p>
          <p className="mt-3 font-mono text-[12.5px] uppercase tracking-[0.2em] text-fg">Discover. Test. Trace. Prove.</p>
          <p className="mt-3 max-w-xl text-[13.5px] leading-relaxed text-dim">Automated discovery. Automated analysis. Evidence-driven security testing.</p>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link to="/scan" className={primary}>Start Security Scan</Link>
            <button type="button" className={ghost} onClick={() => ctx.onGo("ecosystem")}>Explore Platform</button>
          </div>
          <p className="mt-10 font-mono text-[10.5px] uppercase tracking-[0.3em] text-dim" aria-hidden>Scroll to explore ↓</p>
          <p className="sr-only">Scroll to explore</p>
        </>
      );
    case "ecosystem":
      return (
        <>
          <Kicker n={2}>Ecosystem</Kicker>
          <h2 className="text-balance text-[clamp(26px,3.6vw,46px)] font-semibold leading-tight">Your MCP environment isn't just a collection of tools.</h2>
          <p className="mt-3 text-[clamp(22px,3vw,38px)] font-semibold leading-tight text-brand">It's an attack surface.</p>
          <Note>An MCP server hands an AI agent tools, each with a description, a schema and the power to act. Anything an agent can read or call can steer it.</Note>
        </>
      );
    case "discovery":
      return (
        <>
          <Kicker n={3}>Discovery</Kicker>
          <h2 className="text-[clamp(24px,3vw,38px)] font-semibold leading-tight">DISCOVER THE ATTACK SURFACE</h2>
          <p className="mt-3 text-[14px] leading-relaxed text-dim">Every tool, found and read. The scanner connects to the server and reads each tool's name, description, input schema and annotations, then infers what each tool can do: network, files, shell, credentials.</p>
          <div className="mt-4 grid grid-cols-2 gap-3"><Metric label="Tools discovered" value={st.tools} ok={has} /><Metric label="Resources & prompts" value="Not analysed" ok /></div>
          {prov}
        </>
      );
    case "surface":
      return (
        <>
          <Kicker n={4}>Attack surface</Kicker>
          <h2 className="text-[clamp(24px,3vw,38px)] font-semibold leading-tight">EVERY CAPABILITY CHANGES THE RISK</h2>
          <div className="mt-4 grid grid-cols-2 gap-3">
            <Metric label="Tools discovered" value={st.tools} ok={has} />
            <Metric label="Network-enabled tools" value={st.networkTools} ok={has} />
            <Metric label="Filesystem-enabled tools" value={st.filesystemTools} ok={has} />
            <Metric label="Potential high-risk relationships (suspected attack paths)" value={st.paths} ok={has && !!data.analysis} />
          </div>
          {prov}
        </>
      );
    case "testing": {
      const stages = has && data.scan.events.length ? deriveStages(data.scan.events, data.scan.status) : [];
      return (
        <>
          <Kicker n={5}>Security testing</Kicker>
          <h2 className="text-[clamp(24px,3vw,38px)] font-semibold leading-tight">{stages.some((x) => x.state === "active") ? "ANALYZING" : "ANALYSIS"}</h2>
          {stages.length > 0 ? (
            <ul className="mt-3 space-y-1 font-mono text-[12px]" aria-label="Recorded scan stages">
              {stages.map((x) => <li key={x.id} className="flex items-baseline gap-2"><span className="shrink-0">{x.label}</span><span className="min-w-4 flex-1 overflow-hidden whitespace-nowrap text-dim" aria-hidden>{" ".padEnd(60, ".")}</span><span className={cn("shrink-0", x.state === "done" ? "text-ok" : x.state === "failed" ? "text-sev-high" : x.state === "active" ? "text-brand" : "text-dim")}>{x.state === "done" ? "COMPLETE" : x.state === "active" ? "ANALYZING" : x.state === "failed" ? "FAILED" : "NOT RUN"}</span></li>)}
            </ul>
          ) : <p className="mt-3 text-[13px] text-dim">{has ? "No stage events were recorded for this scan." : "No scan has been performed."}</p>}
          {data.testSummary.length > 0 && (
            <ul className="mt-3 space-y-1.5 text-[12.5px]" aria-label="Dynamic tests run in this scan">
              {data.testSummary.slice(0, 5).map((t) => <li key={t.name} className="flex justify-between gap-3 border-b border-line/50 pb-1"><span className="min-w-0 truncate">{humanize(t.name)}</span><span className="shrink-0 font-mono text-dim">{t.failed} failed · {t.passed} passed{t.other ? ` · ${t.other} other` : ""}</span></li>)}
            </ul>
          )}
          <Note>The scanning field in the scene is a scroll-driven illustration. The stage list above is the scan's recorded state.</Note>
          {prov}
        </>
      );
    }
    case "threat":
      return (
        <>
          <Kicker n={6}>Threat</Kicker>
          <h2 className="text-[clamp(26px,3.6vw,46px)] font-semibold leading-tight text-sev-high">THREAT DETECTED</h2>
          {f ? (
            <>
              <p className="mt-2 text-[15px]">Something is wrong. Suspicious tool behavior detected.</p>
              <dl className="mt-4 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1.5 text-[13px]">
                <dt className="text-dim">Severity</dt><dd><SeverityBadge severity={f.severity} /> <span className="sr-only">{SEV_LABEL[f.severity]}</span></dd>
                <dt className="text-dim">Category</dt><dd>{humanize(f.category)}</dd>
                <dt className="text-dim">Affected tool</dt><dd className="break-words font-mono text-[12px]">{f.affected_tools.map((t) => safeLabel(t, 40)).join(", ") || "none recorded"}</dd>
                <dt className="text-dim">Confidence</dt><dd>{f.confidence ? humanize(f.confidence) : UNAVAILABLE}</dd>
                <dt className="text-dim">Evidence available</dt><dd>{f.evidence.length > 0 ? `Yes, ${f.evidence.length} block${f.evidence.length > 1 ? "s" : ""}` : "No evidence blocks recorded"}</dd>
              </dl>
              <p className="mt-3 text-[13px]">{safeLabel(f.title, 140)}</p>
              <button type="button" className={`${ghost} mt-4`} onClick={() => ctx.onInvestigate(f)}>Investigate this finding</button>
            </>
          ) : <p className="mt-2 text-[14px] text-dim">{has ? "No threat was reported by this scan." : status === "loading" ? "Loading scan data…" : "No scan has been performed."}</p>}
          {prov}
        </>
      );
    case "path":
      return (
        <>
          <Kicker n={7}>Attack path</Kicker>
          <h2 className="text-[clamp(24px,3vw,38px)] font-semibold leading-tight">FOLLOW THE PATH</h2>
          <p className="mb-2 mt-1 text-[14px] text-dim">From entry point to potential impact.</p>
          {has && (!data.topPath || data.topPath.nodes.some((x) => x.status !== "evidenced")) && <p className="mb-3 inline-block rounded border border-sev-medium/50 px-2 py-0.5 font-mono text-[11px] uppercase tracking-wider text-sev-medium" data-testid="path-not-verified">Attack path not verified</p>}
          {has ? <PathSteps data={data} motion={motion} onFocusTool={ctx.onFocusTool} /> : <p className="text-[14px] text-dim">{status === "loading" ? "Loading scan data…" : "No scan has been performed."}</p>}
          {prov}
        </>
      );
    case "evidence": {
      const ev = f?.evidence[0];
      const test = f ? data.scan.tests.find((t) => f.affected_tools.includes(t.tool_name) && t.status === "failed") ?? null : null;
      const field = (k: string, v: ReactNode) => <><dt className="text-dim">{k}</dt><dd className="min-w-0 break-words font-mono text-[11.5px]">{v}</dd></>;
      return (
        <>
          <Kicker n={8}>Evidence</Kicker>
          <h2 className="text-[clamp(24px,3vw,38px)] font-semibold leading-tight">Unaltered evidence.</h2>
          <p className="mb-3 mt-1 text-[14px] text-dim">What the scanner recorded, shown as stored and rendered as plain text.</p>
          {f ? (
            <dl className="mb-3 grid grid-cols-[auto,1fr] gap-x-4 gap-y-1 text-[12px]" data-testid="evidence-fields">
              {field("FINDING", safeLabel(f.title, 100))}
              {field("TOOL", f.affected_tools.map((t) => safeLabel(t, 30)).join(", ") || UNAVAILABLE)}
              {field("TEST TYPE", test ? humanize(test.test_name) : ev ? humanize(ev.kind) : UNAVAILABLE)}
              {field("INPUT", test && Object.keys(test.evidence).length ? safeLabel(JSON.stringify((test.evidence as Record<string, unknown>).payload ?? (test.evidence as Record<string, unknown>).input ?? "not recorded"), 90) : "Not recorded")}
              {field("RESPONSE", test ? safeLabel(test.detail || "Not recorded", 120) : "Not recorded")}
              {field("SCHEMA", schemaOf(data, f))}
              {field("SOURCE", f.detector_sources.map((x) => safeLabel(x, 24)).join(", ") || UNAVAILABLE)}
              {field("TIMESTAMP", data.scan.completed_at ? fmtDateTime(data.scan.completed_at) : data.scan.created_at && data.source === "scan" ? fmtDateTime(data.scan.created_at) : UNAVAILABLE)}
            </dl>
          ) : null}
          {ev ? <CodeViewer value={ev.detail} language="json" title={`Evidence · ${safeLabel(ev.summary, 60)}`} maxHeight={150} /> : <p className="text-[14px] text-dim">{has ? "The top finding has no evidence blocks recorded." : "NO SCAN DATA AVAILABLE"}</p>}
          <div className="mt-4 rounded-lg border border-line/70 bg-bg/40 p-3"><UnicodeVisual hidden={has ? data.hiddenCharTool : null} /></div>
          {prov}
        </>
      );
    }
    case "risk":
      return (
        <>
          <Kicker n={9}>Risk</Kicker>
          <h2 className="text-[clamp(24px,3vw,38px)] font-semibold leading-tight">One number, fully explained.</h2>
          {st.riskScore == null ? <p className="mt-4 text-[15px] text-dim">RISK SCORE<br /><span className="font-semibold text-fg">DATA UNAVAILABLE</span><br />Run a security scan to calculate risk. <span className="sr-only">Risk score unavailable.</span></p> : (
            <>
              <div className="mt-4 flex items-baseline gap-3"><span className="text-[64px] font-semibold leading-none"><RiskNumber score={st.riskScore} motion={motion} /></span><span className="text-[13px] text-dim">/ 100 · {st.band}</span></div>
              <ul className="mt-4 space-y-1 text-[12.5px]" aria-label="Risk score components">
                {data.riskParts.map((p) => <li key={p.label} className="flex justify-between border-b border-line/50 pb-1"><span>{p.label}</span><span className="font-mono text-dim">{p.points == null ? UNAVAILABLE : `${p.points > 0 && p.label.startsWith("Confidence") ? "+" : ""}${p.points}${p.cap != null ? ` / ${p.cap}` : ""}`}</span></li>)}
              </ul>
            </>
          )}
          {prov}
        </>
      );
    case "remediation": {
      const v = data.verifyFinding ?? f;
      return (
        <>
          <Kicker n={10}>Remediation</Kicker>
          <h2 className="text-[clamp(24px,3vw,38px)] font-semibold leading-tight">{data.verify.state === "resolved" ? "REMEDIATION VERIFIED" : "REMEDIATION NOT VERIFIED"}</h2>
          <p className="mt-1 text-[12px] text-dim">Remediation recommended.</p>
          <Flow data={data} />
          {v ? (
            <>
              <p className="mt-3 text-[13px] leading-relaxed">{v.remediation ? safeLabel(v.remediation, 420) : "The scanner recorded no remediation text for this finding."}</p>
              <p className="mt-3 text-[12px] text-dim">Tracked status: <span className="text-fg">{humanize(v.triage_status)}</span>. A fix is only counted once a later scan confirms it.</p>
            </>
          ) : <p className="mt-3 text-[14px] text-dim">{has ? "Nothing to remediate: this scan reported no findings." : "No scan has been performed."}</p>}
          {prov}
        </>
      );
    }
    case "verify": {
      const s = STATE_COPY[data.verify.state];
      return (
        <>
          <Kicker n={11}>Verify</Kicker>
          <h2 className="text-[clamp(26px,3.6vw,46px)] font-semibold leading-tight">TEST AGAIN</h2>
          {has ? (
            <>
              <p className={cn("mt-4 inline-block rounded-md border px-3 py-1 font-mono text-[14px] font-semibold tracking-wider", s.cls)} data-testid="verify-state">{s.label}</p>
              <p className="mt-3 text-[13px] leading-relaxed text-dim">{data.verify.detail}</p>
              <Link to="/scan" className={`${ghost} mt-4`}>Run a verification scan</Link>
            </>
          ) : <p className="mt-3 text-[14px] text-dim">{status === "loading" ? "Loading scan data…" : "NOT VERIFIED. No scan has been performed."}</p>}
          {prov}
        </>
      );
    }
    case "final":
      return (
        <>
          <Kicker n={12}>Your turn</Kicker>
          <h2 className="text-balance text-[clamp(28px,4.4vw,56px)] font-semibold leading-[1.05]">KNOW YOUR MCP ATTACK SURFACE</h2>
          <div className="mt-7 flex flex-wrap gap-3">
            <Link to="/scan" className={primary}>Start Scan</Link>
            <Link to="/" className={ghost}>Open Dashboard</Link>
            <Link to="/about" className={ghost}>View Documentation</Link>
          </div>
          <Link to="/scan" className="mt-8 inline-block font-mono text-[12px] uppercase tracking-[0.28em] text-brand underline-offset-4 hover:underline focus-visible:underline">START YOUR SECURITY SCAN →</Link>
        </>
      );
  }
}
