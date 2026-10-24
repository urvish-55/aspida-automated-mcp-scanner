import { ChevronDown, ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Cell, Line, LineChart, Pie, PieChart, ResponsiveContainer, Tooltip as RTip, XAxis, YAxis } from "recharts";
import { useNavigate } from "react-router-dom";
import { MiniBar, RiskGauge } from "../components/RiskGauge";
import { ScanPicker } from "../components/ScanPicker";
import { ContextLoader, EmptyState, PageHeader } from "../components/ui";
import { useActiveScan, useAnalysis, useScanDetail, useScans } from "../state/queries";
import { cn, humanize, SEV_HEX_VAR, SEV_TEXT, SEVERITIES } from "../lib/utils";

interface Breakdown {
  formula_version?: string; formula?: string; total?: number; total_before_clamp?: number; band?: string;
  static?: { findings_scored: number; raw_points: number; cap: number; subtotal: number };
  dynamic?: { findings_scored: number; raw_points: number; cap: number; subtotal: number };
  capability?: { dangerous_combinations_seen: number; strongest_severity: string | null; raw_points: number; cap: number; subtotal: number };
  confidence_adjustment?: { average_confidence_weight: number | null; adjustment_points: number; rule: string };
  dynamic_context?: { requests_sent?: number; note?: string };
}

function Row({ label, points, detail, open: o }: { label: string; points: string; detail: string; open?: boolean }) {
  const [open, setOpen] = useState(!!o);
  return (
    <li className="border-b border-line/60 last:border-0">
      <button className="flex w-full items-center gap-2 py-2.5 text-left" onClick={() => setOpen((x) => !x)} aria-expanded={open}>
        {open ? <ChevronDown className="h-4 w-4 text-dim" /> : <ChevronRight className="h-4 w-4 text-dim" />}<span className="flex-1 font-medium">{label}</span><span className="tabular-nums font-semibold">{points}</span>
      </button>
      {open && <p className="pb-3 pl-6 text-[13px] text-dim">{detail}</p>}
    </li>
  );
}

export default function RiskAnalysis() {
  const nav = useNavigate();
  const { scan, loading } = useActiveScan();
  const detail = useScanDetail(scan?.id);
  const analysis = useAnalysis(scan?.id);
  const scans = useScans(200);
  const findings = useMemo(() => (detail.data?.findings ?? []).filter((f) => f.status !== "informational" && f.category !== "engine" && !["not_tested", "not_applicable", "error"].includes(f.status)), [detail.data]);
  const sev = SEVERITIES.map((s) => ({ name: s, value: findings.filter((f) => f.severity === s).length })).filter((d) => d.value > 0);
  const cats = useMemo(() => { const m = new Map<string, number>(); findings.forEach((f) => m.set(f.category, (m.get(f.category) ?? 0) + 1)); return [...m].map(([name, value]) => ({ name, value })).sort((a, b) => b.value - a.value); }, [findings]);
  const timeline = (scans.data?.items ?? []).filter((s) => s.status === "completed" && s.risk_score != null).sort((a, b) => a.created_at.localeCompare(b.created_at)).map((s) => ({ id: s.id, label: new Date(s.created_at).toLocaleDateString([], { month: "short", day: "numeric" }) + " " + new Date(s.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), risk: s.risk_score as number }));
  const b = (scan?.risk_breakdown ?? null) as Breakdown | null;

  if (loading) return <ContextLoader message="Loading scans…" />;
  if (!scan) return <div><PageHeader title="Risk analysis" /><EmptyState title="No scans yet." body="Run your first MCP security scan to begin analyzing tools and capabilities." action={{ label: "Start New Scan", to: "/scan" }} /></div>;

  return (
    <div>
      <PageHeader title="Risk analysis" sub="How the score is built, where the risk is, and how it changes between scans." actions={<ScanPicker />} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[320px_minmax(0,1fr)]">
        <section className="card flex flex-col items-center p-6" aria-label="Overall risk"><RiskGauge score={scan.risk_score} size={240} label="Overall risk" /><p className="mt-4 text-center text-[12.5px] text-dim">{b?.formula_version ? `Formula ${b.formula_version}. ` : ""}A prioritization aid, not a probability. A low score is not proof of safety.</p></section>

        <section className="card p-5" aria-label="Score explanation">
          <h2 className="mb-1 font-semibold">Score explanation</h2>
          {!b ? <p className="text-dim">This scan has no stored score breakdown (it did not complete).</p> : (
            <>
              <ul>
                <Row open label="Static evidence" points={`+${b.static?.subtotal ?? 0} / ${b.static?.cap ?? 0}`} detail={`${b.static?.findings_scored ?? 0} finding(s) scored for ${b.static?.raw_points ?? 0} raw points, capped at ${b.static?.cap}.`} />
                <Row label="Dynamic evidence" points={`+${b.dynamic?.subtotal ?? 0} / ${b.dynamic?.cap ?? 0}`} detail={`${b.dynamic?.findings_scored ?? 0} confirmed dynamic finding(s). ${b.dynamic_context?.note ?? "Dynamic testing was not run, so it adds nothing; that is not evidence of safety."}`} />
                <Row label="Capability exposure" points={`+${b.capability?.subtotal ?? 0} / ${b.capability?.cap ?? 0}`} detail={`${b.capability?.dangerous_combinations_seen ?? 0} dangerous capability combination(s)${b.capability?.strongest_severity ? `, strongest: ${b.capability.strongest_severity}` : ""}.`} />
                <Row label="Confidence" points={`${(b.confidence_adjustment?.adjustment_points ?? 0) >= 0 ? "+" : ""}${b.confidence_adjustment?.adjustment_points ?? 0}`} detail={`Average evidence confidence weight ${b.confidence_adjustment?.average_confidence_weight ?? "n/a"}. ${b.confidence_adjustment?.rule ?? ""}`} />
                <Row label="Affected surface" points={`${analysis.data?.tools.filter((t) => t.finding_count > 0).length ?? 0} / ${analysis.data?.tools.length ?? 0} tools`} detail="Tools with at least one finding. Shown for context; the surface does not change the formula." />
              </ul>
              <div className="mt-3 flex items-center justify-between rounded-lg bg-raised px-3 py-2"><span className="font-medium">Total (clamped 0-100)</span><span className="text-lg font-semibold tabular-nums">{b.total} <span className="text-[12px] font-normal text-dim">before clamp {b.total_before_clamp}</span></span></div>
            </>
          )}
        </section>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="card p-4"><h2 className="mb-2 font-semibold">Severity distribution</h2>
          {sev.length === 0 ? <p className="py-10 text-center text-dim">No scored findings.</p> : (
            <div role="img" aria-label={`Severity distribution: ${sev.map((s) => `${s.value} ${s.name}`).join(", ")}`} className="h-64">
              <ResponsiveContainer><PieChart><Pie data={sev} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90} paddingAngle={2} onClick={(d) => nav(`/findings?scan=${scan.id}&severity=${(d as { name: string }).name}`)} className="cursor-pointer">{sev.map((s) => <Cell key={s.name} fill={SEV_HEX_VAR[s.name]} stroke="hsl(var(--panel))" />)}</Pie><RTip contentStyle={{ background: "hsl(var(--raised))", border: "1px solid hsl(var(--line))", borderRadius: 8 }} /></PieChart></ResponsiveContainer>
            </div>
          )}
          <div className="flex flex-wrap justify-center gap-3 text-[12px]">{sev.map((s) => <button key={s.name} className="chip hover:border-brand/60" onClick={() => nav(`/findings?scan=${scan.id}&severity=${s.name}`)}><span className="h-2 w-2 rounded-full" style={{ background: SEV_HEX_VAR[s.name] }} /> {s.name} {s.value}</button>)}</div>
        </section>
        <section className="card p-4"><h2 className="mb-2 font-semibold">Risk categories</h2>
          {cats.length === 0 ? <p className="py-10 text-center text-dim">No scored findings.</p> : (
            <div role="img" aria-label={`Findings per category: ${cats.map((c) => `${humanize(c.name)} ${c.value}`).join(", ")}`} className="h-64">
              <ResponsiveContainer><BarChart data={cats.map((c) => ({ ...c, label: humanize(c.name) }))} layout="vertical" margin={{ left: 20 }}><CartesianGrid horizontal={false} stroke="hsl(var(--line))" /><XAxis type="number" allowDecimals={false} stroke="hsl(var(--dim))" fontSize={11} /><YAxis type="category" dataKey="label" width={110} stroke="hsl(var(--dim))" fontSize={11} /><RTip cursor={{ fill: "hsl(var(--raised))" }} contentStyle={{ background: "hsl(var(--raised))", border: "1px solid hsl(var(--line))", borderRadius: 8 }} /><Bar dataKey="value" fill="hsl(var(--brand))" radius={[0, 4, 4, 0]} className="cursor-pointer" onClick={(d) => nav(`/findings?scan=${scan.id}&category=${(d as unknown as { name: string }).name}`)} /></BarChart></ResponsiveContainer>
            </div>
          )}
        </section>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <section className="card p-4"><h2 className="mb-3 font-semibold">Risk by tool</h2>
          {!analysis.data || analysis.data.tools.length === 0 ? <p className="py-6 text-dim">No tools recorded.</p> : (
            <ol className="space-y-2.5">{analysis.data.tools.slice(0, 12).map((t, i) => (
              <li key={t.name}><button className="block w-full rounded-md px-1 py-0.5 text-left transition hover:bg-raised" onClick={() => nav(`/tools?scan=${scan.id}&tool=${encodeURIComponent(t.name)}`)}>
                <div className="flex items-center justify-between"><span className="mono"><span className="mr-2 text-dim">{i + 1}.</span>{t.name}</span><span className={cn("tabular-nums font-semibold", SEV_TEXT[t.exposure.band])}>{t.exposure.score}</span></div><MiniBar value={t.exposure.score} sev={t.exposure.band} /></button></li>
            ))}</ol>
          )}
          <p className="mt-3 text-[11.5px] text-dim">{analysis.data?.exposure_note}</p>
        </section>
        <section className="card p-4"><h2 className="mb-2 font-semibold">Risk timeline</h2>
          {timeline.length < 2 ? <p className="py-10 text-center text-dim">A timeline needs at least two completed scans. {timeline.length} so far.</p> : (
            <div role="img" aria-label={`Risk score across ${timeline.length} scans`} className="h-64"><ResponsiveContainer><LineChart data={timeline}><CartesianGrid stroke="hsl(var(--line))" /><XAxis dataKey="label" stroke="hsl(var(--dim))" fontSize={11} /><YAxis domain={[0, 100]} stroke="hsl(var(--dim))" fontSize={11} /><RTip contentStyle={{ background: "hsl(var(--raised))", border: "1px solid hsl(var(--line))", borderRadius: 8 }} /><Line type="monotone" dataKey="risk" stroke="hsl(var(--brand))" strokeWidth={2} dot={{ r: 4, className: "cursor-pointer" }} activeDot={{ r: 6, onClick: (_e, p) => nav(`/scans/${(p as unknown as { payload: { id: string } }).payload.id}`) }} /></LineChart></ResponsiveContainer></div>
          )}
        </section>
      </div>
    </div>
  );
}
