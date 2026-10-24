import { useMutation, useQuery } from "@tanstack/react-query";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, ArrowLeft, ArrowRight, Boxes, Check, FileUp, Globe, Lock, Play, Server, ShieldCheck } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type ElementType, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { ContextLoader, ErrorState, PageHeader, Pill } from "../components/ui";
import { api, type NewScanInput } from "../services/api";
import { cn, humanize } from "../lib/utils";
import { useHealth } from "../state/queries";

const AUTH_STATEMENT = "I confirm that I am authorized to test this MCP server.";
const STEPS = ["Select target", "Discover", "Security tests", "Safety", "Review & start"] as const;

type Kind = "upload" | "url" | "local" | "docker";
const EXAMPLE = `{
  "mcpServers": {
    "my-server": {
      "command": "npx",
      "args": ["-y", "@example/mcp-server"],
      "tools": [
        {
          "name": "get_weather",
          "description": "Get the current weather for a city.",
          "inputSchema": { "type": "object", "properties": { "city": { "type": "string", "maxLength": 100 } }, "required": ["city"] }
        }
      ]
    }
  }
}`;

interface TargetCard { kind: Kind; title: string; body: string; icon: ElementType }
const CARDS: TargetCard[] = [
  { kind: "upload", title: "Upload MCP configuration", body: "A JSON config, manifest or tool list. Nothing in it is executed.", icon: FileUp },
  { kind: "url", title: "Connect to MCP server", body: "A live HTTP endpoint. Required for dynamic testing.", icon: Globe },
  { kind: "local", title: "Local test server", body: "The bundled deliberately-vulnerable fixture (synthetic demo data).", icon: Server },
  { kind: "docker", title: "Docker test server", body: "The same fixture, run through docker compose.", icon: Boxes },
];

interface TestDef { id: string; label: string; risk: "passive" | "live" | "llm" | "advisory"; blurb: string; state: "on" | "locked" | "unavailable"; flag?: "dynamic" | "semantic" }
const TESTS: TestDef[] = [
  { id: "unicode", label: "Unicode analysis", risk: "passive", state: "locked", blurb: "Hidden, bidirectional and look-alike characters in names and descriptions." },
  { id: "poison", label: "Tool poisoning", risk: "passive", state: "locked", blurb: "Agent-directed instructions, concealment and exfiltration wording in metadata." },
  { id: "schema", label: "Schema analysis", risk: "passive", state: "locked", blurb: "Unconstrained path, command, URL and SQL-like parameters." },
  { id: "capability", label: "Capability analysis", risk: "passive", state: "locked", blurb: "Inferred capabilities and dangerous capability combinations." },
  { id: "collision", label: "Name collision analysis", risk: "passive", state: "locked", blurb: "Look-alike and shadowed tool names." },
  { id: "dynamic", label: "Dynamic input testing", risk: "live", state: "on", flag: "dynamic", blurb: "Sends inert, bounded probes to the live server: path traversal sentinels, echo markers, size limits, malformed input." },
  { id: "injection", label: "Injection testing", risk: "live", state: "locked", blurb: "Command-marker probes. Runs as part of dynamic input testing, never executes anything on its own." },
  { id: "ssrf", label: "SSRF testing", risk: "live", state: "unavailable", blurb: "Not implemented in this scanner version." },
  { id: "semantic", label: "Semantic analysis", risk: "llm", state: "on", flag: "semantic", blurb: "Optional LLM review of findings. Annotates only; never overrides rules. Needs an LLM provider." },
  { id: "ml", label: "ML risk analysis", risk: "advisory", state: "locked", blurb: "Advisory prioritisation from the trained model, when one exists. Never creates or removes findings." },
];

const RISK_PILL: Record<TestDef["risk"], { tone: "ok" | "warn" | "brand" | "neutral"; text: string }> = {
  passive: { tone: "ok", text: "Passive · no network" },
  live: { tone: "warn", text: "Sends live requests" },
  llm: { tone: "brand", text: "Uses LLM provider" },
  advisory: { tone: "neutral", text: "Advisory" },
};

function Stepper({ step, max, onGo }: { step: number; max: number; onGo: (i: number) => void }) {
  return (
    <ol className="mb-6 flex flex-wrap items-center gap-2" aria-label="Scan setup steps">
      {STEPS.map((s, i) => {
        const done = i < step;
        const active = i === step;
        return (
          <li key={s} className="flex items-center gap-2">
            <button disabled={i > max} onClick={() => onGo(i)} aria-current={active ? "step" : undefined}
              className={cn("flex items-center gap-2 rounded-full border px-3 py-1.5 text-[12.5px] transition", active ? "border-brand bg-brand/10 text-fg" : done ? "border-ok/40 text-ok" : "border-line text-dim", i > max && "opacity-40")}>
              <span className={cn("grid h-5 w-5 place-items-center rounded-full text-[11px] font-bold", active ? "bg-brand text-bg" : done ? "bg-ok/20" : "bg-raised")}>{done ? <Check className="h-3 w-3" /> : i + 1}</span>
              {s}
            </button>
            {i < STEPS.length - 1 && <span className="h-px w-5 bg-line" aria-hidden />}
          </li>
        );
      })}
    </ol>
  );
}

function Panel({ children }: { children: ReactNode }) {
  return <motion.div initial={{ opacity: 0, x: 12 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -12 }} transition={{ duration: 0.16 }}>{children}</motion.div>;
}

export default function NewScan() {
  const nav = useNavigate();
  const health = useHealth();
  const [step, setStep] = useState(0);
  const [maxStep, setMaxStep] = useState(0);
  const [kind, setKind] = useState<Kind | null>(null);
  const [configText, setConfigText] = useState("");
  const [uploaded, setUploaded] = useState<{ name: string; stored: string; size: number } | null>(null);
  const [url, setUrl] = useState("");
  const [dynamic, setDynamic] = useState(false);
  const [semantic, setSemantic] = useState(false);
  const [safeMode, setSafeMode] = useState(true);
  const [authorized, setAuthorized] = useState(false);
  const [uploadErr, setUploadErr] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const isUrl = kind === "url" || kind === "local" || kind === "docker";
  const jsonOk = useMemo(() => { if (!configText.trim()) return null; try { JSON.parse(configText); return true; } catch { return false; } }, [configText]);
  const hasTarget = isUrl ? /^https?:\/\//i.test(url) : !!uploaded || jsonOk === true;
  const lockedSafe = health.data?.safe_mode_default ?? true;

  const goto = (i: number) => { setStep(i); setMaxStep((m) => Math.max(m, i)); };
  const pick = (k: Kind) => {
    setKind(k);
    if (k === "local") setUrl("http://127.0.0.1:8101/mcp");
    else if (k === "docker") setUrl("http://127.0.0.1:8101/mcp");
    else if (k === "url") setUrl((u) => (u.startsWith("http://127.") ? "" : u));
  };

  const upload = useMutation({
    mutationFn: (f: File) => api.uploadConfig(f),
    onSuccess: (r, f) => { setUploaded({ name: f.name, stored: r.stored_filename, size: r.size_bytes }); setConfigText(""); setUploadErr(""); },
    onError: (e) => { setUploaded(null); setUploadErr((e as Error).message); },
  });

  const discoverBody = uploaded ? { uploaded_file: uploaded.stored } : jsonOk ? { target_config: configText } : null;
  const discover = useQuery({
    queryKey: ["discover", uploaded?.stored, jsonOk ? configText : null],
    queryFn: () => api.discover(discoverBody as { uploaded_file?: string; target_config?: unknown }),
    enabled: step === 1 && !isUrl && !!discoverBody,
    retry: false,
  });

  const create = useMutation({
    mutationFn: () => {
      const body: NewScanInput = {
        target_type: isUrl ? "url" : "config",
        safe_mode: safeMode,
        dynamic_enabled: dynamic && isUrl,
        semantic_enabled: semantic,
        authorization_confirmed: dynamic && isUrl ? authorized : false,
      };
      if (isUrl) body.server_url = url.trim();
      else if (uploaded) body.uploaded_file = uploaded.stored;
      else body.target_config = JSON.parse(configText);
      return api.createScan(body);
    },
    onSuccess: (s) => nav(`/scans/${s.id}`),
  });

  useEffect(() => { if (!isUrl) setDynamic(false); }, [isUrl]);
  const canStart = hasTarget && (!dynamic || authorized) && !create.isPending;

  const next = () => goto(Math.min(STEPS.length - 1, step + 1));
  const stepOk = [hasTarget && !!kind, true, true, !dynamic || authorized, canStart][step];

  return (
    <div>
      <PageHeader title="New scan" sub="Set up a scan step by step. Safe mode is on by default and dynamic testing always needs explicit authorization." />
      <Stepper step={step} max={maxStep} onGo={setStep} />

      <AnimatePresence mode="wait" initial={false}>
        {step === 0 && (
          <Panel key="s0">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4" role="radiogroup" aria-label="Target type">
              {CARDS.map((c) => (
                <button key={c.kind} role="radio" aria-checked={kind === c.kind} onClick={() => pick(c.kind)}
                  className={cn("card flex flex-col items-start gap-2 p-4 text-left transition hover:border-brand/60", kind === c.kind && "border-brand shadow-glow")}>
                  <c.icon className={cn("h-6 w-6", kind === c.kind ? "text-brand" : "text-dim")} aria-hidden />
                  <span className="font-semibold">{c.title}</span><span className="text-[12.5px] text-dim">{c.body}</span>
                </button>
              ))}
            </div>

            {kind === "upload" && (
              <div className="card mt-4 p-4">
                <div className="flex flex-wrap items-center gap-3">
                  <input ref={fileRef} type="file" accept=".json,application/json" className="sr-only" aria-label="Upload MCP configuration file" onChange={(e) => { const f = e.target.files?.[0]; if (f) upload.mutate(f); }} />
                  <button className="btn" onClick={() => fileRef.current?.click()} disabled={upload.isPending}><FileUp className="h-4 w-4" /> {upload.isPending ? "Uploading…" : "Choose JSON file"}</button>
                  {uploaded && <Pill tone="ok"><Check className="h-3 w-3" /> {uploaded.name} · {(uploaded.size / 1024).toFixed(1)} KB stored</Pill>}
                  {uploadErr && <span role="alert" className="text-sev-critical">{uploadErr}</span>}
                </div>
                <div className="my-3 flex items-center gap-3 text-[12px] text-dim"><span className="h-px flex-1 bg-line" /> or paste JSON <span className="h-px flex-1 bg-line" /></div>
                <textarea className="input mono min-h-[180px]" value={configText} onChange={(e) => { setConfigText(e.target.value); setUploaded(null); }} placeholder={EXAMPLE} spellCheck={false} aria-label="MCP configuration JSON" />
                <div className="mt-2 flex items-center gap-3 text-[12px]">
                  {jsonOk === false && <span role="alert" className="text-sev-critical">That is not valid JSON.</span>}
                  {jsonOk === true && <span className="text-ok">Valid JSON.</span>}
                  <button className="btn-ghost ml-auto" onClick={() => { setConfigText(EXAMPLE); setUploaded(null); }}>Load a clean example</button>
                </div>
              </div>
            )}
            {isUrl && (
              <div className="card mt-4 p-4">
                <label className="label" htmlFor="server-url">Server URL</label>
                <input id="server-url" className="input mono mt-1" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://mcp.example.com/mcp" readOnly={kind === "docker"} />
                {kind === "local" && <p className="mt-2 text-[12.5px] text-dim">Start the fixture with <span className="mono">python fixtures/vulnerable_server.py</span> and set <span className="mono">ALLOW_LOCAL_TARGETS=true</span> for the backend. This is synthetic demo data and is labelled <span className="font-bold text-warn">DEMO DATA</span> in the dashboard.</p>}
                {kind === "docker" && <p className="mt-2 text-[12.5px] text-dim">Run <span className="mono">docker compose up --build vulnerable-fixture</span>. If the scanner itself runs in Docker use <span className="mono">http://host.docker.internal:8101/mcp</span> and ALLOW_LOCAL_TARGETS=true.</p>}
                {kind === "url" && <p className="mt-2 text-[12.5px] text-dim">Only scan servers you own or are authorized to test. Private and local addresses are blocked unless the server allows them.</p>}
              </div>
            )}
          </Panel>
        )}

        {step === 1 && (
          <Panel key="s1">
            {isUrl ? (
              <div className="card p-5">
                <h2 className="font-semibold">Discovery happens during the scan</h2>
                <p className="mt-1 text-dim">For live servers the scanner connects once the scan starts, lists the tools, then analyzes them. There is nothing to preview without contacting <span className="mono">{url}</span>, and this setup step never does.</p>
              </div>
            ) : discover.isLoading ? (
              <ContextLoader message="Discovering MCP tools from the configuration…" />
            ) : discover.error ? (
              <ErrorState title="The configuration could not be read" message={(discover.error as Error).message} causes={["the JSON is not an MCP config, manifest or tool list", "the file is empty or too large"]} onRetry={() => void discover.refetch()} />
            ) : discover.data ? (
              <div className="space-y-4">
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
                  {[["Server", discover.data.servers.length], ["Tools", discover.data.tool_count], ["Resources", null], ["Prompts", null], ["Capabilities", Object.keys(discover.data.capabilities).length]].map(([k, v], i) => (
                    <motion.div key={String(k)} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.08 }} className="card p-4">
                      <div className="label">{k}</div>
                      <div className="mt-1 text-2xl font-semibold tabular-nums">{v == null ? <span className="text-dim" title="Not analyzed by this scanner version">n/a</span> : v}</div>
                    </motion.div>
                  ))}
                </div>
                <div className="card p-4">
                  <h3 className="mb-2 font-semibold">Tools found</h3>
                  <ul className="grid max-h-72 gap-1.5 overflow-y-auto sm:grid-cols-2">
                    {discover.data.tools.map((t) => (
                      <li key={`${t.server}-${t.name}`} className="flex items-center justify-between gap-2 rounded-md border border-line px-3 py-1.5">
                        <span className="mono truncate">{t.name}</span>
                        <span className="flex flex-wrap justify-end gap-1">{t.capabilities.map((c) => <Pill key={c}>{humanize(c)}</Pill>)}</span>
                      </li>
                    ))}
                  </ul>
                  {discover.data.issues.length > 0 && <ul className="mt-3 space-y-1 text-[12.5px] text-warn">{discover.data.issues.map((i, k) => <li key={k}>⚠ {i.message}</li>)}</ul>}
                  <p className="mt-3 text-[12px] text-dim">{discover.data.note}</p>
                </div>
              </div>
            ) : <p className="text-dim">Go back and choose a target first.</p>}
          </Panel>
        )}

        {step === 2 && (
          <Panel key="s2">
            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              {TESTS.map((t) => {
                const checked = t.flag === "dynamic" ? dynamic && isUrl : t.flag === "semantic" ? semantic : t.state === "locked";
                const disabled = t.state !== "on" || (t.flag === "dynamic" && !isUrl);
                const toggle = () => { if (t.flag === "dynamic") { setDynamic(!dynamic); if (dynamic) setAuthorized(false); } if (t.flag === "semantic") setSemantic(!semantic); };
                const rp = RISK_PILL[t.risk];
                const note = t.state === "unavailable" ? "Unavailable" : t.flag === "dynamic" && !isUrl ? "Needs a live URL target" : t.state === "locked" ? "Always on" : null;
                return (
                  <label key={t.id} className={cn("card flex cursor-pointer items-start gap-3 p-4 transition", checked && "border-brand/50", disabled && "cursor-not-allowed opacity-70")}>
                    <input type="checkbox" className="mt-1 h-4 w-4 accent-[hsl(var(--brand))]" checked={checked} disabled={disabled} onChange={toggle} aria-label={t.label} />
                    <span className="min-w-0 flex-1">
                      <span className="flex flex-wrap items-center gap-2"><span className="font-semibold">{t.label}</span><Pill tone={rp.tone}>{rp.text}</Pill>{note && <Pill>{note}</Pill>}</span>
                      <span className="mt-1 block text-[12.5px] text-dim">{t.blurb}</span>
                      {t.id === "semantic" && health.data && !health.data.llm_available && <span className="mt-1 block text-[12px] text-warn">No LLM provider is configured, so this will report “unavailable”.</span>}
                      {t.id === "ml" && health.data && <span className="mt-1 block text-[12px] text-dim">{health.data.ml_available ? "A trained model is present." : "No trained model is present, so this will report “unavailable”."}</span>}
                    </span>
                  </label>
                );
              })}
            </div>
          </Panel>
        )}

        {step === 3 && (
          <Panel key="s3">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div className={cn("card p-5", safeMode && "border-ok/50")}>
                <div className="flex items-center gap-3">
                  <ShieldCheck className={cn("h-8 w-8", safeMode ? "text-ok" : "text-sev-critical")} aria-hidden />
                  <div><div className="label">Safe mode</div><div className={cn("text-3xl font-bold", safeMode ? "text-ok" : "text-sev-critical")}>{safeMode ? "ON" : "OFF"}</div></div>
                </div>
                <ul className="mt-4 list-disc space-y-1 pl-5 text-dim">
                  <li>Only inert probes are sent: echo markers, read-only sentinels, bounded sizes.</li>
                  <li>No destructive payloads, no writes, no command execution on the target.</li>
                  <li>A request budget, payload cap and timeout are enforced by the server.</li>
                  <li>Redirects and addresses are re-validated against the SSRF policy.</li>
                </ul>
                <button className="btn mt-4" disabled={lockedSafe} onClick={() => setSafeMode((s) => !s)} aria-pressed={safeMode}>
                  {lockedSafe ? <><Lock className="h-3.5 w-3.5" /> Locked on by server policy</> : safeMode ? "Turn safe mode off" : "Turn safe mode on"}
                </button>
              </div>
              <div className="card p-5">
                <h3 className="font-semibold">Dynamic testing authorization</h3>
                {!dynamic ? <p className="mt-2 text-dim">Dynamic testing is not selected, so nothing is sent to the target and no authorization is needed.</p> : (
                  <>
                    <p className="mt-2 text-dim">Dynamic tests send live requests to <span className="mono">{url || "the target"}</span>. They must be explicitly authorized.</p>
                    <label className="mt-4 flex cursor-pointer items-start gap-3 rounded-lg border border-warn/40 bg-warn/5 p-3">
                      <input type="checkbox" className="mt-1 h-4 w-4 accent-[hsl(var(--brand))]" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
                      <span>{AUTH_STATEMENT}</span>
                    </label>
                  </>
                )}
              </div>
            </div>
          </Panel>
        )}

        {step === 4 && (
          <Panel key="s4">
            <div className="card p-5">
              <h2 className="mb-3 font-semibold">Scan summary</h2>
              <dl className="grid grid-cols-[170px_1fr] gap-y-2 text-[13.5px]">
                <dt className="text-dim">Target</dt><dd className="mono break-all">{isUrl ? url : uploaded ? `${uploaded.name} (uploaded)` : "Pasted JSON configuration"}</dd>
                <dt className="text-dim">Mode</dt><dd>{isUrl ? "Live server (HTTP)" : "Static configuration"}</dd>
                <dt className="text-dim">Static analyzers</dt><dd>Unicode · Poisoning · Schema · Capability · Collision</dd>
                <dt className="text-dim">Dynamic testing</dt><dd>{dynamic && isUrl ? <Pill tone="warn">Enabled, authorized</Pill> : "Off"}</dd>
                <dt className="text-dim">Semantic analysis</dt><dd>{semantic ? "Requested" : "Off"}</dd>
                <dt className="text-dim">Safe mode</dt><dd>{safeMode ? <Pill tone="ok">ON</Pill> : <Pill tone="bad">OFF</Pill>}</dd>
              </dl>
              {create.error && <div className="mt-4"><ErrorState title="The scan could not be started" message={(create.error as Error).message} causes={["the target was rejected by the SSRF policy (local addresses need ALLOW_LOCAL_TARGETS=true)", "the configuration is invalid", "the API key was rejected"]} onRetry={() => create.mutate()} /></div>}
              <div className="mt-5 flex items-center gap-3">
                <button className="btn-primary !px-5 !py-2.5 text-[14px]" disabled={!canStart} onClick={() => create.mutate()}><Play className="h-4 w-4" /> {create.isPending ? "Starting…" : "Start scan"}</button>
                {!canStart && !create.isPending && <span className="flex items-center gap-1.5 text-[12.5px] text-warn"><AlertTriangle className="h-3.5 w-3.5" /> {!hasTarget ? "Choose a target first." : "Authorize dynamic testing to continue."}</span>}
              </div>
            </div>
          </Panel>
        )}
      </AnimatePresence>

      <div className="mt-6 flex items-center justify-between">
        <button className="btn" onClick={() => setStep(Math.max(0, step - 1))} disabled={step === 0}><ArrowLeft className="h-4 w-4" /> Back</button>
        {step < STEPS.length - 1 && <button className="btn-primary" onClick={next} disabled={!stepOk}>Continue <ArrowRight className="h-4 w-4" /></button>}
      </div>
    </div>
  );
}
