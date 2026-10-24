import { useMutation } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { ErrorState, PageHeader, Pill } from "../components/ui";
import { safeLabel } from "../lib/safeText";
import { api } from "../services/api";
import { useActiveScan, useScanDetail } from "../state/queries";
import type { UnicodeChar } from "../types";

const MAX = 5000;
const SHOWN_CAP = 400;

/** Glyph cell that can never hide or reorder: non-printing characters are replaced by their code point. */
function glyph(c: UnicodeChar): string {
  if (c.invisible || c.category.startsWith("C") || c.category === "Zs" || c.category === "Zl" || c.category === "Zp") return c.char === " " ? "␠" : `⟦${c.codepoint}⟧`;
  return c.char;
}

export default function UnicodeInspector() {
  const [text, setText] = useState("");
  const [onlySuspicious, setOnlySuspicious] = useState(false);
  const { scan } = useActiveScan();
  const detail = useScanDetail(scan?.id);
  const m = useMutation({ mutationFn: (t: string) => api.inspectUnicode(t) });

  useEffect(() => {
    if (!text) return;
    const t = setTimeout(() => m.mutate(text), 350);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [text]);

  const r = m.data && text ? m.data : null;
  const rows = useMemo(() => {
    if (!r) return [];
    const list = onlySuspicious ? r.chars.filter((c) => c.suspicious) : r.chars;
    return list.slice(0, SHOWN_CAP);
  }, [r, onlySuspicious]);
  const revealed = useMemo(() => (r ? r.chars.map((c) => (c.suspicious && !/^[\x20-\x7e]$/.test(c.char) ? `⟦${c.codepoint}⟧` : c.char)).join("") : ""), [r]);

  return (
    <div>
      <PageHeader title="Unicode Inspector" sub="Paste text, or load a tool description from the selected scan, to see every character's code point, Unicode name, category, script, direction and UTF-8 bytes. Hidden or look-alike characters are flagged." />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.4fr)]">
        <section className="card-pad space-y-3" aria-label="Input">
          <label htmlFor="uni-in" className="label block">Text to inspect ({text.length}/{MAX})</label>
          <textarea id="uni-in" className="input min-h-[160px] font-mono" maxLength={MAX} value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste a tool name or description…" spellCheck={false} />
          {(detail.data?.tools.length ?? 0) > 0 && (
            <div>
              <label htmlFor="uni-tool" className="label mb-1 block">Load from scan “{safeLabel(scan?.target_label ?? "", 30)}”</label>
              <select id="uni-tool" className="input" value="" onChange={(e) => { const t = detail.data?.tools.find((x) => x.name === e.target.value); if (t) setText((t.name + "\n" + t.description).slice(0, MAX)); }}>
                <option value="">Choose a tool…</option>
                {detail.data?.tools.map((t) => <option key={t.name} value={t.name}>{safeLabel(t.name, 50)}</option>)}
              </select>
            </div>
          )}
          <p className="text-[12px] text-dim">Text is sent to your own backend only and is not stored.</p>
        </section>

        <section className="min-w-0 space-y-3" aria-label="Result" aria-live="polite">
          {!text && <div className="card-pad text-dim">Enter text to inspect.</div>}
          {text && m.isPending && !r && <div className="card-pad text-dim" role="status">Inspecting…</div>}
          {m.isError && <ErrorState title="Inspection failed" message={(m.error as Error).message} onRetry={() => m.mutate(text)} />}
          {r && (
            <>
              <div className="card-pad">
                <div className="flex flex-wrap items-center gap-2">
                  <Pill tone={r.suspicious_count ? "warn" : "ok"}>{r.suspicious_count ? `${r.suspicious_count} suspicious character(s)` : "No suspicious characters found"}</Pill>
                  <Pill>{r.length} characters</Pill>
                  {Object.entries(r.summary).map(([k, v]) => <Pill key={k}>{k}: {v}</Pill>)}
                </div>
                <h2 className="label mb-1 mt-3">Text with hidden characters revealed</h2>
                <p className="whitespace-pre-wrap break-words rounded-lg bg-raised p-2 font-mono text-[12.5px]">{revealed.slice(0, 1500)}</p>
                <label className="mt-3 flex items-center gap-2 text-[13px]"><input type="checkbox" checked={onlySuspicious} onChange={(e) => setOnlySuspicious(e.target.checked)} /> Show suspicious characters only</label>
              </div>
              <div className="card overflow-x-auto">
                <table className="w-full min-w-[640px] text-left text-[12.5px]">
                  <caption className="sr-only">Per-character Unicode properties</caption>
                  <thead><tr className="border-b border-line text-dim"><th className="p-2">#</th><th className="p-2">Char</th><th className="p-2">Code point</th><th className="p-2">Unicode name</th><th className="p-2">Category</th><th className="p-2">Script</th><th className="p-2">Bidi</th><th className="p-2">UTF-8</th><th className="p-2">Classification</th></tr></thead>
                  <tbody>
                    {rows.map((c) => (
                      <tr key={c.index} className={c.suspicious ? "border-b border-line bg-sev-high/10" : "border-b border-line/50"}>
                        <td className="p-2 tabular-nums text-dim">{c.index}</td>
                        <td className="p-2 font-mono">{glyph(c)}</td>
                        <td className="p-2 font-mono">{c.codepoint}</td>
                        <td className="p-2">{c.name}</td>
                        <td className="p-2">{c.category} <span className="text-dim">{c.category_label}</span></td>
                        <td className="p-2">{c.script ?? "–"}</td>
                        <td className="p-2">{c.bidi}</td>
                        <td className="p-2 font-mono">{c.utf8}</td>
                        <td className="p-2">{c.suspicious ? <span className="font-medium text-sev-high">⚠ Suspicious: {c.suspicious}</span> : <span className="text-dim">Normal</span>}</td>
                      </tr>
                    ))}
                    {rows.length === 0 && <tr><td colSpan={9} className="p-3 text-dim">No characters to show.</td></tr>}
                  </tbody>
                </table>
                {(onlySuspicious ? r.suspicious_count : r.length) > SHOWN_CAP && <p className="p-2 text-[12px] text-dim">Showing the first {SHOWN_CAP} rows.</p>}
              </div>
              <p className="text-[12px] text-dim">{r.note}</p>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
