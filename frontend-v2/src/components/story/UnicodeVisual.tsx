import { useQuery } from "@tanstack/react-query";
import { api } from "../../services/api";
import { safeLabel } from "../../lib/safeText";

const REFERENCE = { codepoint: "U+200B", name: "ZERO WIDTH SPACE", category: "Cf (format)", script: "Common", bidi: "BN" };

function Row({ r, note }: { r: { codepoint: string; name: string; category: string; script: string | null; bidi: string }; note?: string }) {
  return (
    <tr className="border-t border-line/60">
      <td className="py-1 pr-3 font-mono text-brand">{r.codepoint}</td>
      <td className="py-1 pr-3">{r.name}</td>
      <td className="py-1 pr-3 text-dim">{r.category}</td>
      <td className="py-1 pr-3 text-dim">{r.script ?? "none"}</td>
      <td className="py-1 text-dim">{r.bidi}{note ? <span className="sr-only"> ({note})</span> : null}</td>
    </tr>
  );
}

/** Visualises hidden characters from the backend's own Unicode inspector. All text is escaped by React and made visible by safeLabel. */
export function UnicodeVisual({ hidden }: { hidden: { name: string; text: string } | null }) {
  const q = useQuery({ queryKey: ["story-unicode", hidden?.text ?? ""], queryFn: () => api.inspectUnicode(hidden!.text), enabled: !!hidden, staleTime: 60_000 });
  const head = (
    <thead><tr className="text-left text-[10.5px] uppercase tracking-wider text-dim"><th className="pr-3 font-medium">Code point</th><th className="pr-3 font-medium">Name</th><th className="pr-3 font-medium">Category</th><th className="pr-3 font-medium">Script</th><th className="font-medium">Bidi</th></tr></thead>
  );
  return (
    <div className="text-[12.5px]" data-testid="unicode-visual">
      <h3 className="mb-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-dim">Hidden character analysis</h3>
      {!hidden && (
        <>
          <p className="text-dim">No hidden or invisible characters were found in tool names or descriptions of this scan.</p>
          <p className="mt-2 text-[11px] uppercase tracking-wider text-dim">Reference, not from this scan</p>
          <table className="mt-1 w-full">{head}<tbody><Row r={REFERENCE} /></tbody></table>
        </>
      )}
      {hidden && q.isLoading && <p className="text-dim" role="status">Inspecting characters…</p>}
      {hidden && q.error && <p className="text-sev-high" role="alert">Data unavailable: the Unicode inspector could not be reached.</p>}
      {hidden && q.data && (() => {
        const rows = q.data.chars.filter((c) => c.invisible || c.suspicious);
        return (
          <>
            <p className="text-dim">In tool <span className="font-mono text-fg">{safeLabel(hidden.name, 40)}</span>: {q.data.suspicious_count} suspicious of {q.data.length} characters.</p>
            <p className="mt-2 break-words rounded border border-line bg-bg/60 p-2 font-mono text-[11.5px]" aria-label="Text with hidden characters made visible">{safeLabel(hidden.text, 220)}</p>
            <table className="mt-2 w-full">{head}<tbody>{rows.slice(0, 6).map((c) => <Row key={c.index} r={{ codepoint: c.codepoint, name: c.name, category: c.category_label, script: c.script, bidi: c.bidi }} note={c.suspicious ?? undefined} />)}</tbody></table>
            {rows.length > 6 && <p className="mt-1 text-dim">+{rows.length - 6} more in the Unicode Inspector.</p>}
          </>
        );
      })()}
    </div>
  );
}
