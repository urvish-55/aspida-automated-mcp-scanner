import { useVirtualizer } from "@tanstack/react-virtual";
import { Check, ChevronDown, ChevronRight, ChevronsDownUp, ChevronsUpDown, Copy, Search, WrapText } from "lucide-react";
import { Fragment, memo, useDeferredValue, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { cn } from "../lib/utils";

export interface Highlight { start: number; end: number; label?: string }

interface Props {
  value: unknown;
  language?: "json" | "text";
  title?: string;
  maxHeight?: number;
  /** character ranges in the raw text (language="text") to highlight */
  highlights?: Highlight[];
  /** show invisible characters as visible glyphs (text mode) */
  revealInvisible?: boolean;
}

const VIRTUALIZE_AT = 1200;
const LINE_H = 20;
const TOKEN_RE = /("(?:\\.|[^"\\])*")(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;

function toText(value: unknown, language: "json" | "text"): string {
  if (typeof value === "string") {
    if (language === "json") {
      try { return JSON.stringify(JSON.parse(value), null, 2); } catch { return value; }
    }
    return value;
  }
  try { return JSON.stringify(value, null, 2) ?? ""; } catch { return String(value); }
}

function markSearch(text: string, q: string, key: string): ReactNode {
  if (!q) return text;
  const lower = text.toLowerCase();
  const out: ReactNode[] = [];
  let i = 0;
  let n = 0;
  for (;;) {
    const at = lower.indexOf(q, i);
    if (at < 0) break;
    if (at > i) out.push(text.slice(i, at));
    out.push(<mark key={`${key}-${n++}`} className="rounded bg-warn/40 px-0.5 text-fg">{text.slice(at, at + q.length)}</mark>);
    i = at + q.length;
  }
  if (i === 0) return text;
  out.push(text.slice(i));
  return out;
}

const JsonLine = memo(function JsonLine({ line, q }: { line: string; q: string }) {
  const parts: ReactNode[] = [];
  let last = 0;
  let m: RegExpExecArray | null;
  TOKEN_RE.lastIndex = 0;
  let k = 0;
  while ((m = TOKEN_RE.exec(line))) {
    if (m.index > last) parts.push(<Fragment key={`p${k++}`}>{markSearch(line.slice(last, m.index), q, `p${k}`)}</Fragment>);
    const [full, str, colon, kw] = m;
    if (str) {
      const isKey = !!colon;
      parts.push(<span key={`t${k++}`} className={isKey ? "text-brand" : "text-ok"}>{markSearch(str, q, `s${k}`)}</span>);
      if (colon) parts.push(<span key={`c${k++}`} className="text-dim">{colon}</span>);
    } else if (kw) {
      parts.push(<span key={`t${k++}`} className="text-sev-high">{full}</span>);
    } else {
      parts.push(<span key={`t${k++}`} className="text-sev-low">{full}</span>);
    }
    last = m.index + full.length;
  }
  if (last < line.length) parts.push(<Fragment key={`e${k++}`}>{markSearch(line.slice(last), q, `e${k}`)}</Fragment>);
  return <>{parts}</>;
});

const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF\u00AD]/g;
function glyph(ch: string) { return `<U+${ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}>`; }

export function CodeViewer({ value, language = "json", title, maxHeight = 420, highlights, revealInvisible }: Props) {
  const text = useMemo(() => toText(value, language), [value, language]);
  const lines = useMemo(() => text.split("\n"), [text]);
  const virtual = lines.length > VIRTUALIZE_AT;
  const [wrap, setWrap] = useState(language === "text");
  const [query, setQuery] = useState("");
  const dq = useDeferredValue(query.trim().toLowerCase());
  const [copied, setCopied] = useState(false);
  const [folded, setFolded] = useState<Set<number>>(new Set());
  const [hit, setHit] = useState(0);
  const scroller = useRef<HTMLDivElement>(null);

  // fold regions: JSON lines that open a block closed at the same indent
  const regions = useMemo(() => {
    const out = new Map<number, number>();
    if (language !== "json") return out;
    const stack: { indent: number; line: number }[] = [];
    lines.forEach((l, i) => {
      const indent = l.length - l.trimStart().length;
      const t = l.trim();
      if (/[{[]$/.test(t)) stack.push({ indent, line: i });
      else if (/^[}\]],?$/.test(t)) {
        const top = stack.pop();
        if (top && i - top.line > 1) out.set(top.line, i);
      }
    });
    return out;
  }, [lines, language]);

  const visible = useMemo(() => {
    const rows: number[] = [];
    let i = 0;
    while (i < lines.length) {
      rows.push(i);
      if (folded.has(i) && regions.has(i)) i = (regions.get(i) as number) + 1;
      else i++;
    }
    return rows;
  }, [lines, folded, regions]);

  // character offset of each line start (for highlights in text mode)
  const offsets = useMemo(() => {
    const o: number[] = [];
    let acc = 0;
    for (const l of lines) { o.push(acc); acc += l.length + 1; }
    return o;
  }, [lines]);

  const matches = useMemo(() => {
    if (!dq) return [] as number[];
    const m: number[] = [];
    lines.forEach((l, i) => { if (l.toLowerCase().includes(dq)) m.push(i); });
    return m;
  }, [lines, dq]);

  const rowVirt = useVirtualizer({ count: visible.length, getScrollElement: () => scroller.current, estimateSize: () => LINE_H, overscan: 30, enabled: virtual });

  const jumpTo = (lineIdx: number) => {
    const pos = visible.indexOf(lineIdx);
    if (pos < 0) return;
    if (virtual) rowVirt.scrollToIndex(pos, { align: "center" });
    else scroller.current?.querySelector(`[data-line="${lineIdx}"]`)?.scrollIntoView({ block: "center" });
  };
  useEffect(() => { setHit(0); if (matches.length) jumpTo(matches[0]); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [dq]);

  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard blocked */ }
  };

  const renderLine = (li: number): ReactNode => {
    const line = lines[li];
    const isFolded = folded.has(li) && regions.has(li);
    if (language === "json") return <><JsonLine line={line} q={dq} />{isFolded && <span className="ml-1 rounded bg-raised px-1 text-dim">… {(regions.get(li) as number) - li - 1} lines</span>}</>;
    // text mode with highlight ranges
    const base = offsets[li];
    const segs: ReactNode[] = [];
    let cur = 0;
    const hs = (highlights ?? []).filter((h) => h.end > base && h.start < base + line.length + 1).sort((a, b) => a.start - b.start);
    const emit = (s: string, key: string) => {
      if (!revealInvisible) return markSearch(s, dq, key);
      const parts: ReactNode[] = [];
      let last = 0; let m: RegExpExecArray | null; INVISIBLE_RE.lastIndex = 0; let n = 0;
      while ((m = INVISIBLE_RE.exec(s))) {
        if (m.index > last) parts.push(s.slice(last, m.index));
        parts.push(<span key={`${key}i${n++}`} className="rounded bg-sev-critical/25 px-0.5 text-[10.5px] text-sev-critical" title="invisible character">{glyph(m[0])}</span>);
        last = m.index + 1;
      }
      parts.push(s.slice(last));
      return parts;
    };
    hs.forEach((h, n) => {
      const s = Math.max(0, h.start - base);
      const e = Math.min(line.length, h.end - base);
      if (s > cur) segs.push(<Fragment key={`a${n}`}>{emit(line.slice(cur, s), `a${n}`)}</Fragment>);
      segs.push(<mark key={`h${n}`} title={h.label} className="rounded bg-sev-critical/30 px-0.5 text-fg ring-1 ring-sev-critical/60">{emit(line.slice(s, Math.max(s, e)) || "\u00A0", `h${n}`)}</mark>);
      cur = Math.max(cur, e);
    });
    if (cur < line.length || segs.length === 0) segs.push(<Fragment key="z">{emit(line.slice(cur), "z")}</Fragment>);
    return <>{segs}</>;
  };

  const gutter = String(lines.length).length;
  const renderRow = (li: number, style?: React.CSSProperties) => (
    <div key={li} data-line={li} style={style} className={cn("flex", virtual && "absolute left-0 top-0 w-full", matches.includes(li) && dq && "bg-warn/5")}>
      <span className="sticky left-0 z-[1] flex shrink-0 select-none items-start justify-end gap-1 bg-panel pr-2 text-right text-dim" style={{ width: `${gutter + 4}ch` }}>
        {regions.has(li) ? (
          <button className="text-dim hover:text-fg" aria-label={folded.has(li) ? "Expand block" : "Collapse block"} aria-expanded={!folded.has(li)}
            onClick={() => setFolded((f) => { const n = new Set(f); if (n.has(li)) n.delete(li); else n.add(li); return n; })}>
            {folded.has(li) ? <ChevronRight className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
        ) : <span className="w-3" />}
        <span>{li + 1}</span>
      </span>
      <code className={cn("mono block min-w-0 flex-1 pr-3", wrap && !virtual ? "whitespace-pre-wrap break-all" : "whitespace-pre")} style={{ minHeight: LINE_H, lineHeight: `${LINE_H}px` }}>{renderLine(li) || "\u00A0"}</code>
    </div>
  );

  return (
    <div className="overflow-hidden rounded-lg border border-line bg-panel">
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-raised/60 px-2.5 py-1.5">
        {title && <span className="mr-1 text-[12px] font-medium text-dim">{title}</span>}
        <label className="relative ml-auto flex items-center">
          <Search className="pointer-events-none absolute left-2 h-3 w-3 text-dim" aria-hidden />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search" aria-label="Search within viewer"
            onKeyDown={(e) => { if (e.key === "Enter" && matches.length) { const n = (hit + (e.shiftKey ? -1 : 1) + matches.length) % matches.length; setHit(n); jumpTo(matches[n]); } }}
            className="w-32 rounded border border-line bg-bg py-0.5 pl-6 pr-2 text-[12px] outline-none focus:border-brand/60" />
        </label>
        {dq && <span className="text-[11px] text-dim" aria-live="polite">{matches.length ? `${hit + 1}/${matches.length}` : "no matches"}</span>}
        {language === "json" && regions.size > 0 && (
          <>
            <button className="btn-ghost !px-1.5 !py-1" onClick={() => setFolded(new Set(regions.keys()))} aria-label="Collapse all"><ChevronsDownUp className="h-3.5 w-3.5" /></button>
            <button className="btn-ghost !px-1.5 !py-1" onClick={() => setFolded(new Set())} aria-label="Expand all"><ChevronsUpDown className="h-3.5 w-3.5" /></button>
          </>
        )}
        <button className={cn("btn-ghost !px-1.5 !py-1", wrap && !virtual && "text-brand")} onClick={() => setWrap((w) => !w)} disabled={virtual} aria-pressed={wrap && !virtual}
          title={virtual ? "Word wrap is off for very large documents" : "Toggle word wrap"} aria-label="Toggle word wrap"><WrapText className="h-3.5 w-3.5" /></button>
        <button className="btn-ghost !px-1.5 !py-1" onClick={copy} aria-label="Copy to clipboard">{copied ? <Check className="h-3.5 w-3.5 text-ok" /> : <Copy className="h-3.5 w-3.5" />}</button>
      </div>
      <div ref={scroller} className="overflow-auto py-2" style={{ maxHeight }} tabIndex={0} aria-label={title ?? "Code viewer"}>
        {virtual ? (
          <div style={{ height: rowVirt.getTotalSize(), position: "relative", minWidth: "100%" }}>
            {rowVirt.getVirtualItems().map((v) => renderRow(visible[v.index], { transform: `translateY(${v.start}px)`, height: LINE_H }))}
          </div>
        ) : (
          <div className="min-w-fit">{visible.map((li) => renderRow(li))}</div>
        )}
      </div>
      <div className="border-t border-line bg-raised/40 px-2.5 py-1 text-[11px] text-dim">{lines.length.toLocaleString()} {lines.length === 1 ? "line" : "lines"} · {text.length.toLocaleString()} chars{virtual && " · virtualized"}</div>
    </div>
  );
}
