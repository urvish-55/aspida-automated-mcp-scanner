import { ChevronDown, ChevronRight } from "lucide-react";
import { useMemo, useState } from "react";
import { cn } from "../lib/utils";
import type { Evidence, Tool } from "../types";
import { CodeViewer, type Highlight } from "./CodeViewer";
import { Pill, Tabs, TabsContent, TabsList, TabsTrigger } from "./ui";

function str(v: unknown): string { return typeof v === "string" ? v : v == null ? "" : JSON.stringify(v); }

function fieldText(field: string, tool: Tool | undefined): string | null {
  if (!tool) return null;
  const f = field.toLowerCase();
  if (f.includes("description")) return tool.description;
  if (f === "name" || f.includes("tool name") || f.endsWith(" name")) return tool.name;
  return null;
}

function UnicodeEvidence({ ev, tool }: { ev: Evidence; tool?: Tool }) {
  const d = ev.detail;
  const pos = typeof d.position === "number" ? d.position : -1;
  const field = str(d.field);
  const text = fieldText(field, tool);
  const [tab, setTab] = useState("original");
  const highlights: Highlight[] = pos >= 0 ? [{ start: pos, end: pos + 1, label: `${str(d.codepoint)} ${str(d.char_name)}` }] : [];
  const escaped = text ? text.replace(/[\u0000-\u001f\u007f-\uffff]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`) : str(d.context_escaped);
  const codepoints = text ? Array.from(text).map((c) => `U+${(c.codePointAt(0) as number).toString(16).toUpperCase().padStart(4, "0")}`).join(" ") : str(d.codepoint);
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-[13px]">
        <dt className="label self-center">Character</dt><dd className="mono">{str(d.codepoint)}</dd>
        <dt className="label self-center">Name</dt><dd>{str(d.char_name)}</dd>
        <dt className="label self-center">Position</dt><dd>character {pos}</dd>
        <dt className="label self-center">Field</dt><dd>{field}</dd>
        <dt className="label self-center">Class</dt><dd>{str(d.class)} <span className="text-dim">({str(d.unicode_category)})</span></dd>
      </dl>
      <Tabs value={tab} onValueChange={setTab}>
        <TabsList>
          <TabsTrigger value="original">Original</TabsTrigger>
          <TabsTrigger value="escaped">Escaped</TabsTrigger>
          <TabsTrigger value="codepoints">Code points</TabsTrigger>
        </TabsList>
        <TabsContent value="original">
          {text != null ? <CodeViewer value={text} language="text" highlights={highlights} revealInvisible maxHeight={240} title={field} />
            : <p className="text-dim">The full field text is not available for this scan; context: <span className="mono">{str(d.context_escaped)}</span></p>}
        </TabsContent>
        <TabsContent value="escaped"><CodeViewer value={escaped} language="text" maxHeight={240} title="ASCII-escaped" /></TabsContent>
        <TabsContent value="codepoints"><CodeViewer value={codepoints} language="text" maxHeight={240} title="Code points" /></TabsContent>
      </Tabs>
    </div>
  );
}

function TextMatchEvidence({ ev, tool }: { ev: Evidence; tool?: Tool }) {
  const d = ev.detail;
  const matched = str(d.matched_text);
  const field = str(d.field);
  const text = fieldText(field, tool);
  const at = text && matched ? text.indexOf(matched) : -1;
  const highlights: Highlight[] = at >= 0 ? [{ start: at, end: at + matched.length, label: str(d.category) }] : [];
  return (
    <div className="space-y-3">
      <dl className="grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-[13px]">
        <dt className="label">Field</dt><dd>{field}</dd>
        <dt className="label">Category</dt><dd><Pill>{str(d.category)}</Pill></dd>
        {d.why != null && <><dt className="label">Why flagged</dt><dd>{str(d.why)}</dd></>}
      </dl>
      {text != null ? (
        <CodeViewer value={text} language="text" highlights={highlights} revealInvisible maxHeight={260} title={`${tool?.name ?? "tool"} · ${field}`} />
      ) : (
        <CodeViewer value={matched} language="text" maxHeight={160} title="Matched text" highlights={[{ start: 0, end: matched.length }]} />
      )}
      {text != null && at < 0 && <p className="text-[12px] text-dim">The matched span could not be located in the stored description; the finding text is shown instead.</p>}
    </div>
  );
}

function GenericEvidence({ ev }: { ev: Evidence }) {
  return <CodeViewer value={ev.detail} language="json" maxHeight={300} title={ev.kind} />;
}

export function EvidenceBlock({ ev, tools, defaultOpen = false }: { ev: Evidence; tools: Tool[]; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  // Associate evidence with a tool by name appearing in the summary/detail; fall back to the only tool.
  const tool = useMemo(() => {
    const hay = `${ev.summary} ${JSON.stringify(ev.detail)}`;
    return tools.find((t) => t.name && hay.includes(t.name)) ?? (tools.length === 1 ? tools[0] : undefined);
  }, [ev, tools]);
  return (
    <div className="rounded-lg border border-line bg-bg/50">
      <button className="flex w-full items-center gap-2 px-3 py-2.5 text-left" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        {open ? <ChevronDown className="h-4 w-4 shrink-0 text-dim" /> : <ChevronRight className="h-4 w-4 shrink-0 text-dim" />}
        <Pill tone="brand">{ev.kind.replace(/_/g, " ")}</Pill>
        <span className={cn("min-w-0 flex-1 truncate text-[13px]", open && "whitespace-normal")}>{ev.summary}</span>
      </button>
      {open && (
        <div className="border-t border-line px-3 py-3">
          {ev.kind === "unicode_char" ? <UnicodeEvidence ev={ev} tool={tool} />
            : ev.kind === "text_match" ? <TextMatchEvidence ev={ev} tool={tool} />
            : <GenericEvidence ev={ev} />}
        </div>
      )}
    </div>
  );
}
