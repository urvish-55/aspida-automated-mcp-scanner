import { Check, Copy, RefreshCw, ServerOff } from "lucide-react";
import { useState } from "react";

const CMD = "python -m uvicorn backend.api.app:app --port 8000";

export function BackendDown({ onRetry }: { onRetry?: () => void }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(CMD); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* clipboard blocked */ }
  };
  return (
    <div className="grid min-h-[70vh] place-items-center px-4">
      <div className="card w-full max-w-lg p-6 text-center">
        <div className="mx-auto grid h-12 w-12 place-items-center rounded-full border border-warn/40 bg-warn/10 text-warn"><ServerOff className="h-6 w-6" aria-hidden /></div>
        <h1 className="mt-4 text-xl font-semibold">The Aspida backend is not running</h1>
        <p className="mt-1 text-dim">This page only shows results; the scanner lives in the backend. Start it in a second terminal, then retry.</p>
        <div className="mt-4 flex items-center gap-2 rounded-lg border border-line bg-bg px-3 py-2 text-left">
          <code className="mono min-w-0 flex-1 truncate text-[12.5px]">{CMD}</code>
          <button className="btn-ghost shrink-0" onClick={copy} aria-label="Copy command">{copied ? <Check className="h-4 w-4 text-ok" /> : <Copy className="h-4 w-4" />}</button>
        </div>
        <p className="mt-2 text-[12px] text-dim">Run it from the project folder with the virtual environment active.</p>
        <button className="btn-primary mt-5" onClick={onRetry ?? (() => window.location.reload())}><RefreshCw className="h-4 w-4" /> Retry</button>
      </div>
    </div>
  );
}
