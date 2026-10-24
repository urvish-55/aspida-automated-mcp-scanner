import { KeyRound, Network } from "lucide-react";
import { useState } from "react";
import { api, auth } from "../services/api";

export default function Login({ onSuccess }: { onSuccess: () => void }) {
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true); setError("");
    try {
      if (await api.authCheck(key.trim())) { auth.set(key.trim()); onSuccess(); } else setError("That API key was not accepted.");
    } catch { setError("Could not reach the API. Is the backend running on port 8000?"); } finally { setBusy(false); }
  };
  return (
    <div className="grid min-h-screen place-items-center px-4">
      <form className="card w-full max-w-md p-7" onSubmit={(e) => { e.preventDefault(); if (key.trim()) void submit(); }}>
        <div className="mb-5 flex items-center gap-3"><div className="grid h-11 w-11 place-items-center rounded-xl border border-brand/50 bg-brand/10 text-brand shadow-glow"><Network className="h-5 w-5" /></div><div><h1 className="text-lg font-semibold">MCP Pentester</h1><p className="text-[12.5px] text-dim">Security testing for MCP servers</p></div></div>
        <label htmlFor="apikey" className="label">API key</label>
        <div className="relative mt-1.5"><KeyRound className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-dim" aria-hidden /><input id="apikey" type="password" autoComplete="off" autoFocus className="input !pl-9" value={key} onChange={(e) => setKey(e.target.value)} /></div>
        {error && <p role="alert" className="mt-3 text-sev-critical">{error}</p>}
        <button type="submit" className="btn-primary mt-5 w-full !py-2.5" disabled={busy || !key.trim()}>{busy ? "Checking…" : "Sign in"}</button>
        <p className="mt-4 text-[12px] text-dim">The key is in the <span className="mono">API_KEY</span> setting, or in <span className="mono">data/api_key</span> on the server (created on first start). It is kept in this tab's session storage only.</p>
      </form>
    </div>
  );
}
