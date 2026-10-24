import { useEffect, useState } from "react";
import { Shell } from "./components/Shell";
import Login from "./pages/Login";
import { api, auth } from "./services/api";

export default function App() {
  const [version, setVersion] = useState("");
  const [apiDown, setApiDown] = useState(false);
  const [needsKey, setNeedsKey] = useState(false);
  const [ready, setReady] = useState(false);
  const [authRequired, setAuthRequired] = useState(false);

  useEffect(() => {
    const onUnauthorized = () => setNeedsKey(true);
    window.addEventListener("mcp-pentester-unauthorized", onUnauthorized);
    return () => window.removeEventListener("mcp-pentester-unauthorized", onUnauthorized);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const h = await api.health();
        if (cancelled) return;
        setAuthRequired(h.auth_required);
        setApiDown(false);
        if (h.auth_required && !(await api.authCheck(auth.get()))) setNeedsKey(true);
        const v = await api.version();
        if (!cancelled) setVersion(v.version);
      } catch {
        if (!cancelled) setApiDown(true);
      } finally {
        if (!cancelled) setReady(true);
      }
    })();
    return () => { cancelled = true; };
  }, [needsKey]);

  if (!ready) return <div className="grid min-h-screen place-items-center text-dim" role="status">Connecting to the backend…</div>;
  if (needsKey) return <Login onSuccess={() => { setNeedsKey(false); setReady(false); }} />;
  return <Shell version={version} authRequired={authRequired} apiDown={apiDown} onSignOut={() => { auth.clear(); setNeedsKey(true); }} />;
}
