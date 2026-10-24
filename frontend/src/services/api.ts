import type {
  ActivityItem, Analysis, Comparison, DashboardStats, DiscoverResult, Finding, FindingRow, FindingsResponse,
  HealthInfo, MlInfo, NotificationItem, ReportJson, Scan, ScanDetail, SearchResults, SystemHealth, Tool,
  ToolHistory, TriageStatus, UnicodeInspection, VersionInfo,
} from "../types";

// The API key lives in sessionStorage only (cleared when the tab closes) and is sent as a header.
const KEY_STORAGE = "mcp-pentester-api-key";

export const auth = {
  get(): string {
    try { return sessionStorage.getItem(KEY_STORAGE) ?? ""; } catch { return ""; }
  },
  set(key: string): void {
    try { sessionStorage.setItem(KEY_STORAGE, key); } catch { /* storage blocked: key is kept for this page load only */ }
  },
  clear(): void {
    try { sessionStorage.removeItem(KEY_STORAGE); } catch { /* ignore */ }
  },
};

export class UnauthorizedError extends Error {
  constructor() {
    super("Authentication required: enter a valid API key.");
  }
}

function authHeaders(): Record<string, string> {
  const key = auth.get();
  return key ? { "X-API-Key": key } : {};
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    ...init,
    headers: { "Content-Type": "application/json", ...authHeaders(), ...(init?.headers as Record<string, string> | undefined) },
  });
  if (resp.status === 401) {
    auth.clear();
    window.dispatchEvent(new Event("mcp-pentester-unauthorized"));
    throw new UnauthorizedError();
  }
  if (resp.status === 204) return undefined as T;
  if (!resp.ok) {
    let detail = `${resp.status} ${resp.statusText}`;
    try {
      const body = await resp.json();
      if (body?.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      /* keep default */
    }
    throw new Error(detail);
  }
  return (await resp.json()) as T;
}

export interface NewScanInput {
  target_type: "config" | "url";
  target_config?: unknown;
  uploaded_file?: string;
  server_url?: string;
  safe_mode: boolean;
  dynamic_enabled: boolean;
  semantic_enabled: boolean;
  authorization_confirmed: boolean;
}

export const api = {
  health: () => request<HealthInfo>("/api/health"),
  version: () => request<VersionInfo>("/api/version"),
  dashboard: () => request<DashboardStats>("/api/dashboard"),
  createScan: (input: NewScanInput) =>
    request<Scan>("/api/scans", { method: "POST", body: JSON.stringify(input) }),
  listScans: (limit = 50, offset = 0) =>
    request<{ total: number; items: Scan[] }>(`/api/scans?limit=${limit}&offset=${offset}`),
  getScan: (id: string) => request<ScanDetail>(`/api/scans/${id}`),
  deleteScan: (id: string) => request<void>(`/api/scans/${id}`, { method: "DELETE" }),
  cancelScan: (id: string) => request<Scan>(`/api/scans/${id}/cancel`, { method: "POST", body: "{}" }),
  findings: (id: string) => request<{ total: number; items: Finding[] }>(`/api/scans/${id}/findings`),
  tools: (id: string) => request<Tool[]>(`/api/scans/${id}/tools`),
  uploadConfig: async (file: File) => {
    const form = new FormData();
    form.append("file", file);
    // No Content-Type header: the browser sets the multipart boundary.
    const resp = await fetch("/api/uploads", { method: "POST", headers: authHeaders(), body: form });
    if (resp.status === 401) {
      auth.clear();
      window.dispatchEvent(new Event("mcp-pentester-unauthorized"));
      throw new UnauthorizedError();
    }
    if (!resp.ok) {
      let detail = `${resp.status} ${resp.statusText}`;
      try { const b = await resp.json(); if (b?.detail) detail = String(b.detail); } catch { /* keep default */ }
      throw new Error(detail);
    }
    return (await resp.json()) as { stored_filename: string; size_bytes: number };
  },
  analysis: (id: string) => request<Analysis>(`/api/scans/${id}/analysis`),
  compare: (a: string, b: string) => request<Comparison>(`/api/compare?a=${a}&b=${b}`),
  allFindings: (params: Record<string, string | number | boolean | undefined>) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined && v !== "" && v !== null) qs.set(k, String(v)); });
    return request<FindingsResponse>(`/api/findings?${qs.toString()}`);
  },
  finding: (id: string) => request<FindingRow>(`/api/findings/${id}`),
  setTriage: (id: string, status: TriageStatus, note: string) =>
    request<Finding>(`/api/findings/${id}/triage`, { method: "PATCH", body: JSON.stringify({ status, note }) }),
  search: (q: string) => request<SearchResults>(`/api/search?q=${encodeURIComponent(q)}`),
  activity: (limit = 30) => request<{ items: ActivityItem[] }>(`/api/activity?limit=${limit}`),
  notifications: () => request<{ items: NotificationItem[] }>("/api/notifications"),
  discover: (body: { target_config?: unknown; uploaded_file?: string }) =>
    request<DiscoverResult>("/api/discover", { method: "POST", body: JSON.stringify(body) }),
  toolHistory: (name: string) => request<ToolHistory>(`/api/tools/history?name=${encodeURIComponent(name)}`),
  inspectUnicode: (text: string) => request<UnicodeInspection>("/api/unicode/inspect", { method: "POST", body: JSON.stringify({ text }) }),
  mlInfo: () => request<MlInfo>("/api/ml/info"),
  systemHealth: () => request<SystemHealth>("/api/system/health"),
  report: (id: string) => request<ReportJson>(`/api/scans/${id}/report`),
  authCheck: (key: string) =>
    fetch("/api/auth/check", { headers: { "X-API-Key": key } }).then((r) => r.status === 200),
  // Reports need the auth header, so plain <a href> links cannot be used: fetch as a blob and save/open it.
  downloadReport: async (id: string, kind: "pdf" | "json") => {
    const path = kind === "pdf" ? `/api/scans/${id}/report/pdf` : `/api/scans/${id}/report`;
    const resp = await fetch(path, { headers: authHeaders() });
    if (resp.status === 401) {
      auth.clear();
      window.dispatchEvent(new Event("mcp-pentester-unauthorized"));
      throw new UnauthorizedError();
    }
    if (!resp.ok) throw new Error(`Report download failed: ${resp.status} ${resp.statusText}`);
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    window.dispatchEvent(new CustomEvent("mcp-pentester-report", { detail: { id, kind, at: new Date().toISOString() } }));
    if (kind === "pdf") {
      const a = document.createElement("a");
      a.href = url;
      a.download = `mcp-pentester-report-${id}.pdf`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    } else {
      window.open(url, "_blank", "noopener");
      setTimeout(() => URL.revokeObjectURL(url), 60_000);
    }
  },
};
