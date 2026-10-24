import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Sev = (typeof SEVERITIES)[number];
export const SEV_RANK: Record<string, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1, none: 0 };

export const SEV_TEXT: Record<string, string> = {
  critical: "text-sev-critical", high: "text-sev-high", medium: "text-sev-medium", low: "text-sev-low", info: "text-sev-info", none: "text-dim",
};
export const SEV_BG: Record<string, string> = {
  critical: "bg-sev-critical", high: "bg-sev-high", medium: "bg-sev-medium", low: "bg-sev-low", info: "bg-sev-info", none: "bg-line",
};
export const SEV_SOFT: Record<string, string> = {
  critical: "bg-sev-critical/15 text-sev-critical border-sev-critical/40",
  high: "bg-sev-high/15 text-sev-high border-sev-high/40",
  medium: "bg-sev-medium/15 text-sev-medium border-sev-medium/40",
  low: "bg-sev-low/15 text-sev-low border-sev-low/40",
  info: "bg-sev-info/15 text-sev-info border-sev-info/40",
  none: "bg-raised text-dim border-line",
};
export const SEV_HEX_VAR: Record<string, string> = {
  critical: "hsl(var(--sev-critical))", high: "hsl(var(--sev-high))", medium: "hsl(var(--sev-medium))",
  low: "hsl(var(--sev-low))", info: "hsl(var(--sev-info))", none: "hsl(var(--line))",
};

export function riskBand(score: number | null | undefined): { label: string; sev: Sev | "none" } {
  if (score == null) return { label: "NOT SCORED", sev: "none" };
  if (score >= 75) return { label: "CRITICAL RISK", sev: "critical" };
  if (score >= 50) return { label: "HIGH RISK", sev: "high" };
  if (score >= 25) return { label: "MODERATE RISK", sev: "medium" };
  return { label: "LOW RISK", sev: "low" };
}

/** The backend stores UTC timestamps without a zone suffix; treat them as UTC, not local time. */
export function parseTs(iso: string): number {
  return new Date(/(Z|[+-]\d\d:?\d\d)$/.test(iso) ? iso : iso + "Z").getTime();
}

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "-";
  const diff = Math.max(0, Date.now() - parseTs(iso));
  const s = Math.floor(diff / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleTimeString([], { hour12: false });
}
export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "-";
  return new Date(iso).toLocaleString();
}
export function duration(a: string | null, b: string | null): string {
  if (!a) return "-";
  const ms = (b ? parseTs(b) : Date.now()) - parseTs(a);
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

export function humanize(s: string): string {
  return s.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function isLocalTarget(scan: { target_identifier: string; allow_local_targets?: boolean }): boolean {
  if (scan.allow_local_targets) return true;
  try {
    const h = new URL(scan.target_identifier).hostname;
    return h === "localhost" || h === "127.0.0.1" || h === "::1" || h === "[::1]";
  } catch {
    return false;
  }
}

