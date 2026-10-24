import type { Event, ScanStatus } from "../types";
import type { ScanStageView } from "../types/visualization";

export const PIPELINE_STAGES: { id: string; label: string }[] = [
  { id: "initializing", label: "Initialising" },
  { id: "parsing_target", label: "Parsing target" },
  { id: "enumerating_tools", label: "Enumerating tools" },
  { id: "static_analysis", label: "Static analysis" },
  { id: "dynamic_testing", label: "Dynamic testing" },
  { id: "semantic_analysis", label: "Semantic analysis" },
  { id: "risk_aggregation", label: "Risk aggregation" },
  { id: "report_generation", label: "Report generation" },
];

/**
 * Derive the pipeline view purely from stored backend events + scan status.
 * No timers, no interpolation: a stage is "active" only if the backend has started it and has not started a later one.
 */
export function deriveStages(events: Event[], status: ScanStatus): ScanStageView[] {
  const lastIdx = (id: string) => events.reduce((m, e, i) => (e.stage === id ? i : m), -1);
  const started = PIPELINE_STAGES.map((s) => events.some((e) => e.stage === s.id));
  let highest = -1;
  started.forEach((s, i) => { if (s) highest = i; });
  return PIPELINE_STAGES.map((s, i) => {
    const li = lastIdx(s.id);
    const last = li >= 0 ? events[li] : null;
    let state: ScanStageView["state"] = "pending";
    if (started[i]) {
      if (i < highest || status === "completed") state = "done";
      else if (status === "running" || status === "queued") state = "active";
      else if (status === "failed" || status === "cancelled") state = "failed";
    }
    if ((status === "failed" || status === "cancelled") && i === highest) state = "failed";
    const durations = events.filter((e) => e.stage === s.id && e.duration_ms != null).map((e) => e.duration_ms as number);
    return { id: s.id, label: s.label, state, message: last?.message ?? null, durationMs: durations.length ? durations.reduce((a, b) => a + b, 0) : null };
  });
}

/** A scan visualisation may animate only while the backend reports the scan as running. */
export const isLive = (status: ScanStatus | undefined): boolean => status === "running";

/** Findings only exist from the risk-aggregation stage on; say so instead of showing an empty list as "clean". */
export function findingsAvailable(events: Event[], status: ScanStatus): boolean {
  return status === "completed" || events.some((e) => e.stage === "risk_aggregation" || e.stage === "report_generation");
}
