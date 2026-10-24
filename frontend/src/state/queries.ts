import { keepPreviousData, QueryClient, useQuery } from "@tanstack/react-query";
import { api } from "../services/api";
import { usePrefs } from "./prefs";

export const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 4000, refetchOnWindowFocus: false, retry: 1 } },
});

export const useScans = (limit = 100) =>
  useQuery({ queryKey: ["scans", limit], queryFn: () => api.listScans(limit, 0), refetchInterval: 5000 });

export const useDashboard = () => useQuery({ queryKey: ["dashboard"], queryFn: api.dashboard, refetchInterval: 8000 });
export const useHealth = () => useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 15000 });
export const useSystemHealth = () => useQuery({ queryKey: ["system-health"], queryFn: api.systemHealth, refetchInterval: 10000 });
export const useMlInfo = () => useQuery({ queryKey: ["ml-info"], queryFn: api.mlInfo });
export const useActivity = (limit = 30) => useQuery({ queryKey: ["activity", limit], queryFn: () => api.activity(limit), refetchInterval: 6000 });
export const useNotifications = () => useQuery({ queryKey: ["notifications"], queryFn: api.notifications, refetchInterval: 8000 });

export const useScanDetail = (id: string | undefined, poll = false) =>
  useQuery({
    queryKey: ["scan", id],
    queryFn: () => api.getScan(id as string),
    enabled: !!id,
    refetchInterval: (q) => {
      const s = q.state.data?.status;
      return poll || s === "queued" || s === "running" ? 1000 : false;
    },
  });

export const useAnalysis = (id: string | undefined) =>
  useQuery({ queryKey: ["analysis", id], queryFn: () => api.analysis(id as string), enabled: !!id });

export const useFindingsQuery = (params: Record<string, string | number | boolean | undefined>) =>
  useQuery({ queryKey: ["findings", params], queryFn: () => api.allFindings(params), placeholderData: keepPreviousData });

/** The scan the analysis pages operate on: explicit choice, else the most recent finished scan. */
export function useActiveScan() {
  const { scanId, setScanId } = usePrefs();
  const scans = useScans(200);
  const items = scans.data?.items ?? [];
  const finished = items.filter((s) => s.status === "completed" || s.status === "failed" || s.status === "cancelled");
  const chosen = scanId ? items.find((s) => s.id === scanId) : undefined;
  const scan = chosen ?? finished.find((s) => s.status === "completed") ?? finished[0] ?? null;
  return { scan, scans: items, setScanId, loading: scans.isLoading, error: scans.error as Error | null, refetch: scans.refetch };
}
