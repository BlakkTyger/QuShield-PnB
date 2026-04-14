import { useQuery, useMutation } from "@tanstack/react-query";
import api from "@/lib/api";
import type {
  ScanResponse,
  ScanStatus,
  ScanSummary,
  AssetListResponse,
  AssetDetail,
  CBOMDetail,
  CBOMAggregate,
  RiskHeatmap,
  RiskDetail,
  EnterpriseRating,
  FIPSMatrix,
  RegulatoryDeadline,
  TopologyGraph,
  ComplianceDetail,
  GeoMapData,
  ChatResponse,
  AIStatus,
  AIModelsResponse,
  TLSInspectionStatus as TLSInspectionStatusType,
  TLSInspectionResults,
  TLSInspectionHistoryItem,
} from "@/lib/types";

/* ─── Scans ──────────────────────────────────────────── */
export function useScans() {
  return useQuery({
    queryKey: ["scans"],
    queryFn: async () => {
      const { data } = await api.get<ScanStatus[]>("/scans/");
      return data;
    },
  });
}

export function useScanStatus(scanId: string | null, poll = false) {
  return useQuery({
    queryKey: ["scan", scanId],
    queryFn: async () => {
      try {
        const { data } = await api.get<ScanStatus>(`/scans/${scanId}`);
        return data;
      } catch (err: any) {
        if (err.response?.status === 404) {
          console.warn("Scan not found, clearing state...");
          if (typeof window !== "undefined") {
            localStorage.removeItem("qushield_active_scan");
            localStorage.removeItem("qushield_active_domain");
          }
        }
        throw err;
      }
    },
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!poll || !data) return false;
      if (data.status === "completed" || data.status === "failed" || data.status === "cancelled") return false;
      return 2000;
    },
  });
}

export function useScanSummary(scanId: string | null) {
  return useQuery({
    queryKey: ["scan-summary", scanId],
    queryFn: async () => {
      const { data } = await api.get<ScanSummary>(`/scans/${scanId}/summary`);
      return data;
    },
    enabled: !!scanId,
  });
}

export function useCancelScan() {
  return useMutation({
    mutationFn: async (scanId: string) => {
      const { data } = await api.post(`/scans/${scanId}/cancel`);
      return data;
    },
  });
}

export function useStartScan() {
  return useMutation({
    mutationFn: async (params: { targets: string[]; scan_type?: "deep" | "deeper" }) => {
      const { data } = await api.post<ScanResponse>("/scans/", params);
      return data;
    },
  });
}

export function useQuickScan() {
  return useMutation({
    mutationFn: async (params: { domain: string; port?: number }) => {
      const { data } = await api.post("/scans/quick", params);
      return data;
    },
  });
}

export function useShallowScan() {
  return useMutation({
    mutationFn: async (params: { domain: string; top_n?: number; port?: number }) => {
      const { data } = await api.post("/scans/shallow", params);
      return data;
    },
  });
}

export function useShallowResult(scanId: string | null, enabled = false) {
  return useQuery({
    queryKey: ["shallow-result", scanId],
    queryFn: async () => {
      const { data } = await api.get(`/scans/${scanId}/result`);
      return data as Record<string, unknown>;
    },
    enabled: !!scanId && enabled,
    retry: false,
  });
}

/* ─── Assets ─────────────────────────────────────────── */
export function useAssets(
  scanId: string | null,
  params?: { risk_class?: string; asset_type?: string; q?: string; limit?: number; offset?: number }
) {
  return useQuery({
    queryKey: ["assets", scanId, params],
    queryFn: async () => {
      const { data } = await api.get<AssetListResponse>("/assets/", {
        params: { scan_id: scanId, ...params },
      });
      return data;
    },
    enabled: !!scanId,
  });
}

export function useAssetDetail(assetId: string | null) {
  return useQuery({
    queryKey: ["asset-detail", assetId],
    queryFn: async () => {
      const { data } = await api.get<AssetDetail>(`/assets/${assetId}`);
      return data;
    },
    enabled: !!assetId,
  });
}

/* ─── CBOM ───────────────────────────────────────────── */
export function useCBOMForAsset(assetId: string | null) {
  return useQuery({
    queryKey: ["cbom-asset", assetId],
    queryFn: async () => {
      const { data } = await api.get<CBOMDetail>(`/cbom/asset/${assetId}`);
      return data;
    },
    enabled: !!assetId,
  });
}

export function useCBOMAggregate(scanId: string | null) {
  return useQuery({
    queryKey: ["cbom-aggregate", scanId],
    queryFn: async () => {
      const { data } = await api.get<CBOMAggregate>(
        `/cbom/scan/${scanId}/aggregate`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

export function useCBOMAlgorithms(scanId: string | null) {
  return useQuery({
    queryKey: ["cbom-algorithms", scanId],
    queryFn: async () => {
      const { data } = await api.get<{ scan_id: string; algorithms: { name: string; count: number; nist_quantum_level: number; is_quantum_vulnerable: boolean; component_type: string }[]; total_unique: number }>(
        `/cbom/scan/${scanId}/algorithms`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

export function useCBOMKeyLengths(scanId: string | null) {
  return useQuery({
    queryKey: ["cbom-keylengths", scanId],
    queryFn: async () => {
      const { data } = await api.get<{ scan_id: string; key_length_distribution: Record<string, number>; total_components: number }>(
        `/cbom/scan/${scanId}/key-lengths`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

export function useCertificateAuthorities(scanId: string | null) {
  return useQuery({
    queryKey: ["cert-authorities", scanId],
    queryFn: async () => {
      const { data } = await api.get<{ scan_id: string; top_cas: { name: string; count: number; pqc_ready: boolean }[]; total_certificates: number }>(
        `/cbom/certificates/scan/${scanId}/authorities`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

/* ─── Risk ───────────────────────────────────────────── */
export function useRiskHeatmap(scanId: string | null) {
  return useQuery({
    queryKey: ["risk-heatmap", scanId],
    queryFn: async () => {
      const { data } = await api.get<RiskHeatmap>(
        `/risk/scan/${scanId}/heatmap`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

export function useAssetRisk(assetId: string | null) {
  return useQuery({
    queryKey: ["risk-asset", assetId],
    queryFn: async () => {
      const { data } = await api.get<RiskDetail>(`/risk/asset/${assetId}`);
      return data;
    },
    enabled: !!assetId,
  });
}

export function useEnterpriseRating(scanId: string | null) {
  return useQuery({
    queryKey: ["enterprise-rating", scanId],
    queryFn: async () => {
      const { data } = await api.get<EnterpriseRating>(
        `/risk/scan/${scanId}/enterprise-rating`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

export function useMigrationPlan(scanId: string | null) {
  return useQuery({
    queryKey: ["migration-plan", scanId],
    queryFn: async () => {
      const { data } = await api.get(`/risk/scan/${scanId}/migration-plan`);
      return data;
    },
    enabled: !!scanId,
  });
}

export interface CRQCSimParams {
  mode_year?: number;
  sigma?: number;
  n_simulations?: number;
}

export function useCRQCSimulation(params: CRQCSimParams = {}) {
  const { mode_year = 2032, sigma = 3.5, n_simulations = 10000 } = params;
  return useQuery({
    queryKey: ["crqc-simulation", mode_year, sigma, n_simulations],
    queryFn: async () => {
      const { data } = await api.post(`/risk/monte-carlo/simulate`, null, {
        params: { mode_year, sigma, n_simulations },
      });
      return data as {
        n_simulations: number;
        parameters: { mode_year: number; sigma: number; min_year: number; max_year: number };
        statistics: { mean: number; median: number; std_dev: number };
        percentiles: { p5: number; p25: number; p50: number; p75: number; p95: number };
        probability_by_year: Record<string, number>;
        cumulative_by_year: Record<string, number>;
      };
    },
    staleTime: 60_000,
  });
}

export function useCertRace(scanId: string | null) {
  return useQuery({
    queryKey: ["cert-race", scanId],
    queryFn: async () => {
      const { data } = await api.get(`/risk/scan/${scanId}/cert-race`);
      return data as {
        total_certificates: number;
        safe: number;
        natural_rotation: number;
        at_risk: number;
        pct_at_risk: number;
        crqc_median_arrival: number;
        certificates: Array<{
          hostname: string | null;
          common_name: string | null;
          algorithm: string | null;
          valid_to: string | null;
          race_status: "safe" | "natural_rotation" | "at_risk";
          days_until_expiry: number | null;
        }>;
      };
    },
    enabled: !!scanId,
    staleTime: 120_000,
  });
}

export function usePortfolioMonteCarlo(scanId: string | null, params: CRQCSimParams = {}) {
  const { mode_year = 2032, sigma = 3.5, n_simulations = 10000 } = params;
  return useQuery({
    queryKey: ["portfolio-mc", scanId, mode_year, sigma, n_simulations],
    queryFn: async () => {
      const { data } = await api.get(`/risk/scan/${scanId}/monte-carlo`, {
        params: { mode_year, sigma, n_simulations },
      });
      return data as {
        n_assets: number;
        n_simulations: number;
        reference_year: number;
        portfolio_summary: {
          avg_assets_exposed: number;
          pct_portfolio_exposed: number;
          max_assets_exposed: number;
          min_assets_exposed: number;
        };
        per_asset: Array<{
          hostname: string;
          migration_time_years: number;
          data_shelf_life_years: number;
          exposure_probability: number;
          risk_level: string;
        }>;
        crqc_simulation: { median_arrival: number; p5: number; p95: number };
      };
    },
    enabled: !!scanId,
    staleTime: 120_000,
  });
}

/* ─── Compliance ─────────────────────────────────────── */
export function useFIPSMatrix(scanId: string | null) {
  return useQuery({
    queryKey: ["fips-matrix", scanId],
    queryFn: async () => {
      const { data } = await api.get<FIPSMatrix>(
        `/compliance/scan/${scanId}/fips-matrix`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

export function useRegulatoryDeadlines() {
  return useQuery({
    queryKey: ["deadlines"],
    queryFn: async () => {
      const { data } = await api.get<{ deadlines: RegulatoryDeadline[] }>(
        "/compliance/deadlines"
      );
      return data.deadlines;
    },
  });
}

export function useAssetCompliance(assetId: string | null) {
  return useQuery({
    queryKey: ["compliance-asset", assetId],
    queryFn: async () => {
      const { data } = await api.get<ComplianceDetail>(
        `/compliance/asset/${assetId}`
      );
      return data;
    },
    enabled: !!assetId,
  });
}

export function useComplianceAgility(scanId: string | null) {
  return useQuery({
    queryKey: ["compliance-agility", scanId],
    queryFn: async () => {
      const { data } = await api.get(`/compliance/scan/${scanId}/agility`);
      return data;
    },
    enabled: !!scanId,
  });
}

export function useComplianceRegulatory(scanId: string | null) {
  return useQuery({
    queryKey: ["compliance-regulatory", scanId],
    queryFn: async () => {
      const { data } = await api.get(`/compliance/scan/${scanId}/regulatory`);
      return data;
    },
    enabled: !!scanId,
  });
}

/* ─── Topology ───────────────────────────────────────── */
export function useTopology(scanId: string | null) {
  return useQuery({
    queryKey: ["topology", scanId],
    queryFn: async () => {
      const { data } = await api.get<TopologyGraph>(
        `/topology/scan/${scanId}`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

/* ─── GeoIP ──────────────────────────────────────────── */
export function useGeoMapData(scanId: string | null) {
  const query = useQuery({
    queryKey: ["geo-map", scanId],
    queryFn: async () => {
      // First trigger geolocation (lazy-loads if not present)
      await api.get(`/geo/scan/${scanId}`);
      // Then get map-ready data
      const { data } = await api.get<GeoMapData>(`/geo/scan/${scanId}/map-data`);
      return data;
    },
    enabled: !!scanId,
  });

  const refreshGeo = async () => {
    if (!scanId) return;
    // Clear cached geo data on backend and re-resolve
    await api.get(`/geo/scan/${scanId}?refresh=true`);
    // Refetch map data with the freshly resolved locations
    await query.refetch();
  };

  return { ...query, refreshGeo };
}

/* ─── AI Assistant ───────────────────────────────────── */
export function useAIChat() {
  return useMutation({
    mutationFn: async (params: { message: string; mode?: string }) => {
      const { data } = await api.post<ChatResponse>("/ai/chat", params);
      return data;
    },
  });
}

export function useAIStatus() {
  return useQuery({
    queryKey: ["ai-status"],
    queryFn: async () => {
      const { data } = await api.get<AIStatus>("/ai/status");
      return data;
    },
  });
}

export function useAIModels() {
  return useQuery({
    queryKey: ["ai-models"],
    queryFn: async () => {
      const { data } = await api.get<AIModelsResponse>("/ai/models");
      return data;
    },
  });
}

export function useUpdateAISettings() {
  return useMutation({
    mutationFn: async (settings: { deployment_mode?: string; ai_tier?: string; cloud_api_keys?: Record<string, string> }) => {
      const { data } = await api.patch("/ai/settings", settings);
      return data;
    },
  });
}

export function useRefreshEmbeddings() {
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post("/ai/embed/refresh");
      return data;
    },
  });
}

export function useAIMigrationRoadmap() {
  return useMutation({
    mutationFn: async (scanId: string) => {
      const { data } = await api.post(`/ai/migration-roadmap/${scanId}`);
      return data;
    },
  });
}

/* ─── Reports ────────────────────────────────────────── */
export function useGenerateReport() {
  return useMutation({
    mutationFn: async (params: { scanId: string; reportType: string; format?: string; password?: string }) => {
      const { data } = await api.post(
        `/reports/generate/${params.scanId}`,
        { report_type: params.reportType, format: params.format || "pdf", password: params.password || null },
        { responseType: "blob" }
      );
      return data;
    },
  });
}

export function useSavedReports() {
  return useQuery({
    queryKey: ["saved-reports"],
    queryFn: async () => {
      const { data } = await api.get("/reports/saved");
      return data as Array<{
        id: string;
        scan_id: string;
        report_type: string;
        format: string;
        title: string | null;
        file_size_kb: number | null;
        generated_at: string;
        targets: string | null;
      }>;
    },
  });
}

export function useDeleteSavedReport() {
  return useMutation({
    mutationFn: async (reportId: string) => {
      const { data } = await api.delete(`/reports/saved/${reportId}`);
      return data;
    },
  });
}

export function useChartData(scanId: string | null) {
  return useQuery({
    queryKey: ["chart-data", scanId],
    queryFn: async () => {
      const { data } = await api.get(`/reports/chart-data/${scanId}`);
      return data;
    },
    enabled: !!scanId,
  });
}

/* ─── Dashboard Charts ───────────────────────────────── */
export function useAssetTypeDistribution(scanId: string | null) {
  return useQuery({
    queryKey: ["asset-type-distribution", scanId],
    queryFn: async () => {
      const { data } = await api.get<{ scan_id: string; distribution: Record<string, number>; total_assets: number }>(
        `/assets/scan/${scanId}/type-distribution`
      );
      return data;
    },
    enabled: !!scanId,
  });
}

export function useCertificateExpiryTimeline(scanId: string | null) {
  return useQuery({
    queryKey: ["cert-expiry-timeline", scanId],
    queryFn: async () => {
      const { data } = await api.get<{
        scan_id: string;
        timeline: { month: string; count: number; critical: number; warning: number }[];
        total_certificates: number;
        expiring_30_days: number;
        expiring_90_days: number;
      }>(`/cbom/certificates/scan/${scanId}/expiry-timeline`);
      return data;
    },
    enabled: !!scanId,
  });
}

export function useIPVersionDistribution(scanId: string | null) {
  return useQuery({
    queryKey: ["ip-version-distribution", scanId],
    queryFn: async () => {
      const { data } = await api.get<{
        scan_id: string;
        ipv4_only: number;
        ipv6_only: number;
        dual_stack: number;
        total_assets: number;
      }>(`/assets/scan/${scanId}/ip-distribution`);
      return data;
    },
    enabled: !!scanId,
  });
}

export function useNameserverRecords(scanId: string | null) {
  return useQuery({
    queryKey: ["nameserver-records", scanId],
    queryFn: async () => {
      const { data } = await api.get<{
        scan_id: string;
        nameservers: { hostname: string; ns_records: string[]; ip_addresses: string[] }[];
        total_zones: number;
      }>(`/assets/dns/scan/${scanId}/nameservers`);
      return data;
    },
    enabled: !!scanId,
  });
}

/* ─── ReAct Agent ────────────────────────────────────── */

export function useAgentStatus() {
  return useQuery({
    queryKey: ["agent-status"],
    queryFn: async () => {
      const { data } = await api.get("/ai/agent/status");
      return data as { available: boolean; mode: string; model: string; features: string[] };
    },
    staleTime: 60_000,
  });
}

export type AgentEventType = "thought" | "tool" | "answer" | "error" | "done" | "status";
export interface AgentEvent {
  type: AgentEventType;
  content: string;
}

export function useAgentStream() {
  return useMutation({
    mutationFn: async ({
      message,
      history,
      scan_id,
      onEvent,
    }: {
      message: string;
      history?: Array<{ role: string; content: string }>;
      scan_id?: string | null;
      onEvent: (event: AgentEvent) => void;
    }) => {
      const token = typeof window !== "undefined" ? localStorage.getItem("qushield_access_token") : null;
      const response = await fetch("/api/v1/ai/agent/chat", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          body: JSON.stringify({ message, history, scan_id: scan_id ?? undefined }),
        }
      );

      if (!response.ok) {
        throw new Error(`Agent request failed: ${response.status}`);
      }

      const reader = response.body?.getReader();
      const decoder = new TextDecoder();
      if (!reader) throw new Error("No response body");

      let buffer = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith("data: ")) {
            try {
              const event: AgentEvent = JSON.parse(trimmed.slice(6));
              onEvent(event);
              if (event.type === "done") return;
            } catch {
              // skip malformed SSE lines
            }
          }
        }
      }
    },
  });
}

/* ─── TLS Deep Inspection (testssl.sh) ─────────────── */
export function useTestSSLRun(assetId: string | null) {
  return useMutation({
    mutationFn: async () => {
      const { data } = await api.post(`/testssl/${assetId}/run`);
      return data;
    },
  });
}

export function useTestSSLStatus(assetId: string | null) {
  return useQuery({
    queryKey: ["testssl-status", assetId],
    queryFn: async () => {
      const { data } = await api.get<TLSInspectionStatusType>(`/testssl/${assetId}/status`);
      return data;
    },
    enabled: !!assetId,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      if (status === "pending" || status === "running") return 3000;
      return false;
    },
  });
}

export function useTestSSLResults(assetId: string | null) {
  return useQuery({
    queryKey: ["testssl-results", assetId],
    queryFn: async () => {
      const { data } = await api.get<TLSInspectionResults>(`/testssl/${assetId}/results`);
      return data;
    },
    enabled: !!assetId,
  });
}

export function useTestSSLHistory(assetId: string | null) {
  return useQuery({
    queryKey: ["testssl-history", assetId],
    queryFn: async () => {
      const { data } = await api.get<TLSInspectionHistoryItem[]>(`/testssl/${assetId}/history`);
      return data;
    },
    enabled: !!assetId,
  });
}
