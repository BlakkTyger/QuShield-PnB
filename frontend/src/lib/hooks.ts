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
    mutationFn: async (targets: string[]) => {
      const { data } = await api.post<ScanResponse>("/scans/", { targets });
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
      const { data } = await api.get<{ scan_id: string; algorithms: Record<string, number> }>(
        `/cbom/scan/${scanId}/algorithms`
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
  return useQuery({
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
    mutationFn: async (scanId: string) => {
      const { data } = await api.post(`/reports/generate/${scanId}`, {}, {
        responseType: "blob",
      });
      return data;
    },
  });
}
