/* ──────────────────────────────────────────────────────────────────────────
   TypeScript types matching the FastAPI backend response schemas.
   ────────────────────────────────────────────────────────────────────────── */

// ─── Scan ──────────────────────────────────────────────────────
export interface ScanRequest {
  targets: string[];
  config?: Record<string, unknown>;
}

export interface ScanResponse {
  scan_id: string;
  status: string;
  created_at: string;
  message: string;
}

export interface ScanStatus {
  scan_id: string;
  status: string;
  current_phase: number;
  targets: string[];
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  total_assets: number;
  total_certificates: number;
  total_vulnerable: number;
  error_message: string | null;
}

export interface ScanSummary {
  scan_id: string;
  status: string;
  targets: string[];
  created_at: string;
  completed_at: string | null;
  total_assets: number;
  total_certificates: number;
  total_cboms: number;
  total_risk_scores: number;
  total_compliance_results: number;
  risk_breakdown: Record<string, number>;
  compliance_summary: {
    tls_13_enforced: number;
    forward_secrecy: number;
    rbi_compliant: number;
    pci_compliant: number;
    avg_agility_score: number;
    avg_compliance_pct: number;
  };
  shadow_assets: number;
  third_party_assets: number;
}

// ─── Asset ─────────────────────────────────────────────────────
export interface Asset {
  id: string;
  hostname: string;
  ip_address: string | null;
  asset_type: string | null;
  tls_version: string | null;
  key_exchange: string | null;
  risk_score: number | null;
  risk_classification: string | null;
  cert_expiry: string | null;
  cert_expiry_days: number | null;
  nist_level: number | null;
  is_shadow: boolean;
  is_third_party: boolean;
  hosting_provider: string | null;
  cdn_detected: string | null;
  waf_detected: string | null;
  scan_id: string;
}

export interface AssetDetail extends Asset {
  ports: { port: number; protocol: string; service: string | null }[];
  certificates: CertificateInfo[];
  risk: RiskDetail | null;
  compliance: ComplianceDetail | null;
}

export interface CertificateInfo {
  id: string;
  subject: string | null;
  issuer: string | null;
  key_type: string | null;
  key_length: number | null;
  valid_from: string | null;
  valid_to: string | null;
  fingerprint: string | null;
  is_ct_logged: boolean;
  ca_pqc_ready: boolean | null;
  nist_quantum_level: number | null;
}

export interface AssetListResponse {
  items: Asset[];
  total: number;
}

// ─── CBOM ──────────────────────────────────────────────────────
export interface CBOMRecord {
  id: string;
  asset_id: string;
  hostname: string | null;
  spec_version: string | null;
  total_components: number;
  quantum_ready_pct: number | null;
  created_at: string;
}

export interface CBOMComponent {
  id: string;
  name: string | null;
  component_type: string | null;
  algorithm_name: string | null;
  key_type: string | null;
  key_length: number | null;
  nist_quantum_level: number | null;
  quantum_vulnerable: boolean;
  tls_version: string | null;
  bom_ref: string | null;
}

export interface CBOMDetail extends CBOMRecord {
  components: CBOMComponent[];
}

export interface CBOMAggregate {
  scan_id: string;
  total_assets: number;
  total_components: number;
  unique_algorithms: number;
  quantum_ready_pct: number;
  by_type: Record<string, number>;
  by_nist_level: Record<string, number>;
  by_algorithm: Record<string, number>;
}

// ─── Risk ──────────────────────────────────────────────────────
export interface RiskItem {
  id: string;
  asset_id: string;
  hostname: string | null;
  asset_type: string | null;
  quantum_risk_score: number;
  risk_classification: string;
  mosca_x: number | null;
  mosca_y: number | null;
  hndl_exposed: boolean;
  tnfl_risk: boolean;
  tnfl_severity: string | null;
  computed_at: string;
}

export interface RiskDetail {
  asset_id: string;
  hostname: string | null;
  quantum_risk_score: number;
  risk_classification: string;
  mosca: {
    x_migration_years: number | null;
    y_shelf_life_years: number | null;
    z_pessimistic: number | null;
    z_median: number | null;
    z_optimistic: number | null;
  };
  hndl_exposed: boolean;
  tnfl_risk: boolean;
  tnfl_severity: string | null;
  computed_at: string;
  factors: { name: string; score: number; weight: number; rationale: string }[];
}

export interface RiskHeatmap {
  scan_id: string;
  total_assets: number;
  average_risk_score: number;
  classification_distribution: Record<string, number>;
  assets: {
    asset_id: string;
    hostname: string;
    asset_type: string;
    score: number;
    classification: string;
    hndl_exposed: boolean;
    tnfl_risk: boolean;
  }[];
}

export interface EnterpriseRating {
  scan_id: string;
  enterprise_rating: number;
  label: string;
  total_assets: number;
  dimensions: Record<
    string,
    { score: number; weight: number; [key: string]: unknown }
  >;
}

// ─── Compliance ────────────────────────────────────────────────
export interface ComplianceDetail {
  asset_id: string;
  hostname: string | null;
  fips_203_deployed: boolean;
  fips_204_deployed: boolean;
  fips_205_deployed: boolean;
  tls_13_enforced: boolean;
  forward_secrecy: boolean;
  hybrid_mode_active: boolean;
  classical_deprecated: boolean;
  cert_key_adequate: boolean;
  ct_logged: boolean;
  chain_valid: boolean;
  rbi_compliant: boolean;
  sebi_compliant: boolean;
  pci_compliant: boolean;
  npci_compliant: boolean;
  crypto_agility_score: number;
  compliance_pct: number;
}

export interface FIPSMatrix {
  scan_id: string;
  total_assets: number;
  columns: string[];
  column_pass_rates: Record<string, number>;
  assets: Record<string, unknown>[];
}

export interface RegulatoryDeadline {
  name: string;
  jurisdiction: string;
  deadline: string;
  description: string;
  days_remaining: number;
  urgency: string;
  compliance_pct: number | null;
}

// ─── Topology ──────────────────────────────────────────────────
export interface TopologyNode {
  id: string;
  label: string;
  type: string;
  risk_level: string | null;
  metadata: Record<string, unknown>;
}

export interface TopologyEdge {
  source: string;
  target: string;
  type: string;
}

export interface TopologyGraph {
  scan_id: string;
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  stats: Record<string, unknown>;
}

// ─── GeoIP ─────────────────────────────────────────────────────
export interface GeoMarker {
  ip: string;
  hostname: string | null;
  lat: number;
  lon: number;
  city: string | null;
  country: string | null;
  country_code: string | null;
  org: string | null;
  asset_type: string | null;
  risk_score: number | null;
  risk_classification: string | null;
  hndl_exposed: boolean | null;
}

export interface GeoMapData {
  scan_id: string;
  total_markers: number;
  markers: GeoMarker[];
  country_summary: Record<string, { country: string; count: number; vulnerable: number }>;
}

// ─── AI ────────────────────────────────────────────────────────
export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  mode_used?: string;
  sources?: string[];
  timestamp?: string;
}

export interface ChatResponse {
  response: string;
  mode_used: string;
  sources: string[];
}

export interface AIStatus {
  deployment_mode: string;
  active_tier: string;
  vector_store: string;
  tabular_agent: string;
}

export interface AIModelsResponse {
  mode: string;
  tier: string;
  models: string[];
}

// ─── Reports ───────────────────────────────────────────────────
export interface ReportRecord {
  scan_id: string;
  generated_at: string;
  type: string;
  filename: string;
}

// ─── Helpers ───────────────────────────────────────────────────
export type RiskClassification =
  | "quantum_critical"
  | "quantum_vulnerable"
  | "quantum_at_risk"
  | "quantum_aware"
  | "quantum_ready";

export const RISK_COLORS: Record<string, string> = {
  quantum_critical: "#ef4444",
  quantum_vulnerable: "#f97316",
  quantum_at_risk: "#eab308",
  quantum_aware: "#3b82f6",
  quantum_ready: "#22c55e",
};

export const RISK_LABELS: Record<string, string> = {
  quantum_critical: "Quantum Critical",
  quantum_vulnerable: "Quantum Vulnerable",
  quantum_at_risk: "Quantum At Risk",
  quantum_aware: "Quantum Aware",
  quantum_ready: "Quantum Ready",
};
