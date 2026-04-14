"use client";

import { useState, useEffect, useMemo } from "react";
import { Search, Download, X, ExternalLink, ChevronUp, ChevronDown } from "lucide-react";
import { useScans, useAssets, useAssetDetail } from "@/lib/hooks";
import { RiskBadge, EmptyState, Skeleton, ScanSelector } from "@/components/ui";
import type { Asset } from "@/lib/types";

const RISK_FILTERS = [
  { value: "", label: "All Risk Levels" },
  { value: "quantum_critical", label: "Quantum Critical" },
  { value: "quantum_vulnerable", label: "Quantum Vulnerable" },
  { value: "quantum_at_risk", label: "Quantum At Risk" },
  { value: "quantum_aware", label: "Quantum Aware" },
  { value: "quantum_ready", label: "Quantum Ready" },
];

export default function AssetsPage() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [selectedAsset, setSelectedAsset] = useState<string | null>(null);
  const [sortField, setSortField] = useState<string>("risk_score");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const { data: scans } = useScans();
  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("qushield_scan_id") : null;
    if (stored) { setScanId(stored); return; }
    if (scans?.length) {
      const sorted = [...scans].sort(
        (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      );
      const preferred = sorted.find((s) => s.status === "running" || s.status === "completed");
      setScanId((preferred || sorted[0]).scan_id);
    }
  }, [scans]);

  const { data: assetsData, isLoading } = useAssets(scanId, {
    risk_class: riskFilter || undefined,
    q: search || undefined,
    limit: 500,
  });

  const { data: assetDetail } = useAssetDetail(selectedAsset);

  // Client-side sort
  const sortedAssets = useMemo(() => {
    if (!assetsData?.items) return [];
    const items = [...assetsData.items];
    items.sort((a, b) => {
      const aVal = (a as unknown as Record<string, unknown>)[sortField];
      const bVal = (b as unknown as Record<string, unknown>)[sortField];
      if (aVal == null && bVal == null) return 0;
      if (aVal == null) return 1;
      if (bVal == null) return -1;
      if (typeof aVal === "number" && typeof bVal === "number") {
        return sortDir === "asc" ? aVal - bVal : bVal - aVal;
      }
      return sortDir === "asc"
        ? String(aVal).localeCompare(String(bVal))
        : String(bVal).localeCompare(String(aVal));
    });
    return items;
  }, [assetsData, sortField, sortDir]);

  const toggleSort = (field: string) => {
    if (sortField === field) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  };

  const SortIcon = ({ field }: { field: string }) => {
    if (sortField !== field) return null;
    return sortDir === "asc" ? <ChevronUp size={12} /> : <ChevronDown size={12} />;
  };

  const transitionLabel = (state?: string | null) => {
    if (state === "full_pqc_transition") return "Full PQC";
    if (state === "partial_pqc_transition") return "Partial PQC";
    if (state === "classical_only") return "Classical";
    return "Unknown";
  };

  const handleExportCSV = () => {
    if (!sortedAssets.length) return;
    const headers = [
      "Hostname",
      "IP Address",
      "Type",
      "TLS Version",
      "TLS Key Exchange",
      "Cert Key Type",
      "Transition State",
      "Risk Score",
      "Risk Class",
      "Cert Expiry (Days)"
    ];
    const rows = sortedAssets.map((a) => [
      a.hostname,
      a.ip_address || "",
      a.asset_type || "",
      a.tls_version || "",
      a.tls_key_exchange || a.key_exchange || "",
      a.cert_key_type || "",
      transitionLabel(a.crypto_transition_state),
      a.risk_score ?? "",
      a.risk_classification || "",
      a.cert_expiry_days ?? "",
    ]);

    const csvContent = [headers, ...rows]
      .map((row) => row.map((val) => `"${String(val).replace(/"/g, '""')}"`).join(","))
      .join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `qushield_assets_${scanId?.slice(0, 8)}.csv`;
    link.click();
    URL.revokeObjectURL(url);
  };

  if (!scanId) {
    return <EmptyState message="No scan data available. Run a Quick Scan first." />;
  }

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            Asset Inventory
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            {assetsData?.total || 0} assets discovered
          </p>
        </div>
        <div className="flex items-center gap-3">
          <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
          <button className="btn-outline" onClick={handleExportCSV}>
            <Download size={14} /> Export CSV
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex gap-3 mb-6">
        <div className="relative flex-1">
          <Search
            size={14}
            className="absolute left-3 top-1/2 -translate-y-1/2"
            style={{ color: "var(--text-muted)" }}
          />
          <input
            type="text"
            placeholder="Search hostname, IP, type…"
            className="w-full py-2.5 pl-9 pr-3 text-sm rounded-lg"
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-subtle)",
              color: "var(--text-primary)",
              outline: "none",
            }}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="py-2.5 px-4 text-sm rounded-lg"
          style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border-subtle)",
            color: "var(--text-primary)",
            outline: "none",
          }}
          value={riskFilter}
          onChange={(e) => setRiskFilter(e.target.value)}
        >
          {RISK_FILTERS.map((f) => (
            <option key={f.value} value={f.value}>
              {f.label}
            </option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="glass-card-static overflow-hidden">
        <div className="overflow-x-auto max-h-[calc(100vh-280px)] overflow-y-auto">
          {isLoading ? (
            <div className="p-8">
              {[...Array(8)].map((_, i) => (
                <Skeleton key={i} height={40} className="mb-2" />
              ))}
            </div>
          ) : sortedAssets.length === 0 ? (
            <EmptyState message="No assets match your filters." />
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  {[
                    { key: "hostname", label: "Hostname" },
                    { key: "ip_address", label: "IP Address" },
                    { key: "asset_type", label: "Type" },
                    { key: "tls_version", label: "TLS" },
                    { key: "tls_key_exchange", label: "TLS Key Exchange" },
                    { key: "cert_key_type", label: "Cert Key Type" },
                    { key: "crypto_transition_state", label: "Transition State" },
                    { key: "risk_score", label: "Risk Score" },
                    { key: "risk_classification", label: "Risk Class" },
                    { key: "cert_expiry_days", label: "Cert Expiry" },
                  ].map((col) => (
                    <th
                      key={col.key}
                      className="cursor-pointer select-none"
                      onClick={() => toggleSort(col.key)}
                    >
                      <span className="flex items-center gap-1">
                        {col.label} <SortIcon field={col.key} />
                      </span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sortedAssets.map((asset) => (
                  <tr
                    key={asset.id}
                    className="cursor-pointer"
                    onClick={() => setSelectedAsset(asset.id)}
                  >
                    <td>
                      <span className="font-medium" style={{ color: "var(--text-primary)" }}>
                        {asset.hostname}
                      </span>
                    </td>
                    <td>{asset.ip_address || "—"}</td>
                    <td>
                      {asset.asset_type && (
                        <span
                          className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase"
                          style={{
                            background: "var(--bg-card)",
                            border: "1px solid var(--border-subtle)",
                            color: "var(--text-secondary)",
                          }}
                        >
                          {asset.asset_type}
                        </span>
                      )}
                    </td>
                    <td>{asset.tls_version || "—"}</td>
                    <td className="max-w-[150px] truncate">{asset.tls_key_exchange || asset.key_exchange || "—"}</td>
                    <td>{asset.cert_key_type || "—"}</td>
                    <td>{transitionLabel(asset.crypto_transition_state)}</td>
                    <td>
                      <span
                        className="font-bold"
                        style={{
                          color:
                            (asset.risk_score || 0) >= 700
                              ? "var(--risk-critical)"
                              : (asset.risk_score || 0) >= 500
                                ? "var(--risk-vulnerable)"
                                : "var(--text-primary)",
                        }}
                      >
                        {asset.risk_score ?? "—"}
                      </span>
                    </td>
                    <td>
                      {asset.risk_classification && (
                        <RiskBadge classification={asset.risk_classification} />
                      )}
                    </td>
                    <td>
                      {asset.cert_expiry_days != null ? (
                        <span
                          style={{
                            color:
                              asset.cert_expiry_days < 30
                                ? "var(--risk-critical)"
                                : asset.cert_expiry_days < 90
                                  ? "var(--risk-at-risk)"
                                  : "var(--text-secondary)",
                          }}
                        >
                          {asset.cert_expiry_days}d
                        </span>
                      ) : (
                        "—"
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Slide-out Detail Panel */}
      {selectedAsset && (
        <>
          <div
            className="fixed inset-0 z-40"
            style={{ background: "rgba(0,0,0,0.5)" }}
            onClick={() => setSelectedAsset(null)}
          />
          <div className="slide-panel p-6">
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>
                Asset Detail
              </h2>
              <button
                onClick={() => setSelectedAsset(null)}
                style={{ color: "var(--text-muted)" }}
              >
                <X size={20} />
              </button>
            </div>

            {assetDetail ? (
              <div className="space-y-5">
                <div>
                  <span className="text-xs font-semibold uppercase" style={{ color: "var(--text-muted)" }}>
                    Hostname
                  </span>
                  <p className="text-base font-bold" style={{ color: "var(--text-primary)" }}>
                    {assetDetail.hostname}
                  </p>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>IP</span>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>{assetDetail.ip_address || "—"}</p>
                  </div>
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>Type</span>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>{assetDetail.asset_type || "—"}</p>
                  </div>
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>TLS</span>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>{assetDetail.tls_version || "—"}</p>
                  </div>
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>Key Exchange</span>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>
                      {assetDetail.tls_key_exchange || assetDetail.key_exchange || "—"}
                    </p>
                  </div>
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>Cert Key Type</span>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>{assetDetail.cert_key_type || "—"}</p>
                  </div>
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>Cert Plane</span>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>{assetDetail.cert_crypto_plane || "—"}</p>
                  </div>
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>KEX Plane</span>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>{assetDetail.kex_crypto_plane || "—"}</p>
                  </div>
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>Transition</span>
                    <p className="text-sm" style={{ color: "var(--text-primary)" }}>{transitionLabel(assetDetail.crypto_transition_state)}</p>
                  </div>
                </div>

                {assetDetail.risk_classification && (
                  <div>
                    <span className="text-xs" style={{ color: "var(--text-muted)" }}>Risk</span>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-xl font-black" style={{ color: "var(--text-primary)" }}>
                        {assetDetail.risk_score}
                      </span>
                      <RiskBadge classification={assetDetail.risk_classification} />
                    </div>
                  </div>
                )}

                {/* Ports */}
                {assetDetail.ports?.length > 0 && (
                  <div>
                    <span className="text-xs font-semibold uppercase" style={{ color: "var(--text-muted)" }}>
                      Open Ports
                    </span>
                    <div className="flex flex-wrap gap-2 mt-2">
                      {assetDetail.ports.map((p, i) => (
                        <span
                          key={i}
                          className="px-2 py-1 rounded text-xs font-mono"
                          style={{
                            background: "var(--bg-card)",
                            border: "1px solid var(--border-subtle)",
                            color: "var(--text-secondary)",
                          }}
                        >
                          {p.port}/{p.protocol}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Certificates */}
                {assetDetail.certificates?.length > 0 && (
                  <div>
                    <span className="text-xs font-semibold uppercase" style={{ color: "var(--text-muted)" }}>
                      Certificates
                    </span>
                    {assetDetail.certificates.map((cert, i) => (
                      <div
                        key={i}
                        className="mt-2 p-3 rounded-lg"
                        style={{ background: "var(--bg-card)" }}
                      >
                        <p className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
                          {cert.subject || "Unknown"}
                        </p>
                        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                          Issuer: {cert.issuer || "—"} • {cert.key_type} {cert.key_length}
                        </p>
                        <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                          Valid: {cert.valid_from?.slice(0, 10)} → {cert.valid_to?.slice(0, 10)}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="space-y-4">
                {[...Array(5)].map((_, i) => <Skeleton key={i} height={30} />)}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
