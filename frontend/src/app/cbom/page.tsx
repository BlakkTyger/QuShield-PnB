"use client";

import { useState, useEffect } from "react";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from "recharts";
import { Download, Search, ChevronRight, Shield } from "lucide-react";
import { useScans, useAssets, useCBOMForAsset, useCBOMAggregate, useCBOMAlgorithms } from "@/lib/hooks";
import { RiskBadge, EmptyState, Skeleton, ScanSelector } from "@/components/ui";

const NIST_COLORS: Record<number, string> = {
  [-1]: "#6b7280",
  0: "#ef4444",
  1: "#f97316",
  2: "#eab308",
  3: "#22c55e",
  4: "#14b8a6",
  5: "#3b82f6",
};

const NIST_LABELS: Record<number, string> = {
  [-1]: "Unknown",
  0: "L0 — Vulnerable",
  1: "L1 — Minimal",
  2: "L2 — Low",
  3: "L3 — Moderate",
  4: "L4 — High",
  5: "L5 — Full",
};

export default function CBOMPage() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const [assetSearch, setAssetSearch] = useState("");

  const { data: scans } = useScans();
  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("qushield_scan_id") : null;
    if (stored) { setScanId(stored); return; }
    if (scans?.length) {
      const completed = scans.find((s) => s.status === "completed");
      if (completed) setScanId(completed.scan_id);
    }
  }, [scans]);

  const { data: assetsData } = useAssets(scanId, { limit: 500 });
  const { data: cbom } = useCBOMForAsset(selectedAssetId);
  const { data: aggregate } = useCBOMAggregate(scanId);
  const { data: algorithms } = useCBOMAlgorithms(scanId);

  // Filter assets by search
  const filteredAssets = assetsData?.items.filter(
    (a) => !assetSearch || a.hostname.toLowerCase().includes(assetSearch.toLowerCase())
  );

  const algoData = algorithms?.algorithms
    ? algorithms.algorithms
      .map((algo: any) => ({ name: algo.name, value: algo.count }))
      .sort((a: { value: number }, b: { value: number }) => b.value - a.value)
    : [];

  const ALGO_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#22c55e", "#8b5cf6", "#ec4899", "#14b8a6"];

  const handleDownloadCBOM = async () => {
    if (!selectedAssetId) return;
    try {
      const res = await fetch(`/api/v1/cbom/asset/${selectedAssetId}/export`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `cbom_${selectedAssetId.slice(0, 8)}.cdx.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error("Download failed:", e);
    }
  };

  if (!scanId) {
    return <EmptyState message="No scan data available. Run a Quick Scan first." />;
  }

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between mb-2">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            CBOM Explorer
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Cryptographic Bill of Materials — {aggregate?.total_components || 0} components across{" "}
            {aggregate?.total_assets || 0} assets
          </p>
        </div>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>

      {/* Top: Aggregate Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Algorithm Distribution */}
        <div className="glass-card-static p-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Algorithm Distribution
          </h3>
          {algoData.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={algoData.slice(0, 10)} margin={{ left: 10, right: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
                <XAxis
                  dataKey="name"
                  tick={{ fill: "var(--chart-tick)", fontSize: 9 }}
                  angle={-30}
                  textAnchor="end"
                  height={60}
                />
                <YAxis tick={{ fill: "var(--chart-tick)", fontSize: 11 }} />
                <Tooltip
                  contentStyle={{
                    background: "var(--tooltip-bg)", border: "1px solid var(--tooltip-border)",
                    borderRadius: 8, fontSize: 12, color: "var(--tooltip-text)",
                  }}
                  itemStyle={{ color: "var(--tooltip-text)" }}
                  labelStyle={{ color: "var(--tooltip-text)" }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {algoData.slice(0, 10).map((_, i) => (
                    <Cell key={i} fill={ALGO_COLORS[i % ALGO_COLORS.length]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <Skeleton height={250} />
          )}
        </div>

        {/* Quantum Readiness */}
        <div className="glass-card-static p-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            NIST Quantum Level Distribution
          </h3>
          {aggregate?.nist_level_distribution ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={Object.entries(aggregate.nist_level_distribution).map(([lvl, cnt]) => {
                    const parsedLvl = parseInt(lvl.replace('L', ''));
                    return {
                      name: NIST_LABELS[parsedLvl] || `Level ${parsedLvl}`,
                      value: cnt as number,
                    };
                  })}
                  innerRadius={45}
                  outerRadius={80}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {Object.keys(aggregate.nist_level_distribution).map((lvl, i) => {
                    const parsedLvl = parseInt(lvl.replace('L', ''));
                    return <Cell key={i} fill={NIST_COLORS[parsedLvl] || "#6b7280"} />;
                  })}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "var(--tooltip-bg)", border: "1px solid var(--tooltip-border)",
                    borderRadius: 8, fontSize: 12, color: "var(--tooltip-text)",
                  }}
                  itemStyle={{ color: "var(--tooltip-text)" }}
                  labelStyle={{ color: "var(--tooltip-text)" }}
                />
                <Legend
                  formatter={(value) => <span style={{ color: "var(--chart-tick)", fontSize: 10 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <Skeleton height={250} />
          )}
          {aggregate && (
            <div className="text-center mt-2">
              <span className="text-sm font-bold" style={{ color: "var(--accent-gold)" }}>
                {aggregate.quantum_ready_pct?.toFixed(1)}%
              </span>
              <span className="text-xs ml-1" style={{ color: "var(--text-muted)" }}>
                quantum-ready
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Bottom: Asset List + CBOM Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Asset selector */}
        <div className="glass-card-static p-4">
          <div className="relative mb-3">
            <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "var(--text-muted)" }} />
            <input
              type="text"
              placeholder="Search asset…"
              className="w-full py-2 pl-8 pr-3 text-xs rounded-lg"
              style={{
                background: "var(--input-bg)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-primary)",
                outline: "none",
              }}
              value={assetSearch}
              onChange={(e) => setAssetSearch(e.target.value)}
            />
          </div>
          <div className="max-h-[400px] overflow-y-auto space-y-1">
            {filteredAssets?.map((asset) => (
              <button
                key={asset.id}
                onClick={() => setSelectedAssetId(asset.id)}
                className="w-full text-left px-3 py-2.5 rounded-lg flex items-center justify-between transition-colors"
                style={{
                  background: selectedAssetId === asset.id ? "var(--accent-gold-dim)" : "transparent",
                  color: selectedAssetId === asset.id ? "var(--accent-gold)" : "var(--text-secondary)",
                }}
              >
                <div className="truncate">
                  <div className="text-xs font-medium truncate">{asset.hostname}</div>
                  <div className="text-[10px]" style={{ color: "var(--text-muted)" }}>
                    {asset.asset_type || "unknown"}
                  </div>
                </div>
                <ChevronRight size={12} />
              </button>
            ))}
          </div>
        </div>

        {/* Right: CBOM Detail */}
        <div className="glass-card-static p-6 lg:col-span-2">
          {selectedAssetId && cbom ? (
            <div>
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                    {cbom.hostname || "Asset CBOM"}
                  </h3>
                  <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                    {cbom.total_components} components •{" "}
                    {cbom.quantum_ready_pct?.toFixed(1)}% quantum-ready •{" "}
                    CycloneDX {cbom.spec_version}
                  </p>
                </div>
                <button className="btn-outline text-xs" onClick={handleDownloadCBOM}>
                  <Download size={12} /> Download JSON
                </button>
              </div>

              {/* Components Table */}
              <div className="overflow-x-auto">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Component</th>
                      <th>Type</th>
                      <th>Key Length</th>
                      <th>NIST Level</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cbom.components?.map((comp, i) => (
                      <tr key={comp.id || i}>
                        <td>
                          <span className="font-medium" style={{ color: "var(--text-primary)" }}>
                            {comp.name || comp.bom_ref || "—"}
                          </span>
                        </td>
                        <td>
                          <span
                            className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase"
                            style={{
                              background: "var(--bg-card)",
                              border: "1px solid var(--border-subtle)",
                            }}
                          >
                            {comp.component_type || "—"}
                          </span>
                        </td>
                        <td>{comp.key_length ? `${comp.key_length} bit` : "—"}</td>
                        <td>
                          <span
                            className="font-bold"
                            style={{
                              color: NIST_COLORS[comp.nist_quantum_level ?? -1] || "#6b7280",
                            }}
                          >
                            {comp.nist_quantum_level === -1 || comp.nist_quantum_level == null ? "Unknown" : `L${comp.nist_quantum_level}`}
                          </span>
                        </td>
                        <td>
                          {(comp as any).is_quantum_vulnerable ? (
                            <span className="badge badge-critical">Vulnerable</span>
                          ) : (
                            <span className="badge badge-ready">Safe</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-[300px]">
              <Shield size={32} style={{ color: "var(--text-muted)" }} />
              <p className="text-sm mt-3" style={{ color: "var(--text-muted)" }}>
                Select an asset to view its CBOM
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
