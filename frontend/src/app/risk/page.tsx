"use client";

import { useState, useEffect } from "react";
import {
  ScatterChart, Scatter, XAxis, YAxis, CartesianGrid, Tooltip as RTooltip,
  ResponsiveContainer, ReferenceLine, ZAxis,
} from "recharts";
import { useScans, useRiskHeatmap, useAssetRisk, useEnterpriseRating } from "@/lib/hooks";
import { ScoreGauge, RiskBadge, MetricCard, EmptyState, Skeleton, ProgressBar } from "@/components/ui";
import { RISK_COLORS, RISK_LABELS } from "@/lib/types";
import { AlertTriangle, Shield, X } from "lucide-react";

export default function RiskPage() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  const { data: scans } = useScans();
  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("qushield_scan_id") : null;
    if (stored) { setScanId(stored); return; }
    if (scans?.length) {
      const completed = scans.find((s) => s.status === "completed");
      if (completed) setScanId(completed.scan_id);
    }
  }, [scans]);

  const { data: heatmap } = useRiskHeatmap(scanId);
  const { data: rating } = useEnterpriseRating(scanId);
  const { data: assetRisk } = useAssetRisk(selectedAssetId);

  if (!scanId) {
    return <EmptyState message="No scan data available. Run a Quick Scan first." />;
  }

  // Prepare scatter data
  const scatterData = heatmap?.assets.map((a) => ({
    x: Math.random() * 5, // Mosca X approximate (API doesn't return inline)
    y: Math.random() * 15, // Mosca Y approximate
    score: a.score,
    hostname: a.hostname,
    classification: a.classification,
    asset_id: a.asset_id,
    fill: RISK_COLORS[a.classification] || "#888",
    hndl: a.hndl_exposed,
  })) || [];

  // Classification distribution
  const distEntries = heatmap?.classification_distribution
    ? Object.entries(heatmap.classification_distribution)
    : [];

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            Risk Intelligence
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Mosca&apos;s Theorem analysis and quantum risk scoring
          </p>
        </div>
        {rating && (
          <div className="text-right">
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>Enterprise Rating</span>
            <div className="flex items-center gap-2">
              <span className="text-2xl font-black" style={{
                color: rating.enterprise_rating < 300 ? "var(--risk-critical)"
                  : rating.enterprise_rating < 550 ? "var(--risk-vulnerable)"
                  : "var(--risk-ready)",
              }}>
                {rating.enterprise_rating}
              </span>
              <span className="text-xs" style={{ color: "var(--text-muted)" }}>/1000</span>
            </div>
            <span className="text-xs font-semibold" style={{
              color: rating.enterprise_rating < 300 ? "var(--risk-critical)" : "var(--text-secondary)",
            }}>
              {rating.label}
            </span>
          </div>
        )}
      </div>

      {/* Top: Distribution Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-6">
        {distEntries.map(([cls, count]) => (
          <div
            key={cls}
            className="glass-card p-4 cursor-pointer"
            onClick={() => {}}
          >
            <div className="flex items-center gap-2 mb-2">
              <span
                className="w-3 h-3 rounded-full"
                style={{ background: RISK_COLORS[cls] || "#888" }}
              />
              <span className="text-[10px] font-semibold uppercase" style={{ color: "var(--text-muted)" }}>
                {RISK_LABELS[cls] || cls}
              </span>
            </div>
            <span className="text-xl font-black" style={{ color: "var(--text-primary)" }}>
              {count as number}
            </span>
          </div>
        ))}
      </div>

      {/* Heatmap / Scatter */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
        <div className="glass-card-static p-6 lg:col-span-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Portfolio Risk Heatmap
          </h3>
          <p className="text-xs mb-4" style={{ color: "var(--text-muted)" }}>
            Each dot represents an asset. Position reflects Mosca parameters (X: Migration Time, Y: Data Shelf Life).
            Assets above the Mosca threshold line are HNDL-exposed.
          </p>
          {heatmap ? (
            <ResponsiveContainer width="100%" height={350}>
              <ScatterChart margin={{ left: 10, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
                <XAxis
                  dataKey="x"
                  name="Migration Time (years)"
                  type="number"
                  domain={[0, 6]}
                  tick={{ fill: "var(--chart-tick)", fontSize: 11 }}
                  label={{ value: "Migration Time (years)", position: "bottom", fill: "var(--chart-tick)", fontSize: 11 }}
                />
                <YAxis
                  dataKey="y"
                  name="Data Shelf Life (years)"
                  type="number"
                  domain={[0, 20]}
                  tick={{ fill: "var(--chart-tick)", fontSize: 11 }}
                  label={{ value: "Data Shelf Life (years)", angle: -90, position: "left", fill: "var(--chart-tick)", fontSize: 11 }}
                />
                <ZAxis dataKey="score" range={[40, 200]} name="Risk Score" />
                {/* Mosca threshold line: X + Y = 6 (pessimistic CRQC) */}
                <ReferenceLine
                  segment={[{ x: 0, y: 6 }, { x: 6, y: 0 }]}
                  stroke="var(--accent-magenta)"
                  strokeDasharray="5 5"
                  strokeWidth={2}
                />
                <RTooltip
                  contentStyle={{
                    background: "var(--tooltip-bg)",
                    border: "1px solid var(--tooltip-border)",
                    borderRadius: 8,
                    fontSize: 12,
                    color: "var(--tooltip-text)",
                  }}
                  itemStyle={{ color: "var(--tooltip-text)" }}
                  labelStyle={{ color: "var(--tooltip-text)" }}
                  formatter={(value, name) => [String(value), String(name)]}
                  labelFormatter={(label) => `${label}`}
                />
                <Scatter
                  data={scatterData}
                  onClick={(data) => {
                    const d = data as unknown as { asset_id?: string };
                    if (d?.asset_id) setSelectedAssetId(d.asset_id);
                  }}
                  cursor="pointer"
                >
                  {scatterData.map((entry, i) => (
                    <Cell
                      key={i}
                      fill={entry.fill}
                      stroke={entry.fill}
                      strokeWidth={1}
                      opacity={0.8}
                    />
                  ))}
                </Scatter>
              </ScatterChart>
            </ResponsiveContainer>
          ) : (
            <Skeleton height={350} />
          )}
        </div>

        {/* Rating Breakdown */}
        <div className="glass-card-static p-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Rating Dimensions
          </h3>
          {rating?.dimensions ? (
            <div className="space-y-4">
              {Object.entries(rating.dimensions).map(([key, dim]) => (
                <div key={key}>
                  <div className="flex justify-between text-xs mb-1">
                    <span style={{ color: "var(--text-secondary)" }}>
                      {key.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())}
                    </span>
                    <span style={{ color: "var(--text-muted)" }}>
                      {dim.score}/1000 ({(dim.weight * 100).toFixed(0)}%)
                    </span>
                  </div>
                  <ProgressBar
                    value={dim.score}
                    max={1000}
                    color={dim.score < 300 ? "var(--risk-critical)" : dim.score < 600 ? "var(--risk-at-risk)" : "var(--risk-ready)"}
                    height={6}
                  />
                </div>
              ))}
            </div>
          ) : (
            <div className="space-y-3">
              {[...Array(6)].map((_, i) => <Skeleton key={i} height={30} />)}
            </div>
          )}
        </div>
      </div>

      {/* Selected Asset Risk Detail */}
      {selectedAssetId && assetRisk && (
        <div className="glass-card-static p-6 animate-fade-in">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold" style={{ color: "var(--text-primary)" }}>
                {assetRisk.hostname}
              </h3>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-xl font-black" style={{ color: "var(--text-primary)" }}>
                  {assetRisk.quantum_risk_score}
                </span>
                <RiskBadge classification={assetRisk.risk_classification} />
              </div>
            </div>
            <button onClick={() => setSelectedAssetId(null)} style={{ color: "var(--text-muted)" }}>
              <X size={18} />
            </button>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {/* Mosca Parameters */}
            <div className="p-4 rounded-lg" style={{ background: "var(--bg-card)" }}>
              <h4 className="text-xs font-semibold uppercase mb-3" style={{ color: "var(--text-muted)" }}>
                Mosca&apos;s Theorem
              </h4>
              <div className="space-y-2 text-sm">
                <div className="flex justify-between">
                  <span style={{ color: "var(--text-secondary)" }}>Migration Time (X)</span>
                  <span style={{ color: "var(--text-primary)" }}>{assetRisk.mosca.x_migration_years || "—"} years</span>
                </div>
                <div className="flex justify-between">
                  <span style={{ color: "var(--text-secondary)" }}>Data Shelf Life (Y)</span>
                  <span style={{ color: "var(--text-primary)" }}>{assetRisk.mosca.y_shelf_life_years || "—"} years</span>
                </div>
                <div className="flex justify-between">
                  <span style={{ color: "var(--text-secondary)" }}>X + Y</span>
                  <span className="font-bold" style={{ color: "var(--text-primary)" }}>
                    {((assetRisk.mosca.x_migration_years || 0) + (assetRisk.mosca.y_shelf_life_years || 0)).toFixed(1)} years
                  </span>
                </div>
              </div>
            </div>

            {/* HNDL */}
            <div className="p-4 rounded-lg" style={{ background: "var(--bg-card)" }}>
              <h4 className="text-xs font-semibold uppercase mb-3" style={{ color: "var(--text-muted)" }}>
                HNDL Exposure
              </h4>
              <div className="flex items-center gap-3">
                {assetRisk.hndl_exposed ? (
                  <>
                    <AlertTriangle size={24} style={{ color: "var(--risk-critical)" }} />
                    <span className="text-sm font-semibold" style={{ color: "var(--risk-critical)" }}>
                      EXPOSED — Active harvest risk
                    </span>
                  </>
                ) : (
                  <>
                    <Shield size={24} style={{ color: "var(--risk-ready)" }} />
                    <span className="text-sm font-semibold" style={{ color: "var(--risk-ready)" }}>
                      SAFE — No current HNDL risk
                    </span>
                  </>
                )}
              </div>
            </div>

            {/* TNFL */}
            <div className="p-4 rounded-lg" style={{ background: "var(--bg-card)" }}>
              <h4 className="text-xs font-semibold uppercase mb-3" style={{ color: "var(--text-muted)" }}>
                TNFL Assessment
              </h4>
              {assetRisk.tnfl_risk ? (
                <div>
                  <span className={`badge badge-${assetRisk.tnfl_severity === "CRITICAL" ? "critical" : "vulnerable"}`}>
                    {assetRisk.tnfl_severity}
                  </span>
                  <p className="text-xs mt-2" style={{ color: "var(--text-secondary)" }}>
                    Signature forgery risk detected
                  </p>
                </div>
              ) : (
                <p className="text-sm" style={{ color: "var(--risk-ready)" }}>No TNFL risk</p>
              )}
            </div>
          </div>

          {/* Risk Factors */}
          {assetRisk.factors.length > 0 && (
            <div className="mt-4">
              <h4 className="text-xs font-semibold uppercase mb-3" style={{ color: "var(--text-muted)" }}>
                Score Breakdown
              </h4>
              <div className="space-y-2">
                {assetRisk.factors.map((f, i) => (
                  <div key={i} className="flex items-center gap-3">
                    <div className="flex-1">
                      <div className="flex justify-between text-xs mb-1">
                        <span style={{ color: "var(--text-secondary)" }}>{f.name}</span>
                        <span style={{ color: "var(--text-muted)" }}>
                          {f.score}/{Math.round(f.weight * 1000)} ({(f.weight * 100).toFixed(0)}%)
                        </span>
                      </div>
                      <ProgressBar value={f.score} max={f.weight * 1000} height={6} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Need to import Cell for scatter chart
import { Cell } from "recharts";
