"use client";

import { useState, useEffect } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import { ShieldAlert, Clock, Target, TrendingUp } from "lucide-react";
import {
  useScans, useScanSummary, useEnterpriseRating,
  useRiskHeatmap, useRegulatoryDeadlines, useCBOMAlgorithms,
} from "@/lib/hooks";
import { ScoreGauge, MetricCard, RiskBadge, ProgressBar, EmptyState, Skeleton } from "@/components/ui";
import { RISK_COLORS, RISK_LABELS } from "@/lib/types";

export default function DashboardPage() {
  const [scanId, setScanId] = useState<string | null>(null);

  // Get latest completed scan
  const { data: scans, isLoading: scansLoading } = useScans();

  useEffect(() => {
    // Try localStorage first
    const stored = typeof window !== "undefined" ? localStorage.getItem("qushield_scan_id") : null;
    if (stored) { setScanId(stored); return; }
    // Otherwise use latest completed scan
    if (scans?.length) {
      const completed = scans.find((s) => s.status === "completed");
      if (completed) setScanId(completed.scan_id);
    }
  }, [scans]);

  const { data: summary } = useScanSummary(scanId);
  const { data: rating } = useEnterpriseRating(scanId);
  const { data: heatmap } = useRiskHeatmap(scanId);
  const { data: deadlines } = useRegulatoryDeadlines();
  const { data: algorithms } = useCBOMAlgorithms(scanId);

  if (scansLoading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="grid grid-cols-4 gap-4">{[...Array(4)].map((_, i) => <Skeleton key={i} height={100} />)}</div>
        <Skeleton height={400} />
      </div>
    );
  }

  if (!scanId || !summary) {
    return (
      <EmptyState message="No scan data available. Run a Quick Scan first to populate the dashboard." />
    );
  }

  // Prepare chart data
  const riskDistData = Object.entries(summary.risk_breakdown).map(([key, val]) => ({
    name: RISK_LABELS[key] || key,
    value: val as number,
    fill: RISK_COLORS[key] || "#888",
  }));

  const algoData = (() => {
    const raw = algorithms?.algorithms;
    if (!raw) return [];
    if (Array.isArray(raw)) {
      return (raw as any[]).map((entry) => ({
        name: (entry.name as string) || "Unknown",
        value: (entry.count as number) || 0,
        vulnerable: (entry.is_quantum_vulnerable as boolean) || false,
      }));
    }
    // fallback: dict {name: count | object}
    return Object.entries(raw).map(([name, entry]) => {
      const count = typeof entry === "object" && entry !== null ? ((entry as any).count ?? 1) : (entry as number);
      const vulnerable = typeof entry === "object" && entry !== null ? (entry as any).is_quantum_vulnerable : false;
      return { name, value: count, vulnerable };
    });
  })();

  const ALGO_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#22c55e", "#8b5cf6", "#ec4899", "#14b8a6"];

  const hndlCount = typeof summary?.total_assets === "number"
    ? Math.min(heatmap?.assets.filter((a) => a.hndl_exposed).length || 0, summary.total_assets)
    : heatmap?.assets.filter((a) => a.hndl_exposed).length || 0;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            Dashboard
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Organization quantum posture overview — {summary.targets.join(", ")}
          </p>
        </div>
        <div className="text-xs" style={{ color: "var(--text-muted)" }}>
          Last scan: {summary.completed_at ? new Date(summary.completed_at).toLocaleString() : "—"}
        </div>
      </div>

      {/* Top 4 Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="glass-card p-5 flex flex-col items-center">
          <span className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: "var(--text-muted)" }}>
            Quantum Rating
          </span>
          <ScoreGauge score={rating?.enterprise_rating || 0} size={120} label={rating?.label || ""} />
        </div>

        <MetricCard
          title="Assets at HNDL Risk"
          value={hndlCount}
          subtitle={`of ${summary.total_assets} total assets`}
          icon={<ShieldAlert size={18} />}
          color="var(--risk-vulnerable)"
        />

        <MetricCard
          title="Certificates"
          value={summary.total_certificates}
          subtitle={`${summary.compliance_summary.tls_13_enforced} TLS 1.3 enforced`}
          icon={<Clock size={18} />}
        />

        <MetricCard
          title="Compliance"
          value={`${summary.compliance_summary.avg_compliance_pct}%`}
          subtitle={`Agility: ${summary.compliance_summary.avg_agility_score}/100`}
          icon={<Target size={18} />}
          color={summary.compliance_summary.avg_compliance_pct < 50 ? "var(--risk-vulnerable)" : "var(--risk-ready)"}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Asset Risk Distribution */}
        <div className="glass-card-static p-6 lg:col-span-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Asset Risk Distribution
          </h3>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={riskDistData} layout="vertical" margin={{ left: 20, right: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
              <XAxis type="number" tick={{ fill: "var(--chart-tick)", fontSize: 11 }} />
              <YAxis dataKey="name" type="category" tick={{ fill: "var(--chart-tick)", fontSize: 11 }} width={130} />
              <Tooltip
                contentStyle={{
                  background: "var(--tooltip-bg)",
                  border: "1px solid var(--tooltip-border)",
                  borderRadius: 8,
                  fontSize: 12,
                  color: "var(--tooltip-text)",
                }}
                itemStyle={{ color: "var(--tooltip-text)" }}
                labelStyle={{ color: "var(--tooltip-text)" }}
              />
              <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                {riskDistData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Algorithm Exposure Grid */}
        <div className="glass-card-static p-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Algorithm Exposure
          </h3>
          {algoData.length > 0 ? (
            <div className="flex flex-col gap-3 max-h-[260px] overflow-y-auto pr-1">
              {algoData
                .sort((a, b) => (b.value as number) - (a.value as number))
                .slice(0, 20)
                .map((algo, i) => {
                  const pct = Math.round(((algo.value as number) / algoData.reduce((s, x) => s + (x.value as number), 0)) * 100);
                  const barColor = algo.vulnerable ? "var(--risk-critical)" : ALGO_COLORS[i % ALGO_COLORS.length];
                  return (
                    <div key={algo.name} className="flex items-center gap-2">
                      <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: barColor }} />
                      <span
                        className="text-xs flex-1 truncate"
                        style={{ color: algo.vulnerable ? "var(--risk-critical)" : "var(--text-secondary)" }}
                        title={algo.vulnerable ? `${algo.name} — Quantum Vulnerable` : algo.name}
                      >
                        {algo.name}
                      </span>
                      <span className="text-xs font-bold flex-shrink-0" style={{ color: "var(--text-muted)" }}>
                        {algo.value}
                      </span>
                      <div className="w-16 h-1.5 rounded-full overflow-hidden flex-shrink-0" style={{ background: "var(--border-subtle)" }}>
                        <div className="h-full rounded-full" style={{ width: `${pct}%`, background: barColor }} />
                      </div>
                    </div>
                  );
                })}
            </div>
          ) : (
            <div className="flex items-center justify-center h-[260px]" style={{ color: "var(--text-muted)" }}>
              No algorithm data
            </div>
          )}
        </div>
      </div>

      {/* Bottom: Regulatory Deadlines & PQC Adoption */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Regulatory Deadlines */}
        <div className="glass-card-static p-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Regulatory Deadline Countdown
          </h3>
          <div className="flex flex-col gap-3">
            {deadlines?.slice(0, 6).map((d) => (
              <div
                key={d.name}
                className="flex items-center justify-between p-3 rounded-lg"
                style={{ background: "var(--bg-card)" }}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span
                      className="w-2 h-2 rounded-full flex-shrink-0"
                      style={{
                        background:
                          d.urgency === "overdue"
                            ? "var(--urgency-overdue)"
                            : d.urgency === "critical"
                              ? "var(--urgency-critical)"
                              : d.urgency === "warning"
                                ? "var(--urgency-warning)"
                                : "var(--urgency-info)",
                      }}
                    />
                    <span className="text-sm font-medium truncate" style={{ color: "var(--text-primary)" }}>
                      {d.name}
                    </span>
                  </div>
                  <span className="text-[10px] ml-4" style={{ color: "var(--text-muted)" }}>
                    {d.jurisdiction} — {d.deadline}
                  </span>
                </div>
                <span
                  className="text-sm font-bold ml-3 whitespace-nowrap"
                  style={{
                    color:
                      d.days_remaining < 0
                        ? "var(--risk-critical)"
                        : d.days_remaining < 90
                          ? "var(--risk-vulnerable)"
                          : "var(--text-secondary)",
                  }}
                >
                  {d.days_remaining < 0
                    ? `${Math.abs(d.days_remaining)}d overdue`
                    : `${d.days_remaining}d`}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* PQC Adoption + Misc */}
        <div className="flex flex-col gap-6">
          {/* PQC Adoption Progress */}
          <div className="glass-card-static p-6">
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
              PQC Adoption Progress
            </h3>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span style={{ color: "var(--text-secondary)" }}>Quantum Ready</span>
                  <span style={{ color: "var(--risk-ready)" }}>
                    {summary.risk_breakdown["quantum_ready"] || 0} / {summary.total_assets}
                  </span>
                </div>
                <ProgressBar
                  value={summary.risk_breakdown["quantum_ready"] || 0}
                  max={summary.total_assets}
                  color="var(--risk-ready)"
                />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span style={{ color: "var(--text-secondary)" }}>Quantum Aware</span>
                  <span style={{ color: "var(--risk-aware)" }}>
                    {summary.risk_breakdown["quantum_aware"] || 0} / {summary.total_assets}
                  </span>
                </div>
                <ProgressBar
                  value={summary.risk_breakdown["quantum_aware"] || 0}
                  max={summary.total_assets}
                  color="var(--risk-aware)"
                />
              </div>
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span style={{ color: "var(--text-secondary)" }}>At Risk + Vulnerable + Critical</span>
                  <span style={{ color: "var(--risk-critical)" }}>
                    {(summary.risk_breakdown["quantum_at_risk"] || 0) +
                      (summary.risk_breakdown["quantum_vulnerable"] || 0) +
                      (summary.risk_breakdown["quantum_critical"] || 0)} / {summary.total_assets}
                  </span>
                </div>
                <ProgressBar
                  value={
                    (summary.risk_breakdown["quantum_at_risk"] || 0) +
                    (summary.risk_breakdown["quantum_vulnerable"] || 0) +
                    (summary.risk_breakdown["quantum_critical"] || 0)
                  }
                  max={summary.total_assets}
                  color="var(--risk-critical)"
                />
              </div>

              {(() => {
                const totalScored =
                  (summary.risk_breakdown["quantum_ready"] || 0) +
                  (summary.risk_breakdown["quantum_aware"] || 0) +
                  (summary.risk_breakdown["quantum_at_risk"] || 0) +
                  (summary.risk_breakdown["quantum_vulnerable"] || 0) +
                  (summary.risk_breakdown["quantum_critical"] || 0) +
                  (summary.risk_breakdown["unknown"] || 0);

                const finalUnknownCount = Math.max(0, summary.total_assets - totalScored) + (summary.risk_breakdown["unknown"] || 0);

                if (finalUnknownCount > 0) {
                  return (
                    <div>
                      <div className="flex justify-between text-sm mb-2">
                        <span style={{ color: "var(--text-secondary)" }}>Unscanned / Unknown</span>
                        <span style={{ color: "var(--text-muted)" }}>
                          {finalUnknownCount} / {summary.total_assets}
                        </span>
                      </div>
                      <ProgressBar
                        value={finalUnknownCount}
                        max={summary.total_assets}
                        color="var(--border-subtle)"
                      />
                    </div>
                  );
                }
                return null;
              })()}
            </div>
          </div>

          {/* Quick Stats */}
          <div className="glass-card-static p-6">
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
              Scan Summary
            </h3>
            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col">
                <span className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
                  {summary.shadow_assets}
                </span>
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>Shadow Assets</span>
              </div>
              <div className="flex flex-col">
                <span className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
                  {summary.third_party_assets}
                </span>
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>Third-Party</span>
              </div>
              <div className="flex flex-col">
                <span className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
                  {summary.total_cboms}
                </span>
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>CBOMs Generated</span>
              </div>
              <div className="flex flex-col">
                <span className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
                  {summary.compliance_summary.rbi_compliant}
                </span>
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>RBI Compliant</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
