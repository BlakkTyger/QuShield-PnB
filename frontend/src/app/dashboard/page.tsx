"use client";

import { useState, useEffect } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import { ShieldAlert, Clock, Target, TrendingUp } from "lucide-react";
import {
  useScans, useScanSummary, useEnterpriseRating,
  useRiskHeatmap, useRegulatoryDeadlines, useCBOMAlgorithms,
} from "@/lib/hooks";
import { useScanContext } from "@/lib/ScanContext";
import { ScoreGauge, MetricCard, RiskBadge, ProgressBar, EmptyState, Skeleton, ScanSelector } from "@/components/ui";
import { RISK_COLORS, RISK_LABELS } from "@/lib/types";

export default function DashboardPage() {
  const { activeScanId, setActiveScan } = useScanContext();
  const scanId = activeScanId;

  // Get latest completed scan
  const { data: scans, isLoading: scansLoading } = useScans();

  useEffect(() => {
    // Try context first
    if (activeScanId) return;
    // Otherwise use latest completed scan
    if (scans?.length) {
      const completed = scans.find((s) => s.status === "completed");
      if (completed) setActiveScan(completed.scan_id, completed.targets[0], completed.scan_type);
    }
  }, [scans, activeScanId, setActiveScan]);

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

  const algoData = algorithms?.algorithms
    ? algorithms.algorithms.map((algo: { name: string; count: number }) => ({
        name: (algo.name || "unknown").length > 20 ? (algo.name || "unknown").slice(0, 18) + "…" : (algo.name || "unknown"),
        value: algo.count,
      }))
    : [];

  const ALGO_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#22c55e", "#8b5cf6", "#ec4899", "#14b8a6"];

  const hndlCount = heatmap?.assets.filter((a) => a.hndl_exposed).length || 0;

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
        <div className="flex items-center gap-4">
          <ScanSelector />
          <div className="text-xs text-right" style={{ color: "var(--text-muted)" }}>
            Last scan: {summary.completed_at ? new Date(summary.completed_at).toLocaleString() : "—"}
          </div>
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
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 11 }} />
              <YAxis dataKey="name" type="category" tick={{ fill: "#9ca3af", fontSize: 11 }} width={130} />
              <Tooltip
                contentStyle={{
                  background: "#111118",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 8,
                  fontSize: 12,
                  color: "#f0f0f5",
                }}
              />
              <Bar dataKey="value" radius={[0, 6, 6, 0]}>
                {riskDistData.map((entry, i) => (
                  <Cell key={i} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Algorithm Exposure Donut */}
        <div className="glass-card-static p-6">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Algorithm Exposure
          </h3>
          {algoData.length > 0 ? (
            <ResponsiveContainer width="100%" height={260}>
              <PieChart>
                <Pie
                  data={algoData}
                  innerRadius={50}
                  outerRadius={85}
                  paddingAngle={2}
                  dataKey="value"
                >
                  {algoData.map((_, i) => (
                    <Cell key={i} fill={ALGO_COLORS[i % ALGO_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#111118",
                    border: "1px solid rgba(255,255,255,0.1)",
                    borderRadius: 8,
                    fontSize: 12,
                    color: "#f0f0f5",
                  }}
                />
                <Legend
                  formatter={(value) => <span style={{ color: "#9ca3af", fontSize: 10 }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
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
                  <span style={{ color: "var(--text-secondary)" }}>Vulnerable + Critical</span>
                  <span style={{ color: "var(--risk-critical)" }}>
                    {(summary.risk_breakdown["quantum_vulnerable"] || 0) +
                      (summary.risk_breakdown["quantum_critical"] || 0)} / {summary.total_assets}
                  </span>
                </div>
                <ProgressBar
                  value={
                    (summary.risk_breakdown["quantum_vulnerable"] || 0) +
                    (summary.risk_breakdown["quantum_critical"] || 0)
                  }
                  max={summary.total_assets}
                  color="var(--risk-critical)"
                />
              </div>
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
