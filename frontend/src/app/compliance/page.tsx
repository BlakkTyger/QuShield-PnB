"use client";

import { useState, useEffect } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import { CheckCircle, XCircle, Clock, AlertTriangle } from "lucide-react";
import {
  useScans, useFIPSMatrix, useRegulatoryDeadlines,
  useComplianceAgility, useComplianceRegulatory, useScanSummary,
} from "@/lib/hooks";
import { useScanContext } from "@/lib/ScanContext";
import { MetricCard, ProgressBar, EmptyState, Skeleton, ScanSelector } from "@/components/ui";

export default function CompliancePage() {
  const { activeScanId, setActiveScan } = useScanContext();
  const scanId = activeScanId;
  const [activeTab, setActiveTab] = useState<"fips" | "regulatory" | "agility">("fips");

  const { data: scans } = useScans();
  useEffect(() => {
    if (activeScanId) return;
    if (scans?.length) {
      const completed = scans.find((s) => s.status === "completed");
      if (completed) setActiveScan(completed.scan_id, completed.targets[0], completed.scan_type);
    }
  }, [scans, activeScanId, setActiveScan]);

  const { data: summary } = useScanSummary(scanId);
  const { data: fipsMatrix } = useFIPSMatrix(scanId);
  const { data: deadlines } = useRegulatoryDeadlines();
  const { data: agility } = useComplianceAgility(scanId);
  const { data: regulatory } = useComplianceRegulatory(scanId);

  if (!scanId) {
    return <EmptyState message="No scan data available. Run a Quick Scan first." />;
  }

  // Agility histogram data
  const agilityData = agility?.distribution
    ? Object.entries(agility.distribution).map(([range, count]) => ({
        name: range,
        value: count,
      }))
    : [];

  const tabs = [
    { key: "fips" as const, label: "FIPS Matrix" },
    { key: "regulatory" as const, label: "Regulatory" },
    { key: "agility" as const, label: "Crypto-Agility" },
  ];

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-black mb-1" style={{ color: "var(--text-primary)" }}>
            PQC Compliance
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Regulatory alignment and FIPS compliance tracking
          </p>
        </div>
        <ScanSelector />
      </div>

      {/* Headline Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <MetricCard
          title="Compliance Score"
          value={`${summary?.compliance_summary.avg_compliance_pct || 0}%`}
          subtitle="Average across assets"
          icon={<CheckCircle size={18} />}
          color={
            (summary?.compliance_summary.avg_compliance_pct || 0) < 50
              ? "var(--risk-critical)"
              : "var(--text-primary)"
          }
        />
        <MetricCard
          title="TLS 1.3 Enforced"
          value={summary?.compliance_summary.tls_13_enforced || 0}
          subtitle={`of ${summary?.total_assets || 0} assets`}
          icon={<CheckCircle size={18} />}
        />
        <MetricCard
          title="Crypto-Agility"
          value={`${summary?.compliance_summary.avg_agility_score || 0}/100`}
          subtitle="Average agility score"
          icon={<AlertTriangle size={18} />}
          color={(summary?.compliance_summary.avg_agility_score || 0) < 40 ? "var(--risk-vulnerable)" : undefined}
        />
        <MetricCard
          title="RBI Compliant"
          value={summary?.compliance_summary.rbi_compliant || 0}
          subtitle={`of ${summary?.total_assets || 0} assets`}
          icon={<CheckCircle size={18} />}
        />
      </div>

      {/* Regulatory Deadlines Strip */}
      <div className="glass-card-static p-5 mb-6">
        <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: "var(--text-muted)" }}>
          Regulatory Deadline Countdown
        </h3>
        <div className="flex gap-3 overflow-x-auto pb-2">
          {deadlines?.map((d) => (
            <div
              key={d.name}
              className="flex-shrink-0 p-4 rounded-lg min-w-[200px]"
              style={{
                background: "var(--bg-card)",
                border: `1px solid ${
                  d.urgency === "overdue"
                    ? "rgba(239,68,68,0.3)"
                    : d.urgency === "critical"
                    ? "rgba(249,115,22,0.3)"
                    : "var(--border-subtle)"
                }`,
              }}
            >
              <div className="flex items-center gap-2 mb-1">
                <span
                  className="w-2 h-2 rounded-full"
                  style={{
                    background:
                      d.urgency === "overdue" ? "var(--risk-critical)"
                        : d.urgency === "critical" ? "var(--risk-vulnerable)"
                        : d.urgency === "warning" ? "var(--risk-at-risk)"
                        : "var(--risk-aware)",
                  }}
                />
                <span className="text-xs font-semibold" style={{ color: "var(--text-primary)" }}>
                  {d.name}
                </span>
              </div>
              <div className="text-[10px] mb-2" style={{ color: "var(--text-muted)" }}>
                {d.jurisdiction} • {d.deadline}
              </div>
              <span
                className="text-lg font-black"
                style={{
                  color:
                    d.days_remaining < 0 ? "var(--risk-critical)"
                      : d.days_remaining < 90 ? "var(--risk-vulnerable)"
                      : "var(--text-primary)",
                }}
              >
                {d.days_remaining < 0
                  ? `${Math.abs(d.days_remaining)}d overdue`
                  : `${d.days_remaining} days`}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 p-1 rounded-lg inline-flex" style={{ background: "var(--bg-card)" }}>
        {tabs.map((tab) => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key)}
            className="px-5 py-2 rounded-md text-sm font-medium transition-all"
            style={{
              background: activeTab === tab.key ? "var(--accent-gold-dim)" : "transparent",
              color: activeTab === tab.key ? "var(--accent-gold)" : "var(--text-muted)",
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === "fips" && (
        <div className="glass-card-static p-6 animate-fade-in">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            FIPS Compliance Matrix
          </h3>
          {fipsMatrix ? (
            <div className="overflow-x-auto">
              {/* Derive columns from the matrix data */}
              {(() => {
                const fipsColumns = ["fips_203_ml_kem", "fips_204_ml_dsa", "fips_205_slh_dsa", "hybrid_mode", "tls_13", "forward_secrecy"];
                const fipsLabels: Record<string, string> = {
                  fips_203_ml_kem: "FIPS 203 (ML-KEM)",
                  fips_204_ml_dsa: "FIPS 204 (ML-DSA)",
                  fips_205_slh_dsa: "FIPS 205 (SLH-DSA)",
                  hybrid_mode: "Hybrid Mode",
                  tls_13: "TLS 1.3",
                  forward_secrecy: "Forward Secrecy",
                };
                const matrixData = fipsMatrix.matrix || [];
                const summaryData = fipsMatrix.summary || {};
                return (
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Asset</th>
                        {fipsColumns.map((col) => (
                          <th key={col} className="text-center">
                            <div>{fipsLabels[col] || col}</div>
                            {summaryData[col === "fips_203_ml_kem" ? "fips_203_deployed" : col === "fips_204_ml_dsa" ? "fips_204_deployed" : col === "fips_205_slh_dsa" ? "fips_205_deployed" : col === "hybrid_mode" ? "hybrid_active" : col === "tls_13" ? "tls_13_enforced" : col] != null && (
                              <div className="text-[9px] font-normal mt-0.5" style={{ color: "var(--text-muted)" }}>
                                {summaryData.total_assets ? Math.round(
                                  (summaryData[col === "fips_203_ml_kem" ? "fips_203_deployed" : col === "fips_204_ml_dsa" ? "fips_204_deployed" : col === "fips_205_slh_dsa" ? "fips_205_deployed" : col === "hybrid_mode" ? "hybrid_active" : col === "tls_13" ? "tls_13_enforced" : col] as any || 0)
                                  / summaryData.total_assets * 100
                                ) : 0}%
                              </div>
                            )}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {matrixData.slice(0, 30).map((asset, i) => (
                        <tr key={i}>
                          <td>
                            <span className="font-medium text-xs" style={{ color: "var(--text-primary)" }}>
                              {asset.hostname}
                            </span>
                          </td>
                          {fipsColumns.map((col) => (
                            <td key={col} className="text-center">
                              {asset[col] ? (
                                <CheckCircle size={14} style={{ color: "var(--risk-ready)", display: "inline" }} />
                              ) : (
                                <XCircle size={14} style={{ color: "var(--risk-critical)", display: "inline" }} />
                              )}
                            </td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                );
              })()}
            </div>
          ) : (
            <Skeleton height={300} />
          )}
        </div>
      )}

      {activeTab === "regulatory" && (
        <div className="glass-card-static p-6 animate-fade-in">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            India Regulatory Compliance
          </h3>
          {regulatory ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(regulatory.regulations).map(
                ([key, data]) => {
                  const total = data.compliant + data.non_compliant;
                  return (
                    <div key={key} className="p-4 rounded-lg" style={{ background: "var(--bg-card)" }}>
                      <div className="flex justify-between items-center mb-2">
                        <span className="text-xs font-bold uppercase tracking-tight" style={{ color: "var(--text-primary)" }}>
                          {key.replace(/_/g, " ")}
                        </span>
                        <span
                          className="text-sm font-black"
                          style={{
                            color: data.pct < 50 ? "var(--risk-critical)" : "var(--risk-ready)",
                          }}
                        >
                          {data.pct.toFixed(1)}%
                        </span>
                      </div>
                      <ProgressBar
                        value={data.compliant}
                        max={total || 1}
                        height={6}
                        color={data.pct < 50 ? "var(--risk-critical)" : "var(--risk-ready)"}
                      />
                      <div className="text-[9px] mt-1.5 opacity-60" style={{ color: "var(--text-muted)" }}>
                        {data.compliant} of {total} nodes fully compliant
                      </div>
                    </div>
                  );
                }
              )}
            </div>
          ) : (
            <Skeleton height={200} />
          )}
        </div>
      )}

      {activeTab === "agility" && (
        <div className="glass-card-static p-6 animate-fade-in">
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Crypto-Agility Score Distribution
          </h3>
          {agility ? (
            <div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                <MetricCard
                  title="Average Agility"
                  value={(agility as any).average_agility?.toFixed(1) || "—"}
                />
                <MetricCard
                  title="Migration-Blocked"
                  value={(agility as any).distribution?.["0-20"] || 0}
                  color="var(--risk-critical)"
                />
                <MetricCard
                  title="Low Agility"
                  value={(agility as any).distribution?.["21-40"] || 0}
                  color="var(--risk-vulnerable)"
                />
                <MetricCard
                  title="High Agility"
                  value={((agility as any).distribution?.["81-100"] || 0) + ((agility as any).distribution?.["61-80"] || 0)}
                  color="var(--risk-ready)"
                />
              </div>
              {agilityData.length > 0 && (
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={agilityData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                    <XAxis dataKey="name" tick={{ fill: "#9ca3af", fontSize: 11 }} />
                    <YAxis tick={{ fill: "#6b7280", fontSize: 11 }} />
                    <Tooltip
                      contentStyle={{
                        background: "#111118", border: "1px solid rgba(255,255,255,0.1)",
                        borderRadius: 8, fontSize: 12, color: "#f0f0f5",
                      }}
                    />
                    <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                      {agilityData.map((_, i) => (
                        <Cell
                          key={i}
                          fill={
                            i === 0 ? "#ef4444" : i === 1 ? "#f97316" : i === 2 ? "#eab308" : "#22c55e"
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </div>
          ) : (
            <Skeleton height={300} />
          )}
        </div>
      )}
    </div>
  );
}
