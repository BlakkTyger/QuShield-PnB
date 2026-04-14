"use client";

import { useState, useMemo, useEffect } from "react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, ReferenceLine, Cell,
} from "recharts";
import {
  useCRQCSimulation, useCertRace, usePortfolioMonteCarlo, useScans,
  type CRQCSimParams,
} from "@/lib/hooks";
import { ScanSelector, EmptyState, Skeleton } from "@/components/ui";
import { AlertTriangle, Clock, Activity, ChevronDown, ChevronUp, Info } from "lucide-react";

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState<T>(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

const RISK_LEVEL_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
  minimal: "#14b8a6",
};

const RACE_COLORS = {
  safe: "#22c55e",
  natural_rotation: "#f59e0b",
  at_risk: "#ef4444",
};

export default function MonteCarloPage() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [modeYear, setModeYear] = useState(2032);
  const [sigma, setSigma] = useState(3.5);
  const [atRiskFilter, setAtRiskFilter] = useState(false);
  const [showAllAssets, setShowAllAssets] = useState(false);

  const { data: scans } = useScans();

  const debouncedParams: CRQCSimParams = {
    mode_year: useDebounce(modeYear, 300),
    sigma: useDebounce(sigma, 300),
    n_simulations: 10000,
  };

  const { data: crqcData, isLoading: crqcLoading } = useCRQCSimulation(debouncedParams);
  const { data: certRace, isLoading: certLoading } = useCertRace(scanId);
  const { data: portfolio, isLoading: portLoading } = usePortfolioMonteCarlo(scanId, debouncedParams);

  // Build probability curve data for chart
  const curveData = useMemo(() => {
    if (!crqcData?.probability_by_year) return [];
    return Object.entries(crqcData.probability_by_year).map(([year, prob]) => ({
      year: parseInt(year),
      probability: Math.round(prob * 10000) / 100, // convert to %
      cumulative: Math.round((crqcData.cumulative_by_year[year] || 0) * 100),
    }));
  }, [crqcData]);

  // Cert race bar data
  const certRaceBarData = useMemo(() => {
    if (!certRace) return [];
    return [
      { name: "Safe (PQC)", value: certRace.safe, fill: RACE_COLORS.safe },
      { name: "Natural Rotation", value: certRace.natural_rotation, fill: RACE_COLORS.natural_rotation },
      { name: "At Risk", value: certRace.at_risk, fill: RACE_COLORS.at_risk },
    ];
  }, [certRace]);

  // Filtered cert list
  const filteredCerts = useMemo(() => {
    if (!certRace?.certificates) return [];
    if (atRiskFilter) return certRace.certificates.filter((c) => c.race_status === "at_risk");
    return certRace.certificates;
  }, [certRace, atRiskFilter]);

  const displayedAssets = showAllAssets
    ? portfolio?.per_asset || []
    : (portfolio?.per_asset || []).slice(0, 10);

  return (
    <div className="animate-fade-in space-y-8">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            Monte Carlo CRQC Simulation
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Probabilistic quantum risk assessment using log-normal CRQC arrival modeling
          </p>
        </div>
        <ScanSelector scans={scans} scanId={scanId} onChange={setScanId} />
      </div>

      {/* ─── Section 1: CRQC Arrival Probability Curve ─── */}
      <div className="glass-card-static p-6">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-sm font-bold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
            CRQC Arrival Probability Distribution
          </h2>
          <div className="flex items-center gap-2 text-xs" style={{ color: "var(--text-muted)" }}>
            <Activity size={12} className="text-orange-400" />
            {crqcData ? `${crqcData.n_simulations.toLocaleString()} simulations` : "Loading…"}
          </div>
        </div>
        <p className="text-xs mb-5" style={{ color: "var(--text-muted)" }}>
          Log-normal distribution modeling the probability a Cryptographically Relevant Quantum Computer (CRQC) arrives in a given year.
          Asymmetric shape reflects: breakthrough could be earlier than expected, but delays are more likely.
        </p>

        {/* Stats row */}
        {crqcData && (
          <div className="grid grid-cols-3 gap-4 mb-6">
            {[
              { label: "P5 — Aggressive", year: crqcData.percentiles.p5, color: "#ef4444", desc: "5% chance by" },
              { label: "P50 — Median", year: crqcData.percentiles.p50, color: "#f97316", desc: "50% chance by" },
              { label: "P95 — Conservative", year: crqcData.percentiles.p95, color: "#22c55e", desc: "95% chance by" },
            ].map(({ label, year, color, desc }) => (
              <div key={label} className="bg-white/5 border rounded-xl p-4" style={{ borderColor: "var(--border-subtle)" }}>
                <div className="text-[10px] uppercase tracking-widest mb-1" style={{ color: "var(--text-muted)" }}>{label}</div>
                <div className="text-3xl font-black mb-1" style={{ color }}>{year}</div>
                <div className="text-[11px]" style={{ color: "var(--text-muted)" }}>{desc} {year}</div>
              </div>
            ))}
          </div>
        )}

        {/* Chart */}
        {crqcLoading ? (
          <Skeleton height={300} />
        ) : (
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={curveData} margin={{ top: 10, right: 20, left: 0, bottom: 5 }}>
              <defs>
                <linearGradient id="crqcGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#f97316" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" />
              <XAxis
                dataKey="year"
                tick={{ fill: "var(--chart-tick)", fontSize: 11 }}
                label={{ value: "Year", position: "insideBottom", offset: -2, fill: "var(--chart-tick)", fontSize: 11 }}
              />
              <YAxis
                tick={{ fill: "var(--chart-tick)", fontSize: 11 }}
                tickFormatter={(v) => `${v}%`}
                label={{ value: "Probability %", angle: -90, position: "insideLeft", fill: "var(--chart-tick)", fontSize: 11 }}
              />
              <Tooltip
                contentStyle={{ background: "var(--tooltip-bg)", border: "1px solid var(--tooltip-border)", borderRadius: 8, fontSize: 12, color: "var(--tooltip-text)" }}
                formatter={((value: unknown, name: unknown) => [
                  name === "probability" ? `${Number(value).toFixed(2)}%` : `${Number(value)}%`,
                  name === "probability" ? "Arrival Probability" : "Cumulative",
                ]) as never}
                labelFormatter={(label) => `Year ${label}`}
              />
              {crqcData && (
                <>
                  <ReferenceLine x={crqcData.percentiles.p5} stroke="#ef4444" strokeDasharray="4 4" strokeWidth={1.5}
                    label={{ value: "P5", fill: "#ef4444", fontSize: 10, position: "top" }} />
                  <ReferenceLine x={crqcData.percentiles.p50} stroke="#f97316" strokeDasharray="4 4" strokeWidth={2}
                    label={{ value: "P50", fill: "#f97316", fontSize: 10, position: "top" }} />
                  <ReferenceLine x={crqcData.percentiles.p95} stroke="#22c55e" strokeDasharray="4 4" strokeWidth={1.5}
                    label={{ value: "P95", fill: "#22c55e", fontSize: 10, position: "top" }} />
                </>
              )}
              <Area
                type="monotone"
                dataKey="probability"
                stroke="#f97316"
                strokeWidth={2}
                fill="url(#crqcGrad)"
              />
            </AreaChart>
          </ResponsiveContainer>
        )}

        {/* Sliders */}
        <div className="mt-6 grid grid-cols-1 md:grid-cols-2 gap-6 border-t pt-5" style={{ borderColor: "var(--border-subtle)" }}>
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-bold" style={{ color: "var(--text-secondary)" }}>
                Mode Year (Most Likely CRQC Arrival)
              </label>
              <span className="text-sm font-black text-orange-400">{modeYear}</span>
            </div>
            <input
              type="range" min={2028} max={2040} step={1} value={modeYear}
              onChange={(e) => setModeYear(Number(e.target.value))}
              className="w-full accent-orange-400"
            />
            <div className="flex justify-between text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
              <span>2028 (Aggressive)</span><span>2040 (Conservative)</span>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-bold" style={{ color: "var(--text-secondary)" }}>
                Sigma σ (Distribution Spread, years)
              </label>
              <span className="text-sm font-black text-orange-400">{sigma.toFixed(1)}</span>
            </div>
            <input
              type="range" min={1} max={8} step={0.5} value={sigma}
              onChange={(e) => setSigma(Number(e.target.value))}
              className="w-full accent-orange-400"
            />
            <div className="flex justify-between text-[10px] mt-1" style={{ color: "var(--text-muted)" }}>
              <span>1.0 (Narrow/Certain)</span><span>8.0 (Wide/Uncertain)</span>
            </div>
          </div>
        </div>

        {crqcData && (
          <div className="mt-4 flex items-start gap-2 text-xs p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
            <Info size={12} className="text-blue-400 shrink-0 mt-0.5" />
            <span style={{ color: "var(--text-muted)" }}>
              Mean arrival: <strong className="text-blue-400">{crqcData.statistics.mean.toFixed(1)}</strong> ·
              Std dev: <strong className="text-blue-400">{crqcData.statistics.std_dev.toFixed(1)} yrs</strong> ·
              Adjust sliders above to model different analyst assumptions — all portfolio metrics update automatically.
            </span>
          </div>
        )}
      </div>

      {/* ─── Section 2: Cert Race + Portfolio Summary ─── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Cert Race Chart */}
        <div className="glass-card-static p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Certificate Expiry vs CRQC Race
            </h2>
            {atRiskFilter && (
              <button
                onClick={() => setAtRiskFilter(false)}
                className="text-xs text-red-400 border border-red-400/30 px-2 py-1 rounded-full hover:bg-red-400/10 transition"
              >
                Showing At-Risk only — clear
              </button>
            )}
          </div>

          {!scanId ? (
            <EmptyState message="Select a scan to view certificate race analysis." />
          ) : certLoading ? (
            <Skeleton height={220} />
          ) : certRace ? (
            <>
              {/* Summary badges */}
              <div className="grid grid-cols-3 gap-3 mb-5">
                {[
                  { label: "Safe (PQC)", count: certRace.safe, color: RACE_COLORS.safe, status: "safe" },
                  { label: "Natural Rotation", count: certRace.natural_rotation, color: RACE_COLORS.natural_rotation, status: "natural_rotation" },
                  { label: "At Risk", count: certRace.at_risk, color: RACE_COLORS.at_risk, status: "at_risk" },
                ].map(({ label, count, color, status }) => (
                  <button
                    key={status}
                    onClick={() => setAtRiskFilter(status === "at_risk" ? !atRiskFilter : false)}
                    className={`text-left p-3 rounded-xl border transition ${status === "at_risk" && atRiskFilter ? "border-red-400/60 bg-red-400/10" : "border-transparent bg-white/5 hover:bg-white/10"}`}
                    style={{ borderColor: status === "at_risk" && atRiskFilter ? undefined : "var(--border-subtle)" }}
                  >
                    <div className="text-2xl font-black mb-0.5" style={{ color }}>{count}</div>
                    <div className="text-[10px] uppercase tracking-wide" style={{ color: "var(--text-muted)" }}>{label}</div>
                  </button>
                ))}
              </div>

              <ResponsiveContainer width="100%" height={160}>
                <BarChart data={certRaceBarData} layout="vertical" margin={{ left: 0, right: 20 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--chart-grid)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "var(--chart-tick)", fontSize: 11 }} />
                  <YAxis type="category" dataKey="name" tick={{ fill: "var(--chart-tick)", fontSize: 11 }} width={120} />
                  <Tooltip
                    contentStyle={{ background: "var(--tooltip-bg)", border: "1px solid var(--tooltip-border)", borderRadius: 8, fontSize: 12, color: "var(--tooltip-text)" }}
                    formatter={((v: unknown) => [Number(v), "Certificates"]) as never}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {certRaceBarData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>

              {certRace.pct_at_risk > 0 && (
                <div className="mt-4 flex items-center gap-2 text-xs p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                  <AlertTriangle size={12} className="text-red-400 shrink-0" />
                  <span style={{ color: "var(--text-muted)" }}>
                    <strong className="text-red-400">{(certRace.pct_at_risk * 100).toFixed(1)}%</strong> of certificates will still be active when CRQC arrives (P50: {certRace.crqc_median_arrival}) — requires out-of-band proactive replacement.
                  </span>
                </div>
              )}
            </>
          ) : (
            <EmptyState message="No certificate data found for this scan." />
          )}
        </div>

        {/* Portfolio Summary */}
        <div className="glass-card-static p-6">
          <h2 className="text-sm font-bold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Portfolio Exposure Summary
          </h2>

          {!scanId ? (
            <EmptyState message="Select a scan to view portfolio simulation." />
          ) : portLoading ? (
            <Skeleton height={220} />
          ) : portfolio ? (
            <>
              <div className="grid grid-cols-2 gap-4 mb-6">
                {[
                  {
                    label: "Avg Assets Exposed",
                    value: `${portfolio.portfolio_summary.avg_assets_exposed.toFixed(1)}`,
                    sub: `of ${portfolio.n_assets} total`,
                    color: portfolio.portfolio_summary.pct_portfolio_exposed > 0.6 ? "#ef4444" : portfolio.portfolio_summary.pct_portfolio_exposed > 0.3 ? "#f97316" : "#22c55e",
                  },
                  {
                    label: "Portfolio Exposure",
                    value: `${(portfolio.portfolio_summary.pct_portfolio_exposed * 100).toFixed(1)}%`,
                    sub: "probability-weighted",
                    color: portfolio.portfolio_summary.pct_portfolio_exposed > 0.6 ? "#ef4444" : "#f97316",
                  },
                  {
                    label: "Worst-Case Exposed",
                    value: `${portfolio.portfolio_summary.max_assets_exposed}`,
                    sub: "assets (max sim)",
                    color: "#ef4444",
                  },
                  {
                    label: "CRQC Median Arrival",
                    value: `${portfolio.crqc_simulation.median_arrival.toFixed(0)}`,
                    sub: `P5:${portfolio.crqc_simulation.p5} — P95:${portfolio.crqc_simulation.p95}`,
                    color: "#f97316",
                  },
                ].map(({ label, value, sub, color }) => (
                  <div key={label} className="bg-white/5 border rounded-xl p-4" style={{ borderColor: "var(--border-subtle)" }}>
                    <div className="text-[10px] uppercase tracking-widest mb-1" style={{ color: "var(--text-muted)" }}>{label}</div>
                    <div className="text-2xl font-black" style={{ color }}>{value}</div>
                    <div className="text-[11px] mt-0.5" style={{ color: "var(--text-muted)" }}>{sub}</div>
                  </div>
                ))}
              </div>

              <div className="text-xs p-3 rounded-lg bg-orange-500/10 border border-orange-500/20 flex gap-2 items-start">
                <Clock size={12} className="text-orange-400 shrink-0 mt-0.5" />
                <span style={{ color: "var(--text-muted)" }}>
                  Based on {portfolio.n_simulations.toLocaleString()} simulations. Mosca's inequality (X+Y{">"}{" "}Z) checked per asset using current mode_year={debouncedParams.mode_year}, σ={debouncedParams.sigma}.
                </span>
              </div>
            </>
          ) : (
            <EmptyState message="No risk data found for this scan." />
          )}
        </div>
      </div>

      {/* ─── Section 3: Per-Asset Exposure Table ─── */}
      {scanId && (
        <div className="glass-card-static p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Per-Asset Quantum Exposure Probability
            </h2>
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>
              Sorted by exposure probability — highest risk first
            </span>
          </div>

          {portLoading ? (
            <Skeleton height={300} />
          ) : portfolio?.per_asset && portfolio.per_asset.length > 0 ? (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b" style={{ borderColor: "var(--border-subtle)" }}>
                      {["Hostname", "Exposure Probability", "Migration Time", "Data Shelf Life", "Risk Level"].map((h) => (
                        <th key={h} className="text-left text-[11px] font-semibold uppercase tracking-wider py-2 px-3" style={{ color: "var(--text-muted)" }}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {displayedAssets.map((asset, i) => {
                      const pct = Math.round(asset.exposure_probability * 100);
                      const color = RISK_LEVEL_COLORS[asset.risk_level] || "#888";
                      return (
                        <tr key={i} className="border-b hover:bg-white/5 transition" style={{ borderColor: "var(--border-subtle)" }}>
                          <td className="py-2.5 px-3 font-mono text-xs" style={{ color: "var(--text-primary)" }}>
                            {asset.hostname}
                          </td>
                          <td className="py-2.5 px-3">
                            <div className="flex items-center gap-2">
                              <div className="flex-1 bg-white/10 rounded-full h-1.5 max-w-[80px]">
                                <div className="h-1.5 rounded-full" style={{ width: `${pct}%`, background: color }} />
                              </div>
                              <span className="text-xs font-bold" style={{ color }}>{pct}%</span>
                            </div>
                          </td>
                          <td className="py-2.5 px-3 text-xs" style={{ color: "var(--text-secondary)" }}>
                            {asset.migration_time_years.toFixed(1)} yr
                          </td>
                          <td className="py-2.5 px-3 text-xs" style={{ color: "var(--text-secondary)" }}>
                            {asset.data_shelf_life_years.toFixed(1)} yr
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full"
                              style={{ background: `${color}22`, color, border: `1px solid ${color}44` }}
                            >
                              {asset.risk_level}
                            </span>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {portfolio.per_asset.length > 10 && (
                <button
                  onClick={() => setShowAllAssets(!showAllAssets)}
                  className="mt-4 flex items-center gap-1 text-xs text-orange-400 hover:text-orange-300 transition"
                >
                  {showAllAssets ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                  {showAllAssets ? "Show less" : `Show all ${portfolio.per_asset.length} assets`}
                </button>
              )}
            </>
          ) : (
            <EmptyState message="No per-asset simulation data available." />
          )}
        </div>
      )}

      {/* ─── Cert Race Detail Table ─── */}
      {scanId && certRace && filteredCerts.length > 0 && (
        <div className="glass-card-static p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold uppercase tracking-wider" style={{ color: "var(--text-muted)" }}>
              Certificate Race Detail {atRiskFilter && <span className="text-red-400 ml-1">— At Risk Only</span>}
            </h2>
            <span className="text-xs" style={{ color: "var(--text-muted)" }}>{filteredCerts.length} certificates</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b" style={{ borderColor: "var(--border-subtle)" }}>
                  {["Hostname", "Common Name", "Algorithm", "Expires", "Days Left", "Status"].map((h) => (
                    <th key={h} className="text-left text-[11px] font-semibold uppercase tracking-wider py-2 px-3" style={{ color: "var(--text-muted)" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredCerts.map((cert, i) => {
                  const statusColor = RACE_COLORS[cert.race_status] || "#888";
                  const statusLabel = cert.race_status === "natural_rotation" ? "Natural Rotation" : cert.race_status === "at_risk" ? "At Risk" : "Safe";
                  return (
                    <tr key={i} className="border-b hover:bg-white/5 transition" style={{ borderColor: "var(--border-subtle)" }}>
                      <td className="py-2.5 px-3 font-mono text-xs" style={{ color: "var(--text-primary)" }}>{cert.hostname || "—"}</td>
                      <td className="py-2.5 px-3 text-xs" style={{ color: "var(--text-secondary)" }}>{cert.common_name || "—"}</td>
                      <td className="py-2.5 px-3 font-mono text-xs text-yellow-400">{cert.algorithm || "—"}</td>
                      <td className="py-2.5 px-3 text-xs" style={{ color: "var(--text-secondary)" }}>
                        {cert.valid_to ? new Date(cert.valid_to).toLocaleDateString() : "—"}
                      </td>
                      <td className="py-2.5 px-3 text-xs" style={{ color: cert.days_until_expiry != null && cert.days_until_expiry < 90 ? "#ef4444" : "var(--text-secondary)" }}>
                        {cert.days_until_expiry != null ? `${cert.days_until_expiry}d` : "—"}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full"
                          style={{ background: `${statusColor}22`, color: statusColor, border: `1px solid ${statusColor}44` }}
                        >
                          {statusLabel}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
