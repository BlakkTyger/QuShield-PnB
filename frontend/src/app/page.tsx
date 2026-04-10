"use client";

import { useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { Zap, CheckCircle, Loader2, ArrowRight, Shield, Lock, Key, Award } from "lucide-react";
import { useStartScan, useScanStatus, useScanSummary, useEnterpriseRating } from "@/lib/hooks";
import { ScoreGauge, MetricCard, RiskBadge } from "@/components/ui";
import { RISK_LABELS } from "@/lib/types";

const EXAMPLE_DOMAINS = ["pnb.bank.in", "hdfcbank.com", "onlinesbi.sbi.bank.in"];

const PHASES = [
  { id: 1, name: "Asset Discovery", desc: "DNS, subdomains, port scan" },
  { id: 2, name: "Crypto Inspection", desc: "TLS, ciphers, certificates" },
  { id: 3, name: "CBOM Generation", desc: "CycloneDX CBOM assembly" },
  { id: 4, name: "Risk Assessment", desc: "Mosca, HNDL, compliance" },
];

export default function QuickScanPage() {
  const [domain, setDomain] = useState("");
  const [scanId, setScanId] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const router = useRouter();

  const startScan = useStartScan();
  const { data: scanStatus } = useScanStatus(scanId, isScanning);
  const { data: summary } = useScanSummary(
    scanStatus?.status === "completed" ? scanId : null
  );
  const { data: rating } = useEnterpriseRating(
    scanStatus?.status === "completed" ? scanId : null
  );

  // Stop polling when done
  if (scanStatus?.status === "completed" && isScanning) {
    setIsScanning(false);
  }
  if (scanStatus?.status === "failed" && isScanning) {
    setIsScanning(false);
  }

  const handleScan = useCallback(async () => {
    if (!domain.trim()) return;
    setIsScanning(true);
    try {
      const res = await startScan.mutateAsync([domain.trim()]);
      setScanId(res.scan_id);
    } catch {
      setIsScanning(false);
    }
  }, [domain, startScan]);

  const currentPhase = scanStatus?.current_phase || 0;
  const showResults = scanStatus?.status === "completed" && summary;

  return (
    <div className="max-w-5xl mx-auto animate-fade-in">
      {/* Hero */}
      <div className="text-center mb-10 pt-8">
        <div
          className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-semibold mb-4"
          style={{
            background: "var(--accent-gold-dim)",
            color: "var(--accent-gold)",
            border: "1px solid rgba(251,188,9,0.2)",
          }}
        >
          <Shield size={12} /> Quantum-Safe Crypto Scanner
        </div>
        <h1
          className="text-4xl font-black mb-3"
          style={{ color: "var(--text-primary)" }}
        >
          Quick Scan
        </h1>
        <p className="text-base" style={{ color: "var(--text-secondary)" }}>
          Enter a domain to instantly assess its quantum cryptographic posture
        </p>
      </div>

      {/* Scan Input */}
      <div className="glass-card-static p-8 mb-8">
        <div className="flex gap-3">
          <input
            type="text"
            className="scan-input flex-1"
            placeholder="Enter a domain, URL, or IP address…"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleScan()}
            disabled={isScanning}
          />
          <button
            onClick={handleScan}
            disabled={isScanning || !domain.trim()}
            className="btn-primary whitespace-nowrap"
          >
            {isScanning ? (
              <Loader2 size={18} className="animate-spin" />
            ) : (
              <Zap size={18} />
            )}
            {isScanning ? "Scanning…" : "Scan Now"}
          </button>
        </div>

        {/* Example tags */}
        <div className="flex flex-wrap gap-2 mt-4">
          <span className="text-xs" style={{ color: "var(--text-muted)" }}>
            Try:
          </span>
          {EXAMPLE_DOMAINS.map((d) => (
            <button
              key={d}
              onClick={() => setDomain(d)}
              disabled={isScanning}
              className="px-3 py-1 rounded-full text-xs font-medium transition-all"
              style={{
                background: "var(--bg-card)",
                color: "var(--text-secondary)",
                border: "1px solid var(--border-subtle)",
                cursor: isScanning ? "not-allowed" : "pointer",
              }}
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {/* Progress Stepper */}
      {isScanning && scanId && (
        <div className="glass-card-static p-8 mb-8 animate-fade-in">
          <div className="flex items-center justify-between mb-6">
            <h3
              className="text-sm font-semibold uppercase tracking-wider"
              style={{ color: "var(--text-muted)" }}
            >
              Scan Progress
            </h3>
            <span className="text-xs" style={{ color: "var(--accent-gold)" }}>
              Phase {currentPhase} of 4
            </span>
          </div>
          <div className="flex items-center gap-2">
            {PHASES.map((phase, i) => {
              const status =
                currentPhase > phase.id
                  ? "completed"
                  : currentPhase === phase.id
                  ? "active"
                  : "pending";
              return (
                <div key={phase.id} className="flex items-center gap-2 flex-1">
                  <div className="flex flex-col items-center">
                    <div className={`stepper-dot ${status}`}>
                      {status === "completed" ? (
                        <CheckCircle size={14} />
                      ) : status === "active" ? (
                        <Loader2 size={14} className="animate-spin" />
                      ) : (
                        phase.id
                      )}
                    </div>
                    <span
                      className="text-[10px] mt-2 text-center font-medium"
                      style={{
                        color:
                          status === "completed"
                            ? "var(--risk-ready)"
                            : status === "active"
                            ? "var(--accent-gold)"
                            : "var(--text-muted)",
                      }}
                    >
                      {phase.name}
                    </span>
                  </div>
                  {i < PHASES.length - 1 && (
                    <div
                      className={`stepper-line ${
                        currentPhase > phase.id ? "completed" : ""
                      }`}
                      style={{ marginBottom: 24 }}
                    />
                  )}
                </div>
              );
            })}
          </div>

          {/* Live stats */}
          {scanStatus && (
            <div
              className="mt-6 pt-4 flex gap-6 text-xs"
              style={{
                borderTop: "1px solid var(--border-subtle)",
                color: "var(--text-muted)",
              }}
            >
              <span>
                Assets: <b style={{ color: "var(--text-primary)" }}>{scanStatus.total_assets}</b>
              </span>
              <span>
                Certs: <b style={{ color: "var(--text-primary)" }}>{scanStatus.total_certificates}</b>
              </span>
              <span>
                Vulnerable: <b style={{ color: "var(--risk-vulnerable)" }}>{scanStatus.total_vulnerable}</b>
              </span>
            </div>
          )}
        </div>
      )}

      {/* Error */}
      {scanStatus?.status === "failed" && (
        <div
          className="glass-card-static p-6 mb-8 animate-fade-in"
          style={{ borderColor: "var(--risk-critical)" }}
        >
          <p style={{ color: "var(--risk-critical)" }}>
            Scan failed: {scanStatus.error_message || "Unknown error"}
          </p>
        </div>
      )}

      {/* Results */}
      {showResults && (
        <div className="animate-fade-in">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Left: Scorecard */}
            <div className="glass-card-static p-8 flex flex-col items-center">
              <h3
                className="text-xs font-semibold uppercase tracking-wider mb-6"
                style={{ color: "var(--text-muted)" }}
              >
                Quantum Cyber Rating
              </h3>
              <ScoreGauge
                score={rating?.enterprise_rating || 0}
                size={200}
                label={rating?.label || ""}
              />

              <div className="grid grid-cols-2 gap-3 mt-8 w-full">
                <MetricCard
                  title="TLS Version"
                  value={`${summary.compliance_summary.tls_13_enforced} TLS 1.3`}
                  subtitle={`of ${summary.total_assets} assets`}
                  icon={<Lock size={16} />}
                />
                <MetricCard
                  title="Assets Scanned"
                  value={summary.total_assets}
                  subtitle={`${summary.total_certificates} certificates`}
                  icon={<Server size={16} />}
                />
                <MetricCard
                  title="Compliance"
                  value={`${summary.compliance_summary.avg_compliance_pct}%`}
                  subtitle="avg compliance"
                  icon={<CheckCircle size={16} />}
                />
                <MetricCard
                  title="NIST PQC"
                  value={`${
                    summary.risk_breakdown["quantum_ready"] || 0
                  } Ready`}
                  subtitle={`${summary.risk_breakdown["quantum_vulnerable"] || 0} vulnerable`}
                  icon={<Award size={16} />}
                  color="var(--risk-vulnerable)"
                />
              </div>
            </div>

            {/* Right: Key Findings */}
            <div className="glass-card-static p-8">
              <h3
                className="text-xs font-semibold uppercase tracking-wider mb-6"
                style={{ color: "var(--text-muted)" }}
              >
                Key Findings
              </h3>
              <div className="flex flex-col gap-3">
                {Object.entries(summary.risk_breakdown).map(
                  ([cls, count]) => (
                    <div
                      key={cls}
                      className="flex items-center justify-between p-3 rounded-lg"
                      style={{ background: "var(--bg-card)" }}
                    >
                      <div className="flex items-center gap-3">
                        <RiskBadge classification={cls} />
                        <span
                          className="text-sm"
                          style={{ color: "var(--text-secondary)" }}
                        >
                          {RISK_LABELS[cls] || cls}
                        </span>
                      </div>
                      <span
                        className="text-lg font-bold"
                        style={{ color: "var(--text-primary)" }}
                      >
                        {count as number}
                      </span>
                    </div>
                  )
                )}

                {summary.shadow_assets > 0 && (
                  <div
                    className="p-3 rounded-lg"
                    style={{
                      background: "var(--accent-magenta-dim)",
                      border: "1px solid rgba(162,14,55,0.3)",
                    }}
                  >
                    <span className="badge badge-critical">Shadow IT</span>
                    <span
                      className="ml-2 text-sm"
                      style={{ color: "var(--text-secondary)" }}
                    >
                      {summary.shadow_assets} unregistered asset(s) detected
                    </span>
                  </div>
                )}
              </div>

              <button
                className="btn-primary w-full mt-8"
                onClick={() => {
                  // Store scanId for other pages
                  if (typeof window !== "undefined") {
                    localStorage.setItem("qushield_scan_id", scanId!);
                  }
                  router.push("/dashboard");
                }}
              >
                View Full Dashboard <ArrowRight size={16} />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function Server({ size }: { size: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" x2="6.01" y1="6" y2="6"/><line x1="6" x2="6.01" y1="18" y2="18"/>
    </svg>
  );
}
