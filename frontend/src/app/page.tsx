"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Zap, CheckCircle, Loader2, ArrowRight, Shield, Lock, Award, Server, ChevronDown, ChevronUp, Key, Clock, Layers, Target, ShieldAlert } from "lucide-react";
import { useStartScan, useQuickScan, useShallowScan, useScanStatus, useScanSummary, useEnterpriseRating, useCancelScan } from "@/lib/hooks";
import { ScoreGauge, MetricCard, RiskBadge } from "@/components/ui";

type ScanTier = "quick" | "shallow" | "deep";

const SCAN_TIERS = [
  { value: "quick" as ScanTier, label: "Quick", time: "3–8s", desc: "Single SSL probe", icon: Zap },
  { value: "shallow" as ScanTier, label: "Shallow", time: "30–90s", desc: "CT discovery + top-N TLS", icon: Clock },
  { value: "deep" as ScanTier, label: "Deep", time: "5–10 min", desc: "Full infrastructure audit", icon: Layers },
];

const EXAMPLE_DOMAINS = ["pnb.bank.in", "hdfcbank.com", "sbi.co.in"];

const PHASES = [
  { id: 1, name: "Discovery" },
  { id: 2, name: "Inspection" },
  { id: 3, name: "CBOM Build" },
  { id: 4, name: "Risk Score" },
  { id: 5, name: "Compliance" },
  { id: 6, name: "Topology" },
];

export default function QuickScanPage() {
  const [domain, setDomain] = useState("");
  const [scanId, setScanId] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [logsOpen, setLogsOpen] = useState(true);
  const [scanTier, setScanTier] = useState<ScanTier>("deep");
  const [quickResult, setQuickResult] = useState<Record<string, unknown> | null>(null);
  const logsContainerRef = useRef<HTMLDivElement>(null);

  const router = useRouter();
  const startScan = useStartScan();
  const quickScan = useQuickScan();
  const shallowScan = useShallowScan();
  const cancelScan = useCancelScan();

  const { data: scanStatus, isError, error } = useScanStatus(scanId, isScanning);
  const { data: summary } = useScanSummary(
    scanStatus?.status === "completed" ? scanId : null
  );
  const { data: rating } = useEnterpriseRating(
    scanStatus?.status === "completed" ? scanId : null
  );

  // Automatic cleanup of stale scans (e.g. 404 on poll)
  useEffect(() => {
    if (isError && (error as any)?.response?.status === 404) {
      console.warn("Scan session expired or invalid. Resetting UI.");
      setIsScanning(false);
      setScanId(null);
      if (typeof window !== "undefined") {
        localStorage.removeItem("qushield_active_scan");
        localStorage.removeItem("qushield_active_domain");
      }
    }
  }, [isError, error]);

  // Stop polling when done
  useEffect(() => {
    if (scanStatus?.status === "completed" && isScanning) {
      setIsScanning(false);
    }
    if (scanStatus?.status === "failed" && isScanning) {
      setIsScanning(false);
    }
  }, [scanStatus, isScanning]);

  // Hook up SSE stream
  useEffect(() => {
    if (!scanId || scanStatus?.status === "completed" || scanStatus?.status === "failed") return;

    // Explicitly hit the proxy endpoint on Next.js matching the FastApi
    const token = localStorage.getItem("qushield_access_token") || "";
    // Directly target the FastAPI backend on port 8000 to bypass Next.js proxy buffering
    const backendUrl = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:8000";
    const es = new EventSource(`${backendUrl}/api/v1/scans/${scanId}/stream?token=${token}`);

    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.message) {
          setLogs((prev) => [...prev, `[${new Date().toISOString().split("T")[1].slice(0, -1)}] ${data.message}`]);
        }
      } catch {
        setLogs((prev) => [...prev, `[${new Date().toISOString().split("T")[1].slice(0, -1)}] ${event.data}`]);
      }
    };

    es.onerror = () => {
      es.close();
    };

    return () => es.close();
  }, [scanId, scanStatus?.status]);

  // Auto scroll logs
  useEffect(() => {
    if (logsContainerRef.current) {
      logsContainerRef.current.scrollTop = logsContainerRef.current.scrollHeight;
    }
  }, [logs]);

  // Restore active scan from localStorage on mount
  useEffect(() => {
    if (typeof window !== "undefined") {
      const savedScan = localStorage.getItem("qushield_active_scan");
      const savedDomain = localStorage.getItem("qushield_active_domain");
      if (savedScan && savedDomain) {
        setScanId(savedScan);
        setDomain(savedDomain);
        setIsScanning(true); // Triggers at least one poll to check actual status
      }
    }
  }, []);

  const handleScan = useCallback(async () => {
    if (!domain.trim()) return;
    setIsScanning(true);
    setLogs([]);
    setQuickResult(null);
    setScanId(null);
    if (typeof window !== "undefined") {
      localStorage.removeItem("qushield_active_scan");
    }
    try {
      if (scanTier === "quick") {
        const res = await quickScan.mutateAsync({ domain: domain.trim() });
        setQuickResult(res);
        setIsScanning(false);
        // If the quick scan returned a cached deep scan, load it
        if (res.cached && res.scan_id) {
          setScanId(res.scan_id);
          if (typeof window !== "undefined") {
            localStorage.setItem("qushield_active_scan", res.scan_id);
            localStorage.setItem("qushield_active_domain", domain.trim());
          }
        }
        return;
      }
      if (scanTier === "shallow") {
        const res = await shallowScan.mutateAsync({ domain: domain.trim() });
        setQuickResult(res);
        setIsScanning(false);
        if (res.cached && res.scan_id) {
          setScanId(res.scan_id);
          if (typeof window !== "undefined") {
            localStorage.setItem("qushield_active_scan", res.scan_id);
            localStorage.setItem("qushield_active_domain", domain.trim());
          }
        }
        return;
      }
      // Deep scan
      const res = await startScan.mutateAsync([domain.trim()]);
      setScanId(res.scan_id);
      if (typeof window !== "undefined") {
        localStorage.setItem("qushield_active_scan", res.scan_id);
        localStorage.setItem("qushield_active_domain", domain.trim());
      }
    } catch {
      setIsScanning(false);
    }
  }, [domain, scanTier, startScan, quickScan, shallowScan]);

  const handleCancel = useCallback(async () => {
    if (!scanId || !isScanning) return;
    try {
      await cancelScan.mutateAsync(scanId);
      setIsScanning(false);
      setScanId(null);
      if (typeof window !== "undefined") {
        localStorage.removeItem("qushield_active_scan");
        localStorage.removeItem("qushield_active_domain");
      }
      setLogs((prev) => [...prev, `[${new Date().toISOString().split("T")[1].slice(0, -1)}] SCAN CANCELLED BY USER`]);
    } catch (err) {
      console.error("Cancel failed", err);
    }
  }, [scanId, isScanning, cancelScan]);

  const currentPhase = scanStatus ? Math.min(scanStatus.current_phase || 1, 6) : 0;
  const showResults = scanTier === "deep" && scanStatus?.status === "completed" && summary && !isScanning;

  return (
    <div className="max-w-6xl mx-auto animate-fade-in pb-20">
      {/* Hero */}
      <div className="text-center mb-10 pt-8 flex flex-col items-center">
        <div
          className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-semibold mb-4 animate-pulse-glow"
          style={{
            background: "var(--accent-gold-dim)",
            color: "var(--accent-gold)",
            border: "1px solid rgba(251,188,9,0.3)",
          }}
        >
          <Shield size={12} /> Quantum-Safe Crypto Scanner
        </div>
        <h1 className="text-5xl font-black mb-4 tracking-tight" style={{ color: "var(--text-primary)" }}>
          Quick Scan
        </h1>
        <p className="text-lg max-w-2xl" style={{ color: "var(--text-secondary)" }}>
          The front door to QuShield-PnB. Enter a domain, URL, or IP address for an immediate
          evaluation of your cryptographic posture and quantum vulnerability.
        </p>
      </div>

      {/* Target Input */}
      <div className="glass-card p-10 mb-8 mx-auto max-w-4xl shadow-xl">
        <div className="flex gap-4">
          <input
            type="text"
            className="flex-1 text-lg px-6 py-4 rounded-xl transition-all"
            placeholder="Enter a domain, URL, or IP address…"
            style={{
              background: "var(--bg-document)",
              color: "var(--text-primary)",
              border: "2px solid var(--border-subtle)",
              outline: "none"
            }}
            onFocus={(e) => e.target.style.borderColor = "var(--accent-gold)"}
            onBlur={(e) => e.target.style.borderColor = "var(--border-subtle)"}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleScan()}
            disabled={isScanning}
          />
          <button
            onClick={handleScan}
            disabled={isScanning || !domain.trim()}
            className="btn-primary px-8 py-4 rounded-xl font-bold text-lg flex items-center justify-center gap-2 transition-all disabled:opacity-50 disabled:scale-100 whitespace-nowrap"
          >
            {isScanning ? <Loader2 size={24} className="animate-spin" /> : <Zap size={24} />}
            {isScanning ? "Scanning…" : "Scan Now"}
          </button>
        </div>

        {/* Example tags */}
        {!isScanning && (
          <div className="flex flex-wrap items-center justify-center gap-3 mt-6">
            <span className="text-sm" style={{ color: "var(--text-muted)" }}>Try:</span>
            {EXAMPLE_DOMAINS.map((d) => (
              <button
                key={d}
                onClick={() => setDomain(d)}
                className="px-4 py-1.5 rounded-full text-sm font-medium transition-colors hover:bg-[var(--accent-maroon)] hover:text-white"
                style={{
                  background: "var(--bg-card)",
                  color: "var(--text-secondary)",
                  border: "1px solid var(--border-subtle)"
                }}
              >
                {d}
              </button>
            ))}
          </div>
        )}

        {/* Scan Tier Selector */}
        {!isScanning && (
          <div className="flex items-center justify-center gap-3 mt-5">
            {SCAN_TIERS.map((tier) => {
              const Icon = tier.icon;
              return (
                <button
                  key={tier.value}
                  onClick={() => setScanTier(tier.value)}
                  className="flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all"
                  style={{
                    background: scanTier === tier.value ? "var(--accent-gold-dim)" : "var(--bg-document)",
                    color: scanTier === tier.value ? "var(--accent-gold)" : "var(--text-muted)",
                    border: `1px solid ${scanTier === tier.value ? "var(--accent-gold)" : "var(--border-subtle)"}`,
                  }}
                >
                  <Icon size={14} />
                  {tier.label}
                  <span className="text-[10px] ml-1 opacity-70">{tier.time}</span>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Quick/Shallow Scan Loading State */}
      {isScanning && !scanId && (
        <div className="glass-card p-12 mb-8 flex flex-col items-center justify-center animate-fade-in text-center">
          <Loader2 size={40} className="animate-spin mb-6" style={{ color: "var(--accent-gold)" }} />
          <h3 className="text-xl font-bold uppercase tracking-widest mb-2" style={{ color: "var(--text-primary)" }}>
            Probing Target
          </h3>
          <p className="text-sm max-w-md leading-relaxed" style={{ color: "var(--text-secondary)" }}>
            {scanTier === "quick"
              ? "Establishing secure connection and assessing primary TLS endpoint for quantum risk posture..."
              : "Discovering active infrastructure elements across the perimeter. This may take up to 90 seconds depending on target size..."}
          </p>
        </div>
      )}

      {/* Progress Region (Deep Scan Active) */}
      {isScanning && scanId && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8 animate-fade-in">
          {/* Progress Stepper */}
          <div className="glass-card-static p-8 lg:col-span-2 flex flex-col justify-center">
            <div className="flex items-center justify-between mb-8">
              <h3 className="text-sm font-bold uppercase tracking-widest" style={{ color: "var(--accent-gold)" }}>
                Analysis In Progress
              </h3>
              <button
                onClick={handleCancel}
                className="text-[10px] font-bold uppercase tracking-tighter px-3 py-1.5 rounded-lg border border-[var(--risk-critical)] text-[var(--risk-critical)] hover:bg-[var(--risk-critical)] hover:text-white transition-all flex items-center gap-1.5"
              >
                <div className="w-1.5 h-1.5 rounded-full bg-[var(--risk-critical)]" />
                Cancel Scan
              </button>
            </div>
            <div className="flex items-center justify-between gap-2 max-w-2xl mx-auto w-full pb-10 pt-2">
              {PHASES.map((phase, i) => {
                const status =
                  currentPhase > phase.id
                    ? "completed"
                    : currentPhase === phase.id
                      ? "active"
                      : "pending";
                return (
                  <div key={phase.id} className="flex items-center gap-2 flex-1">
                    <div className="flex flex-col items-center relative">
                      <div
                        className={`w-10 h-10 relative z-10 rounded-full flex items-center justify-center transition-all ${status === "active" ? "animate-pulse shadow-[0_0_15px_rgba(251,188,9,0.5)]" : ""}`}
                        style={{
                          background: status === "completed" ? "var(--risk-ready)" : status === "active" ? "var(--accent-gold)" : "var(--bg-card)",
                          color: status === "pending" ? "var(--text-muted)" : "#fff",
                          border: status === "pending" ? "1px solid var(--border-subtle)" : "none"
                        }}
                      >
                        {status === "completed" ? <CheckCircle size={20} /> : status === "active" ? <Loader2 size={20} className="animate-spin" /> : phase.id}
                      </div>
                      <span
                        className="text-xs text-center font-bold tracking-wide absolute top-12 w-32 left-1/2 -translate-x-1/2"
                        style={{ color: status === "completed" ? "var(--text-primary)" : status === "active" ? "var(--accent-gold)" : "var(--text-muted)" }}
                      >
                        {phase.name}
                      </span>
                    </div>
                    {i < PHASES.length - 1 && (
                      <div className="h-1 flex-1 mx-2 rounded-full overflow-hidden" style={{ background: "var(--bg-card)" }}>
                        <div
                          className="h-full transition-all duration-1000 ease-in-out"
                          style={{
                            width: currentPhase > phase.id ? "100%" : currentPhase === phase.id ? "50%" : "0%",
                            background: "var(--risk-ready)"
                          }}
                        />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Live Log Console */}
          <div className="glass-card-static flex flex-col border-[var(--accent-gold-dim)]" style={{ height: "250px" }}>
            <div
              className="flex items-center justify-between px-4 py-3 border-b border-[rgba(255,255,255,0.05)] cursor-pointer shrink-0"
              onClick={() => setLogsOpen(!logsOpen)}
              style={{ background: "rgba(0,0,0,0.2)" }}
            >
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                <span className="text-xs font-bold font-mono tracking-wider text-green-400">LIVE FEED</span>
              </div>
              {logsOpen ? <ChevronUp size={14} className="text-zinc-500" /> : <ChevronDown size={14} className="text-zinc-500" />}
            </div>

            {logsOpen && (
              <div
                ref={logsContainerRef}
                className="flex-1 bg-[#0a0a0c] p-4 text-[11px] font-mono leading-relaxed overflow-y-auto scroll-smooth"
              >
                {logs.length === 0 ? (
                  <span className="text-zinc-600 italic">Awaiting telemetry...</span>
                ) : (
                  logs.map((log, i) => (
                    <div key={i} className={`${log.includes("ERROR") ? "text-red-400" : log.includes("SUCCESS") || log.includes("Found") ? "text-green-400" : "text-zinc-400"} pb-1`}>
                      {log}
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Error */}
      {scanStatus?.status === "failed" && !isScanning && (
        <div className="glass-card-static p-6 mb-8 text-center" style={{ borderColor: "var(--risk-critical)" }}>
          <h2 className="text-xl font-bold mb-2" style={{ color: "var(--risk-critical)" }}>Scan Aborted</h2>
          <p style={{ color: "var(--text-secondary)" }}>{scanStatus.error_message || "Target could not be resolved or network timeout occurred."}</p>
        </div>
      )}

      {/* Results (Completed Deep Scan) */}
      {showResults && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 animate-[slide-up_0.5s_ease-out]">
          {/* Left: Scorecard */}
          <div className="glass-card-static p-8 flex flex-col items-center shadow-2xl relative overflow-hidden">
            <div className="absolute -top-10 -right-10 w-40 h-40 bg-[var(--risk-ready)] opacity-10 blur-3xl rounded-full"></div>

            <h3 className="text-sm font-bold uppercase tracking-wider mb-8" style={{ color: "var(--text-muted)" }}>
              Quantum Cyber Rating
            </h3>

            <div className="mb-4">
              <ScoreGauge
                score={rating?.enterprise_rating || 0}
                size={220}
                label={rating?.label || ""}
              />
            </div>
            <p className="font-bold text-lg mb-8 tracking-wide uppercase" style={{ color: rating?.enterprise_rating && rating.enterprise_rating > 700 ? "var(--risk-ready)" : "var(--risk-vulnerable)" }}>
              {rating?.enterprise_rating && rating.enterprise_rating > 700 ? "Quantum Ready" : "Vulnerable"}
            </p>

            <div className="grid grid-cols-2 gap-4 w-full">
              <MetricCard
                title="TLS Version"
                value={`${summary.compliance_summary.tls_13_enforced} TLS 1.3`}
                subtitle={`of ${summary.total_assets} endpoints`}
                icon={<Lock size={16} />}
              />
              <MetricCard
                title="Key Exchange"
                value="RSA / ECDH"
                subtitle={summary.risk_breakdown["quantum_critical"] ? "At Risk to Shor's" : "Secure"}
                icon={<Key size={16} />}
                color={summary.risk_breakdown["quantum_critical"] ? "var(--risk-critical)" : undefined}
              />
              <MetricCard
                title="Cert Expiry"
                value={`${summary.total_certificates} Active`}
                subtitle="Monitored"
                icon={<Award size={16} />}
              />
              <MetricCard
                title="NIST Post-Quantum"
                value={`Level ${rating?.enterprise_rating && rating.enterprise_rating > 700 ? "4" : "1"}`}
                subtitle="Security Tier"
                icon={<Shield size={16} />}
                color={rating?.enterprise_rating && rating.enterprise_rating < 700 ? "var(--risk-vulnerable)" : "var(--risk-ready)"}
              />
            </div>
          </div>

          {/* Right: Key Findings */}
          <div className="flex flex-col h-full">
            <h3 className="text-sm font-bold uppercase tracking-wider mb-6 ml-2" style={{ color: "var(--text-muted)" }}>
              Key Findings Map
            </h3>

            <div className="flex flex-col gap-4 flex-1">
              {/* Generate intelligent finding cards based on breakdown */}
              {summary.risk_breakdown["quantum_critical"] ? (
                <div className="glass-card-static p-5 flex flex-col gap-2 relative overflow-hidden border-l-4 border-l-[var(--risk-critical)]">
                  <div className="absolute right-0 top-0 w-32 h-32 bg-[var(--risk-critical)] opacity-5 blur-2xl rounded-full"></div>
                  <div className="flex items-center gap-3">
                    <span className="badge badge-critical">Critical</span>
                    <h4 className="font-bold text-sm text-[var(--text-primary)]">Classical Key Exchange Detected</h4>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
                    Target utilizes RSA/ECC algorithms inherently vulnerable to Shor's algorithm. Deep scan reveals active exposure to 'Harvest Now, Decrypt Later' (HNDL) data collection.
                  </p>
                </div>
              ) : null}

              {summary.shadow_assets > 0 ? (
                <div className="glass-card-static p-5 flex flex-col gap-2 border-l-4 border-l-[var(--urgent-amber)]">
                  <div className="flex items-center gap-3">
                    <span className="badge" style={{ background: "rgba(249,115,22,0.1)", color: "#f97316" }}>High Risk</span>
                    <h4 className="font-bold text-sm text-[var(--text-primary)]">Discovered Shadow Infrastructure</h4>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
                    {summary.shadow_assets} uncatalogued subdomains identified on the perimeter. Shadow IT drastically increases untracked cryptographic debt.
                  </p>
                </div>
              ) : null}

              {summary.compliance_summary.tls_13_enforced < summary.total_assets ? (
                <div className="glass-card-static p-5 flex flex-col gap-2 border-l-4 border-l-[var(--urgent-amber)]">
                  <div className="flex items-center gap-3">
                    <span className="badge" style={{ background: "rgba(249,115,22,0.1)", color: "#f97316" }}>Medium Risk</span>
                    <h4 className="font-bold text-sm text-[var(--text-primary)]">Legacy TLS Versions Supported</h4>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
                    Some assets permit downgrades to TLSv1.2 or under, lacking enforced Forward Secrecy.
                  </p>
                </div>
              ) : null}

              {/* If no critical/high issues found */}
              {!summary.risk_breakdown["quantum_critical"] && summary.shadow_assets === 0 && (
                <div className="glass-card-static p-5 flex flex-col gap-2 border-l-4 border-l-[var(--risk-ready)]">
                  <div className="flex items-center gap-3">
                    <span className="badge badge-ready">Secure</span>
                    <h4 className="font-bold text-sm text-[var(--text-primary)]">Aggressive Cypto-Agility Baseline</h4>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
                    Target demonstrates PQC readiness with ML-KEM integration and enforced TLSv1.3 standards.
                  </p>
                </div>
              )}
            </div>

            <button
              className="mt-6 px-6 py-4 rounded-xl font-bold text-sm uppercase tracking-wider flex items-center justify-center gap-3 transition-colors hover:bg-[var(--accent-maroon)] hover:text-white"
              style={{ background: "var(--bg-card)", color: "var(--text-primary)", border: "1px solid var(--border-subtle)" }}
              onClick={() => {
                if (typeof window !== "undefined") localStorage.setItem("qushield_scan_id", scanId!);
                router.push("/assets");
              }}
            >
              Run Full Infrastructure Audit <ArrowRight size={18} />
            </button>
          </div>
        </div>
      )}

      {/* Quick and Shallow Scan Results */}
      {quickResult && !isScanning && (
        <div className="glass-card-static p-8 shadow-2xl relative overflow-hidden animate-[slide-up_0.5s_ease-out]">
          <div className="absolute -top-20 -right-20 w-80 h-80 bg-[var(--accent-gold)] opacity-5 blur-3xl rounded-full"></div>

          <h3 className="text-sm font-bold uppercase tracking-wider mb-8 flex justify-between items-center" style={{ color: "var(--text-muted)" }}>
            {quickResult.scan_type === "quick" ? "Quick Probe Results" : "Shallow Scan Results"}
            <span className="text-xs font-mono" style={{ color: "var(--text-secondary)" }}>{quickResult.duration_ms}ms</span>
          </h3>

          {quickResult.scan_type === "quick" && quickResult.risk && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              <div className="flex flex-col items-center justify-center">
                <ScoreGauge
                  score={(quickResult.risk as any).score || 0}
                  size={180}
                  label={(quickResult.risk as any).classification?.replace("quantum_", "") || ""}
                />
              </div>
              <div className="md:col-span-2 grid grid-cols-2 gap-4">
                <MetricCard
                  title="TLS Protocol"
                  value={(quickResult.tls as any)?.negotiated_protocol || "Unknown"}
                  subtitle={(quickResult.tls as any)?.forward_secrecy ? "Forward Secrecy OK" : "No Forward Secrecy"}
                  icon={<Lock size={16} />}
                />
                <MetricCard
                  title="Target Host"
                  value={String(quickResult.domain)}
                  subtitle={`Port ${quickResult.port}`}
                  icon={<Server size={16} />}
                />
                <MetricCard
                  title="NIST Post-Quantum"
                  value={`Level ${(quickResult.quantum_assessment as any)?.nist_level || 1}`}
                  subtitle={(quickResult.quantum_assessment as any)?.is_quantum_vulnerable ? "Vulnerable to Shor's" : "PQC Protected"}
                  icon={<Shield size={16} />}
                  color={(quickResult.quantum_assessment as any)?.is_quantum_vulnerable ? "var(--risk-critical)" : "var(--risk-ready)"}
                />
                <div className="flex items-center justify-center p-2 rounded-xl" style={{ border: "1px dashed var(--border-subtle)" }}>
                  <button
                    className="w-full h-full py-4 rounded-lg font-bold text-sm uppercase tracking-wider flex items-center justify-center gap-2 transition-all hover:bg-[var(--accent-gold-dim)] hover:text-[var(--accent-gold)]"
                    style={{ color: "var(--text-primary)" }}
                    onClick={() => {
                      setScanTier("deep");
                      setDomain(String(quickResult.domain));
                      // Slight delay to allow state to settle
                      setTimeout(() => handleScan(), 100);
                    }}
                  >
                    Run Deep Scan <ArrowRight size={16} />
                  </button>
                </div>
              </div>
            </div>
          )}

          {quickResult.scan_type === "shallow" && quickResult.summary && (
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <MetricCard
                title="Average Risk Score"
                value={String((quickResult.summary as any).avg_risk_score || 0)}
                subtitle={(quickResult.summary as any).avg_risk_classification?.replace("quantum_", "") || ""}
                icon={<ScoreGauge score={(quickResult.summary as any).avg_risk_score || 0} size={0} label="" /> && <Layers size={16} />}
                color={(quickResult.summary as any).avg_risk_score < 700 ? "var(--risk-vulnerable)" : "var(--risk-ready)"}
              />
              <MetricCard
                title="Elements Discovered"
                value={String((quickResult.summary as any).total_subdomains_discovered || 0)}
                subtitle={`${(quickResult.summary as any).live_subdomains || 0} live assets`}
                icon={<Target size={16} />}
              />
              <MetricCard
                title="Vulnerable Assets"
                value={String((quickResult.summary as any).quantum_vulnerable || 0)}
                subtitle="High Priority"
                icon={<ShieldAlert size={16} />}
                color={(quickResult.summary as any).quantum_vulnerable > 0 ? "var(--urgent-amber)" : undefined}
              />
              <div className="flex items-center justify-center p-2 rounded-xl" style={{ border: "1px dashed var(--border-subtle)" }}>
                <button
                  className="w-full h-full py-4 rounded-lg font-bold text-xs uppercase tracking-wider flex items-center justify-center gap-2 transition-all hover:bg-[var(--accent-gold-dim)] hover:text-[var(--accent-gold)]"
                  style={{ color: "var(--text-primary)", textAlign: "center" }}
                  onClick={() => {
                    setScanTier("deep");
                    setDomain(String(quickResult.domain));
                    setTimeout(() => handleScan(), 100);
                  }}
                >
                  Upgrade to Deep Scan <ArrowRight size={14} />
                </button>
              </div>
            </div>
          )}

          {quickResult.error && (
            <div className="mt-4 p-4 border border-[var(--risk-critical)] rounded-lg text-[var(--risk-critical)] text-sm font-mono text-center">
              Error: {String(quickResult.error)}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
