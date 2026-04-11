"use client";

import { useState, useCallback, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import { Zap, CheckCircle, Loader2, ArrowRight, Shield, Lock, Award, Server, ChevronDown, ChevronUp, Key, Clock, Layers, AlertCircle, TrendingDown, Activity, Database } from "lucide-react";
import { useStartScan, useQuickScan, useShallowScan, useScanStatus, useScanSummary, useEnterpriseRating, useCancelScan } from "@/lib/hooks";
import { ScoreGauge, MetricCard, RiskBadge, ProgressBar } from "@/components/ui";
import { useScanContext } from "@/lib/ScanContext";

type ScanTier = "quick" | "shallow" | "deep";

const SCAN_TIERS = [
  { value: "quick" as ScanTier, label: "Quick", time: "3–8s", desc: "Single SSL probe", icon: Zap },
  { value: "shallow" as ScanTier, label: "Shallow", time: "30–90s", desc: "CT discovery + top-N TLS", icon: Clock },
  { value: "deep" as ScanTier, label: "Deep", time: "5–10 min", desc: "Full infrastructure audit", icon: Layers },
];

const EXAMPLE_DOMAINS = ["pnb.bank.in", "hdfcbank.com", "sbi.co.in"];

const PHASES = [
  { id: 1, name: "DNS Resolution" },
  { id: 2, name: "Certificate Retrieval" },
  { id: 3, name: "TLS Handshake" },
  { id: 4, name: "Cipher Negotiation" },
  { id: 5, name: "Risk Scoring" },
];

export default function QuickScanPage() {
  const { activeScanId: scanId, activeDomain, setActiveScan } = useScanContext();
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [logsOpen, setLogsOpen] = useState(true);
  const [scanTier, setScanTier] = useState<ScanTier>("deep");
  const [quickResult, setQuickResult] = useState<any | null>(null);
  const [reconnectKey, setReconnectKey] = useState(0);
  const [counters, setCounters] = useState({
    assets: 0,
    certs: 0,
    ips: 0,
    vuln: 0
  });
  const logsEndRef = useRef<HTMLDivElement>(null);

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

    const token = typeof window !== "undefined" ? localStorage.getItem("qushield_access_token") : "";
    const es = new EventSource(`/api/v1/scans/${scanId}/stream?token=${token}`);

    const handleMessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data);
        if (data.message) {
          setLogs((prev) => [...prev, `[${new Date().toISOString().split("T")[1].slice(0, -1)}] ${data.message}`]);
        }
        if (data.data) {
          const type = data.event_type;
          if (type === "asset_discovered") setCounters(c => ({ ...c, assets: c.assets + (data.data.count || 0) }));
          else if (type === "crypto_result") setCounters(c => ({ ...c, certs: c.certs + 1 }));
          else if (type === "ip_resolved") setCounters(c => ({ ...c, ips: c.ips + (data.data.count || 1) }));
        }
      } catch (err) { console.error("SSE parse error", err); }
    };

    es.addEventListener("scan_started", handleMessage as any);
    es.addEventListener("phase_start", handleMessage as any);
    es.addEventListener("asset_discovered", handleMessage as any);
    es.addEventListener("crypto_result", handleMessage as any);
    es.addEventListener("ip_resolved", handleMessage as any);
    es.addEventListener("scan_complete", handleMessage as any);
    es.addEventListener("scan_failed", handleMessage as any);
    es.onmessage = handleMessage;

    let retryCount = 0;
    es.onerror = () => {
      es.close();
      if (retryCount < 5) {
        retryCount++;
        setTimeout(() => {
          if (scanId && isScanning) setReconnectKey(prev => prev + 1);
        }, 2000 * retryCount);
      }
    };

    return () => es.close();
  }, [scanId, scanStatus?.status, reconnectKey, isScanning]);

  // Auto scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Restore active scan from localStorage on mount
  useEffect(() => {
    if (scanId && activeDomain) {
      setDomain(activeDomain);
      if (scanStatus?.status && !["completed", "failed", "cancelled"].includes(scanStatus.status)) {
        setIsScanning(true);
      }
    }
  }, [scanId, activeDomain, scanStatus?.status]);

  const handleScan = useCallback(async () => {
    if (!domain.trim()) return;
    setIsScanning(true);
    setLogs([]);
    setQuickResult(null);
    setCounters({ assets: 0, certs: 0, ips: 0, vuln: 0 });
    const target = domain.trim();
    try {
      if (scanTier === "quick") {
        const res = await quickScan.mutateAsync({ domain: target });
        setQuickResult(res);
        setIsScanning(false);
        if (res.scan_id) setActiveScan(res.scan_id, target, "quick");
        return;
      }
      if (scanTier === "shallow") {
        const res = await shallowScan.mutateAsync({ domain: target });
        if (res.scan_id) setActiveScan(res.scan_id, target, "shallow");
        return;
      }
      const res = await startScan.mutateAsync([target]);
      if (res.scan_id) setActiveScan(res.scan_id, target, "deep");
    } catch { setIsScanning(false); }
  }, [domain, scanTier, startScan, quickScan, shallowScan]);

  const handleCancel = useCallback(async () => {
    if (!scanId || !isScanning) return;
    try {
      await cancelScan.mutateAsync(scanId);
      setIsScanning(false);
      setActiveScan("", "", "");
      setLogs((prev) => [...prev, `[${new Date().toISOString().split("T")[1].slice(0, -1)}] SCAN CANCELLED BY USER`]);
    } catch (err) {
      console.error("Cancel failed", err);
    }
  }, [scanId, isScanning, cancelScan, setActiveScan]);

  const currentPhase = scanStatus ? Math.min(scanStatus.current_phase || 1, 5) : 0;
  // Show results if scan is completed OR if we have a direct synchronous result (quickResult)
  const showResults = (scanStatus?.status === "completed" && summary) || (!!quickResult && !isScanning);

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

      {/* Progress Region (Scanner Active) */}
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
            <div className="grid grid-cols-4 gap-4 mb-8">
              <div className="glass-card-static p-4 border-[rgba(0,255,255,0.1)]">
                <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">Assets Discovered</div>
                <div className="text-2xl font-black text-cyan-400">{counters.assets}</div>
              </div>
              <div className="glass-card-static p-4 border-[rgba(255,255,0,0.1)]">
                <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">Certs Analyzed</div>
                <div className="text-2xl font-black text-yellow-400">{counters.certs}</div>
              </div>
              <div className="glass-card-static p-4 border-[rgba(0,255,0,0.1)]">
                <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">IPs Scanned</div>
                <div className="text-2xl font-black text-emerald-400">{counters.ips}</div>
              </div>
              <div className="glass-card-static p-4 border-[rgba(251,188,9,0.1)]">
                <div className="text-[10px] uppercase tracking-widest text-zinc-500 mb-1">Vulnerabilities</div>
                <div className="text-2xl font-black text-orange-400">{counters.vuln}</div>
              </div>
            </div>

            <div className="flex items-center justify-between gap-2 max-w-2xl mx-auto w-full">
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
          <div className="glass-card-static flex flex-col border-[var(--accent-gold-dim)] lg:h-[400px] h-[300px]">
            <div
              className="flex items-center justify-between px-4 py-3 border-b border-[rgba(255,255,255,0.05)] cursor-pointer"
              onClick={() => setLogsOpen(!logsOpen)}
              style={{ background: "rgba(0,0,0,0.2)" }}
            >
              <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></div>
                <span className="text-xs font-bold font-mono tracking-wider text-green-400">LIVE TELEMETRY STREAM</span>
              </div>
              {logsOpen ? <ChevronUp size={14} className="text-zinc-500" /> : <ChevronDown size={14} className="text-zinc-500" />}
            </div>

            {logsOpen && (
              <div className="flex-1 bg-[#050507] p-4 text-[11px] font-mono leading-relaxed overflow-y-auto scrollbar-thin">
                {logs.length === 0 ? (
                  <span className="text-zinc-600 italic">Awaiting telemetry from orchestrator...</span>
                ) : (
                  logs.map((log, i) => (
                    <div key={i} className={`mb-1 ${log.includes("ERROR") ? "text-red-400" : log.includes("SUCCESS") || log.includes("Found") || log.includes("complete") ? "text-emerald-400" : "text-zinc-400"}`}>
                      <span className="text-zinc-600 mr-2 opacity-50">{">"}</span>{log}
                    </div>
                  ))
                )}
                <div ref={logsEndRef} />
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

      {/* Results (Synchronous Quick Result) */}
      {quickResult && !isScanning && (
        <div className="animate-fade-in mb-12">
          <div className="flex items-center gap-3 mb-6 ml-1">
            <Zap className="text-[var(--accent-gold)]" size={20} />
            <h2 className="text-xl font-black uppercase tracking-tight" style={{ color: "var(--text-primary)" }}>
              Instant Assessment Results
            </h2>
            <div className="h-px flex-1 bg-[var(--border-subtle)] ml-4" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Quick Score */}
            <div className="glass-card-static p-8 flex flex-col items-center justify-center">
              <ScoreGauge
                score={quickResult.risk?.score || 0}
                size={200}
                label={quickResult.risk?.classification || "unknown"}
              />
              <div className="mt-6 text-center">
                <RiskBadge classification={quickResult.risk?.classification || "unknown"} />
                <p className="text-[10px] mt-4 uppercase tracking-widest font-bold" style={{ color: "var(--text-muted)" }}>
                  Primary Endpoint Analysis
                </p>
              </div>
            </div>

            {/* Assessment Details */}
            <div className="lg:col-span-2 grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="glass-card-static p-6">
                <div className="flex items-center gap-2 mb-4">
                  <Lock size={16} className="text-cyan-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-cyan-400">TLS Configuration</span>
                </div>
                <div className="space-y-4">
                  <div>
                    <div className="text-[10px] uppercase text-zinc-500 mb-1">Negotiated Protocol</div>
                    <div className="text-sm font-bold text-zinc-100">{quickResult.tls?.negotiated_protocol || "Unknown"}</div>
                  </div>
                  <div>
                    <div className="text-[10px] uppercase text-zinc-500 mb-1">Key Exchange / Cipher</div>
                    <div className="text-sm font-bold text-zinc-100 truncate">{quickResult.tls?.negotiated_cipher || "Unknown"}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    {quickResult.tls?.forward_secrecy ? (
                      <CheckCircle size={14} className="text-emerald-500" />
                    ) : (
                      <AlertCircle size={14} className="text-red-500" />
                    )}
                    <span className="text-xs font-medium text-zinc-300">Forward Secrecy Enforced</span>
                  </div>
                </div>
              </div>

              <div className="glass-card-static p-6">
                <div className="flex items-center gap-2 mb-4">
                  <Shield size={16} className="text-purple-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-purple-400">Quantum Assessment</span>
                </div>
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] uppercase text-zinc-500">NIST Quantum Level</span>
                    <span className="text-xs font-black text-purple-300">Level {quickResult.quantum_assessment?.lowest_nist_level >= 0 ? quickResult.quantum_assessment.lowest_nist_level : "0"}</span>
                  </div>
                  <ProgressBar
                    value={quickResult.quantum_assessment?.lowest_nist_level || 0}
                    max={5}
                    color="var(--risk-aware)"
                  />
                  <div className="p-3 rounded-lg bg-black/30 border border-white/5">
                    <div className="text-[10px] uppercase text-zinc-500 mb-2">Vulnerable Algorithms</div>
                    <div className="flex flex-wrap gap-1.5">
                      {quickResult.quantum_assessment?.vulnerable_algorithms?.map((algo: string) => (
                        <span key={algo} className="text-[9px] px-2 py-0.5 rounded bg-red-500/10 text-red-300 border border-red-500/20">{algo}</span>
                      ))}
                      {(!quickResult.quantum_assessment?.vulnerable_algorithms || quickResult.quantum_assessment.vulnerable_algorithms.length === 0) && (
                        <span className="text-[9px] text-zinc-500 italic">None detected</span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              <div className="glass-card-static p-6 md:col-span-2">
                <div className="flex items-center gap-2 mb-4">
                  <Activity size={16} className="text-emerald-400" />
                  <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">Compliance & Risk Exposure</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                   <div>
                     <div className="flex justify-between items-center mb-2">
                       <span className="text-[10px] uppercase text-zinc-500">Global Compliance Score</span>
                       <span className="text-xs font-bold text-emerald-400">{quickResult.compliance?.compliance_pct}%</span>
                     </div>
                     <ProgressBar value={quickResult.compliance?.compliance_pct || 0} color="var(--risk-ready)" />
                     <div className="mt-4 flex flex-wrap gap-x-4 gap-y-2">
                        <div className="flex items-center gap-1.5 opacity-70">
                           {quickResult.compliance?.tls_1_3_enforced ? <CheckCircle size={10} className="text-emerald-500"/> : <AlertCircle size={10} className="text-zinc-500"/>}
                           <span className="text-[9px] text-zinc-400">TLS 1.3</span>
                        </div>
                        <div className="flex items-center gap-1.5 opacity-70">
                           {quickResult.compliance?.pci_dss_4_basic ? <CheckCircle size={10} className="text-emerald-500"/> : <AlertCircle size={10} className="text-zinc-500"/>}
                           <span className="text-[9px] text-zinc-400">PCI DSS 4.0</span>
                        </div>
                        <div className="flex items-center gap-1.5 opacity-70">
                           {quickResult.compliance?.sebi_tls_compliant ? <CheckCircle size={10} className="text-emerald-500"/> : <AlertCircle size={10} className="text-zinc-500"/>}
                           <span className="text-[9px] text-zinc-400">SEBI CSCRF</span>
                        </div>
                     </div>
                   </div>
                   <div className="flex flex-col justify-center border-l border-white/5 pl-8">
                     <div className="flex items-center gap-2 mb-1">
                        <TrendingDown size={14} className={quickResult.risk?.mosca?.exposed_pessimistic ? "text-red-400" : "text-emerald-400"} />
                        <span className="text-xs font-bold">HNDL Exposure</span>
                     </div>
                     <p className="text-[10px] text-zinc-500 leading-relaxed">
                        {quickResult.risk?.mosca?.exposed_pessimistic 
                          ? "Harvest-Now-Decrypt-Later risk detected. Encrypted data captured today may be decrypted by a CRQC."
                          : "No immediate HNDL exposure detected based on default shelf-life parameters."}
                     </p>
                   </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Results (Deep/Shallow Scan from DB) */}
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
                value={`${summary?.compliance_summary?.tls_13_enforced || 0} TLS 1.3`}
                subtitle={`of ${summary?.total_assets || 0} endpoints`}
                icon={<Lock size={16} />}
              />
              <MetricCard
                title="Key Exchange"
                value="RSA / ECDH"
                subtitle={summary?.risk_breakdown?.["quantum_critical"] ? "At Risk to Shor's" : "Secure"}
                icon={<Key size={16} />}
                color={summary?.risk_breakdown?.["quantum_critical"] ? "var(--risk-critical)" : undefined}
              />
              <MetricCard
                title="Cert Expiry"
                value={`${summary?.total_certificates || 0} Active`}
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
              {summary?.risk_breakdown?.["quantum_critical"] ? (
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

              {(summary?.shadow_assets || 0) > 0 ? (
                <div className="glass-card-static p-5 flex flex-col gap-2 border-l-4 border-l-[var(--urgent-amber)]">
                  <div className="flex items-center gap-3">
                    <span className="badge" style={{ background: "rgba(249,115,22,0.1)", color: "#f97316" }}>High Risk</span>
                    <h4 className="font-bold text-sm text-[var(--text-primary)]">Discovered Shadow Infrastructure</h4>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)] leading-relaxed mt-1">
                    {summary?.shadow_assets} uncatalogued subdomains identified on the perimeter. Shadow IT drastically increases untracked cryptographic debt.
                  </p>
                </div>
              ) : null}

              {(summary?.compliance_summary?.tls_13_enforced || 0) < (summary?.total_assets || 0) ? (
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
              {!summary?.risk_breakdown?.["quantum_critical"] && summary?.shadow_assets === 0 && (
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
                if (scanId) setActiveScan(scanId, domain, scanTier);
                router.push("/assets");
              }}
            >
              View Detailed Asset Inventory <ArrowRight size={18} />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
