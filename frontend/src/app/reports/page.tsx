"use client";

import { useState, useEffect } from "react";
import { useScans, useGenerateReport } from "@/lib/hooks";
import { EmptyState, Skeleton } from "@/components/ui";
import { FileText, Download, Loader2, CheckCircle, AlertTriangle } from "lucide-react";

interface GeneratedReport {
  scanId: string;
  domain: string;
  generatedAt: string;
}

export default function ReportsPage() {
  const { data: scans, isLoading: scansLoading } = useScans();
  const generateReport = useGenerateReport();
  const [selectedScanId, setSelectedScanId] = useState("");
  const [reportType, setReportType] = useState("executive");
  const [format] = useState("pdf");
  const [generating, setGenerating] = useState(false);
  const [generatedReports, setGeneratedReports] = useState<GeneratedReport[]>([]);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  // Load generated reports from localStorage
  useEffect(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("qushield_reports");
      if (saved) {
        try { setGeneratedReports(JSON.parse(saved)); } catch { /* noop */ }
      }
    }
  }, []);

  const completedScans = (scans || []).filter((s) => s.status === "completed");

  const handleGenerate = async () => {
    if (!selectedScanId) return;
    setGenerating(true);
    setSuccessMsg(null);
    setErrorMsg(null);
    try {
      const blob = await generateReport.mutateAsync(selectedScanId);
      // Download the blob as PDF
      const url = URL.createObjectURL(new Blob([blob], { type: "application/pdf" }));
      const a = document.createElement("a");
      a.href = url;
      a.download = `qushield_${reportType}_${selectedScanId.slice(0, 8)}.pdf`;
      a.click();
      URL.revokeObjectURL(url);

      const scan = completedScans.find((s) => s.scan_id === selectedScanId);
      const newReport: GeneratedReport = {
        scanId: selectedScanId,
        domain: scan?.targets.join(", ") || selectedScanId.slice(0, 8),
        generatedAt: new Date().toISOString(),
      };
      const updated = [newReport, ...generatedReports].slice(0, 20);
      setGeneratedReports(updated);
      localStorage.setItem("qushield_reports", JSON.stringify(updated));
      setSuccessMsg("Report generated and downloaded successfully!");
    } catch (err) {
      setErrorMsg("Failed to generate report. Please try again.");
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div className="animate-fade-in">
      <div className="mb-6">
        <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
          Reports & Export
        </h1>
        <p className="text-sm" style={{ color: "var(--text-muted)" }}>
          Generate executive summaries, compliance reports, and CBOM audit packages
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Report Builder */}
        <div className="lg:col-span-2 glass-card-static p-6">
          <h3 className="text-xs font-bold uppercase tracking-wider mb-6" style={{ color: "var(--accent-gold)" }}>
            Report Builder
          </h3>

          {/* Step 1: Report Type */}
          <div className="mb-6">
            <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: "var(--text-muted)" }}>
              Step 1 — Report Type
            </label>
            <div className="space-y-2">
              {[
                { value: "executive", label: "Quantum Risk Executive Summary", desc: "AI-generated narrative with key metrics" },
                { value: "cbom_audit", label: "CBOM Audit Package", desc: "CycloneDX 1.6 compliant output" },
                { value: "rbi_submission", label: "RBI Crypto Governance", desc: "Formatted for RBI regulatory submission" },
                { value: "migration_progress", label: "PQC Migration Progress", desc: "Current migration status report" },
                { value: "full_scan", label: "Full Infrastructure Scan", desc: "Complete scan data and findings" },
              ].map((opt) => (
                <label
                  key={opt.value}
                  className="flex items-start gap-3 p-3 rounded-lg cursor-pointer transition-all"
                  style={{
                    background: reportType === opt.value ? "var(--accent-gold-dim)" : "var(--bg-card)",
                    border: `1px solid ${reportType === opt.value ? "var(--accent-gold)" : "var(--border-subtle)"}`,
                  }}
                >
                  <input
                    type="radio"
                    name="reportType"
                    value={opt.value}
                    checked={reportType === opt.value}
                    onChange={(e) => setReportType(e.target.value)}
                    className="mt-1"
                  />
                  <div>
                    <span className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>{opt.label}</span>
                    <p className="text-xs mt-0.5" style={{ color: "var(--text-muted)" }}>{opt.desc}</p>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {/* Step 2: Scan Selection */}
          <div className="mb-6">
            <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: "var(--text-muted)" }}>
              Step 2 — Select Scan
            </label>
            {scansLoading ? (
              <Skeleton height={40} />
            ) : completedScans.length === 0 ? (
              <p className="text-sm" style={{ color: "var(--text-muted)" }}>No completed scans available</p>
            ) : (
              <select
                className="w-full py-2.5 px-4 text-sm rounded-lg"
                style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)", outline: "none" }}
                value={selectedScanId}
                onChange={(e) => setSelectedScanId(e.target.value)}
              >
                <option value="">Select a scan…</option>
                {completedScans.map((s) => (
                  <option key={s.scan_id} value={s.scan_id}>
                    {s.targets.join(", ")} — {new Date(s.created_at).toLocaleDateString()} ({s.total_assets} assets)
                  </option>
                ))}
              </select>
            )}
          </div>

          {/* Step 3: Format */}
          <div className="mb-6">
            <label className="block text-xs font-semibold uppercase tracking-wide mb-2" style={{ color: "var(--text-muted)" }}>
              Step 3 — Output Format
            </label>
            <div className="flex gap-3">
              {["PDF"].map((f) => (
                <span
                  key={f}
                  className="px-4 py-2 rounded-lg text-sm font-semibold"
                  style={{
                    background: "var(--accent-gold-dim)",
                    color: "var(--accent-gold)",
                    border: "1px solid var(--accent-gold)",
                  }}
                >
                  {f}
                </span>
              ))}
              {["CSV", "JSON"].map((f) => (
                <span
                  key={f}
                  className="px-4 py-2 rounded-lg text-sm font-semibold opacity-50 cursor-not-allowed"
                  style={{ background: "var(--bg-card)", color: "var(--text-muted)", border: "1px solid var(--border-subtle)" }}
                  title="Coming soon"
                >
                  {f}
                </span>
              ))}
            </div>
          </div>

          {/* Alerts */}
          {successMsg && (
            <div className="flex items-center gap-2 p-3 rounded-lg mb-4 animate-fade-in"
                 style={{ background: "rgba(34,197,94,0.1)", border: "1px solid rgba(34,197,94,0.2)", color: "#22c55e" }}>
              <CheckCircle size={16} /> <span className="text-sm">{successMsg}</span>
            </div>
          )}
          {errorMsg && (
            <div className="flex items-center gap-2 p-3 rounded-lg mb-4 animate-fade-in"
                 style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)", color: "#ef4444" }}>
              <AlertTriangle size={16} /> <span className="text-sm">{errorMsg}</span>
            </div>
          )}

          {/* Generate */}
          <button
            className="btn-primary w-full py-3 rounded-xl font-bold text-sm flex items-center justify-center gap-2"
            disabled={!selectedScanId || generating}
            onClick={handleGenerate}
          >
            {generating ? <Loader2 size={18} className="animate-spin" /> : <FileText size={18} />}
            {generating ? "Generating…" : "Generate Report"}
          </button>
        </div>

        {/* Report History */}
        <div className="lg:col-span-3 glass-card-static p-6">
          <h3 className="text-xs font-bold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
            Previously Generated Reports
          </h3>
          {generatedReports.length === 0 ? (
            <EmptyState message="No reports generated yet. Use the builder to create your first report." />
          ) : (
            <div className="space-y-3 max-h-[600px] overflow-y-auto">
              {generatedReports.map((r, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between p-4 rounded-lg"
                  style={{ background: "var(--bg-card)" }}
                >
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: "var(--accent-gold-dim)" }}>
                      <FileText size={18} style={{ color: "var(--accent-gold)" }} />
                    </div>
                    <div>
                      <p className="text-sm font-semibold" style={{ color: "var(--text-primary)" }}>
                        Executive Report — {r.domain}
                      </p>
                      <p className="text-xs" style={{ color: "var(--text-muted)" }}>
                        {new Date(r.generatedAt).toLocaleString()} • PDF • Scan {r.scanId.slice(0, 8)}
                      </p>
                    </div>
                  </div>
                  <button
                    className="btn-outline text-xs flex items-center gap-1"
                    onClick={() => {
                      // Re-generate and download
                      setSelectedScanId(r.scanId);
                      handleGenerate();
                    }}
                  >
                    <Download size={12} /> Download
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
