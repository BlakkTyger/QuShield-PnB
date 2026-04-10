"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useScans } from "@/lib/hooks";
import { EmptyState, Skeleton, RiskBadge } from "@/components/ui";
import { RefreshCw, ArrowRight, Clock, Zap, Search as SearchIcon, Layers } from "lucide-react";

type ScanTypeFilter = "" | "quick" | "shallow" | "deep";

export default function ScanHistoryPage() {
  const router = useRouter();
  const { data: scans, isLoading, refetch } = useScans();
  const [typeFilter, setTypeFilter] = useState<ScanTypeFilter>("");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");

  const filteredScans = (scans || []).filter((s) => {
    if (typeFilter && (s as unknown as Record<string, unknown>).scan_type !== typeFilter) return false;
    if (statusFilter && s.status !== statusFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const matchTarget = s.targets.some((t) => t.toLowerCase().includes(q));
      const matchId = s.scan_id.toLowerCase().includes(q);
      if (!matchTarget && !matchId) return false;
    }
    return true;
  });

  const handleViewScan = (scanId: string) => {
    if (typeof window !== "undefined") {
      localStorage.setItem("qushield_scan_id", scanId);
    }
    router.push("/dashboard");
  };

  const getScanTypeColor = (type: string) => {
    switch (type) {
      case "quick": return "var(--risk-ready)";
      case "shallow": return "var(--accent-gold)";
      case "deep": return "var(--accent-magenta)";
      default: return "var(--text-muted)";
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed": return "var(--risk-ready)";
      case "running": return "var(--accent-gold)";
      case "failed": return "var(--risk-critical)";
      case "queued": return "var(--text-muted)";
      default: return "var(--text-muted)";
    }
  };

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            Scan History
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            All scans run by your account, grouped and filterable
          </p>
        </div>
        <button
          className="btn-outline flex items-center gap-2"
          onClick={() => refetch()}
        >
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 mb-6">
        <div className="relative flex-1 min-w-[200px]">
          <SearchIcon size={14} className="absolute left-3 top-1/2 -translate-y-1/2" style={{ color: "var(--text-muted)" }} />
          <input
            type="text"
            placeholder="Search domain or scan ID…"
            className="w-full py-2.5 pl-9 pr-3 text-sm rounded-lg"
            style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)", outline: "none" }}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="py-2.5 px-4 text-sm rounded-lg"
          style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)", outline: "none" }}
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value as ScanTypeFilter)}
        >
          <option value="">All Types</option>
          <option value="quick">Quick</option>
          <option value="shallow">Shallow</option>
          <option value="deep">Deep</option>
        </select>
        <select
          className="py-2.5 px-4 text-sm rounded-lg"
          style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)", outline: "none" }}
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          <option value="">All Status</option>
          <option value="completed">Completed</option>
          <option value="running">Running</option>
          <option value="failed">Failed</option>
          <option value="queued">Queued</option>
        </select>
      </div>

      {/* Table */}
      <div className="glass-card-static overflow-hidden">
        {isLoading ? (
          <div className="p-8">
            {[...Array(6)].map((_, i) => <Skeleton key={i} height={40} className="mb-2" />)}
          </div>
        ) : filteredScans.length === 0 ? (
          <EmptyState message="No scans found. Run your first scan from the Quick Scan page." />
        ) : (
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Domain(s)</th>
                  <th>Scan Type</th>
                  <th>Status</th>
                  <th>Date</th>
                  <th>Assets</th>
                  <th>Vulnerable</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => (
                  <tr key={scan.scan_id} className="cursor-pointer" onClick={() => handleViewScan(scan.scan_id)}>
                    <td>
                      <div className="flex flex-col">
                        <span className="font-medium text-sm" style={{ color: "var(--text-primary)" }}>
                          {scan.targets.join(", ")}
                        </span>
                        <span className="text-[10px] font-mono" style={{ color: "var(--text-muted)" }}>
                          {scan.scan_id.slice(0, 8)}…
                        </span>
                      </div>
                    </td>
                    <td>
                      <span
                        className="px-2 py-0.5 rounded text-[10px] font-bold uppercase"
                        style={{
                          background: `color-mix(in srgb, ${getScanTypeColor((scan as unknown as Record<string, string>).scan_type || "deep")} 15%, transparent)`,
                          color: getScanTypeColor((scan as unknown as Record<string, string>).scan_type || "deep"),
                        }}
                      >
                        {(scan as unknown as Record<string, string>).scan_type || "deep"}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{ background: getStatusColor(scan.status) }}
                        />
                        <span className="text-sm capitalize" style={{ color: "var(--text-secondary)" }}>
                          {scan.status}
                        </span>
                      </div>
                    </td>
                    <td>
                      <span className="text-sm" style={{ color: "var(--text-secondary)" }}>
                        {new Date(scan.created_at).toLocaleDateString()} {new Date(scan.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </td>
                    <td>
                      <span className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                        {scan.total_assets}
                      </span>
                    </td>
                    <td>
                      <span
                        className="text-sm font-bold"
                        style={{ color: scan.total_vulnerable > 0 ? "var(--risk-critical)" : "var(--risk-ready)" }}
                      >
                        {scan.total_vulnerable}
                      </span>
                    </td>
                    <td>
                      <button
                        className="flex items-center gap-1 text-xs font-semibold px-3 py-1.5 rounded-lg transition-colors hover:bg-[var(--accent-gold-dim)]"
                        style={{ color: "var(--accent-gold)" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          handleViewScan(scan.scan_id);
                        }}
                      >
                        View <ArrowRight size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
