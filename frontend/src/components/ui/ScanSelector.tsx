"use client";

import { useEffect } from "react";
import { ScanStatus } from "@/lib/types";
import { Radar } from "lucide-react";

interface ScanSelectorProps {
  scans: ScanStatus[] | undefined;
  scanId: string | null;
  onChange: (scanId: string | null) => void;
  className?: string;
  allowAll?: boolean;
}

export function ScanSelector({ scans, scanId, onChange, className = "", allowAll = false }: ScanSelectorProps) {
  const completedScans = scans?.filter((s) => s.status === "completed") ?? [];

  useEffect(() => {
    if (!scanId && !allowAll && completedScans.length > 0) {
      const stored = typeof window !== "undefined" ? localStorage.getItem("qushield_scan_id") : null;
      const target = stored ?? completedScans[0].scan_id;
      onChange(target);
    }
  }, [completedScans.length]);

  if (completedScans.length === 0) return null;

  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <Radar size={14} className="text-orange-400 shrink-0" />
      <select
        value={scanId ?? ""}
        onChange={(e) => {
          const val = e.target.value;
          if (val === "") {
            if (typeof window !== "undefined") localStorage.removeItem("qushield_scan_id");
            onChange(null);
          } else {
            if (typeof window !== "undefined") localStorage.setItem("qushield_scan_id", val);
            onChange(val);
          }
        }}
        className="text-xs rounded border px-2 py-1.5 outline-none appearance-none"
        style={{
          background: "var(--bg-card)",
          borderColor: "var(--border-subtle)",
          color: "var(--text-primary)",
          minWidth: 180,
        }}
      >
        {allowAll && (
          <option value="" className="text-black">All scans (global)</option>
        )}
        {completedScans.map((s) => (
          <option key={s.scan_id} value={s.scan_id} className="text-black">
            {s.targets?.join(", ") || s.scan_id.slice(0, 8).toUpperCase()} &mdash;{" "}
            {s.completed_at ? new Date(s.completed_at).toLocaleDateString() : "pending"}
          </option>
        ))}
      </select>
    </div>
  );
}
