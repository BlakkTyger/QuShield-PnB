"use client";

import { useState, useEffect } from "react";
import { ChevronDown, Search, Loader2 } from "lucide-react";
import { useScans } from "@/lib/hooks";
import { useScanContext } from "@/lib/ScanContext";

interface ScanSelectorProps {
  onScanChange?: (scanId: string, domain: string) => void;
  className?: string;
}

export function ScanSelector({ onScanChange, className = "" }: ScanSelectorProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null);
  
  const { data: scans, isLoading } = useScans(20);

  const { activeScanId, setActiveScan } = useScanContext();

  useEffect(() => {
    // Keep internal selector state in sink with context
    setSelectedId(activeScanId);
  }, [activeScanId]);

  useEffect(() => {
    if (scans && selectedId) {
      const match = scans.find(s => s.scan_id === selectedId);
      if (match) {
        setSelectedDomain(match.targets[0] || "Unknown");
      }
    }
  }, [scans, selectedId]);

  const handleSelect = (scanId: string, domain: string, scanType?: string) => {
    setActiveScan(scanId, domain, scanType);
    setIsOpen(false);
    if (onScanChange) {
      onScanChange(scanId, domain);
    }
  };

  return (
    <div className={`relative ${className}`}>
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-3 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all w-full md:w-64 justify-between bg-[var(--bg-document)] border border-[var(--border-subtle)] hover:border-[var(--accent-gold)]"
      >
        <span className="truncate">
          {isLoading ? (
            <span className="flex items-center gap-2 opacity-50">
              <Loader2 size={14} className="animate-spin" /> Loading scans...
            </span>
          ) : selectedDomain ? (
            <span>Scan: <span className="text-[var(--accent-gold)]">{selectedDomain}</span></span>
          ) : (
            <span className="opacity-50">Select a scan...</span>
          )}
        </span>
        <ChevronDown size={16} className={`transition-transform ${isOpen ? "rotate-180" : ""}`} />
      </button>

      {isOpen && (
        <div className="absolute top-full mt-2 left-0 right-0 z-[100] glass-card shadow-2xl overflow-hidden animate-slide-up max-h-64 overflow-y-auto border border-[var(--accent-gold-dim)]">
          {scans?.length === 0 ? (
            <div className="p-4 text-center text-xs text-[var(--text-muted)] italic">
              No scans found.
            </div>
          ) : (
            <div className="flex flex-col">
              {scans?.map((scan) => (
                <button
                  key={scan.scan_id}
                  onClick={() => handleSelect(scan.scan_id, scan.targets[0], scan.scan_type)}
                  className={`px-4 py-3 text-left text-xs transition-colors hover:bg-[var(--accent-gold-dim)] border-b border-[rgba(255,255,255,0.03)] last:border-0 ${selectedId === scan.scan_id ? "bg-[rgba(251,188,9,0.05)] text-[var(--accent-gold)]" : "text-[var(--text-secondary)]"}`}
                >
                  <div className="font-bold truncate">{scan.targets[0]}</div>
                  <div className="flex items-center gap-2 mt-1 opacity-60">
                    <span className="capitalize">{scan.scan_type}</span>
                    <span>•</span>
                    <span>{new Date(scan.created_at).toLocaleDateString()}</span>
                  </div>
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
