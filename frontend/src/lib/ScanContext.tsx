"use client";
import { createContext, useContext, useState, useEffect, type ReactNode } from "react";

interface ScanCtx {
  activeScanId: string | null;
  activeDomain: string | null;
  activeScanType: string | null;
  setActiveScan: (id: string | null, domain?: string | null, type?: string | null) => void;
}

const ScanContext = createContext<ScanCtx>({
  activeScanId: null,
  activeDomain: null,
  activeScanType: null,
  setActiveScan: () => {},
});

export const useScanContext = () => useContext(ScanContext);

export function ScanProvider({ children }: { children: ReactNode }) {
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [activeDomain, setActiveDomain] = useState<string | null>(null);
  const [activeScanType, setActiveScanType] = useState<string | null>(null);

  useEffect(() => {
    // Restore on mount
    if (typeof window !== "undefined") {
      setActiveScanId(localStorage.getItem("qushield_scan_id"));
      setActiveDomain(localStorage.getItem("qushield_active_domain"));
      setActiveScanType(localStorage.getItem("qushield_active_type"));
    }
    
    // Listen for cross-tab or auth changes
    const handleStorage = () => {
      setActiveScanId(localStorage.getItem("qushield_scan_id"));
      setActiveDomain(localStorage.getItem("qushield_active_domain"));
      setActiveScanType(localStorage.getItem("qushield_active_type"));
    };
    
    window.addEventListener("storage", handleStorage);
    window.addEventListener("qushield-auth-change", handleStorage);
    return () => {
      window.removeEventListener("storage", handleStorage);
      window.removeEventListener("qushield-auth-change", handleStorage);
    };
  }, []);

  const setActiveScan = (id: string | null, domain: string | null = null, type: string | null = null) => {
    setActiveScanId(id);
    setActiveDomain(domain);
    setActiveScanType(type);
    
    if (typeof window !== "undefined") {
      if (id) localStorage.setItem("qushield_scan_id", id);
      else localStorage.removeItem("qushield_scan_id");
      
      if (domain) localStorage.setItem("qushield_active_domain", domain);
      else localStorage.removeItem("qushield_active_domain");
      
      if (type) localStorage.setItem("qushield_active_type", type);
      else localStorage.removeItem("qushield_active_type");
    }
  };

  return (
    <ScanContext.Provider value={{ activeScanId, activeDomain, activeScanType, setActiveScan }}>
      {children}
    </ScanContext.Provider>
  );
}
