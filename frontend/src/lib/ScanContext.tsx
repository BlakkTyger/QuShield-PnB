"use client";
import { createContext, useContext, useState, type ReactNode } from "react";

interface ScanCtx {
  activeScanId: string | null;
  setActiveScanId: (id: string | null) => void;
}

const ScanContext = createContext<ScanCtx>({
  activeScanId: null,
  setActiveScanId: () => {},
});

export const useScanContext = () => useContext(ScanContext);

export function ScanProvider({ children }: { children: ReactNode }) {
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  return (
    <ScanContext.Provider value={{ activeScanId, setActiveScanId }}>
      {children}
    </ScanContext.Provider>
  );
}
