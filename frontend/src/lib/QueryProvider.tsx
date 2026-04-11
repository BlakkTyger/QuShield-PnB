"use client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState, useEffect, type ReactNode } from "react";

export default function QueryProvider({ children }: { children: ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30_000,
            retry: 1,
            refetchOnWindowFocus: false,
          },
        },
      })
  );

  // Clear all cached queries when user auth state changes (login/logout)
  // This prevents stale data from User A appearing for User B
  useEffect(() => {
    const handleAuthChange = () => {
      client.clear();
    };
    window.addEventListener("qushield-auth-change", handleAuthChange);
    return () => window.removeEventListener("qushield-auth-change", handleAuthChange);
  }, [client]);

  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}
