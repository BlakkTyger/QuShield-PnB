import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import QueryProvider from "@/lib/QueryProvider";
import AppShell from "@/components/layout/AppShell";
import { ScanProvider } from "@/lib/ScanContext";

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
});

export const metadata: Metadata = {
  title: "QuShield — Quantum-Safe Crypto Scanner",
  description:
    "Post-Quantum Cryptographic Bill of Materials (CBOM) Scanner for Indian Banking Infrastructure. " +
    "Discover, inventory, and assess quantum risk across your organization.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={inter.variable}>
      <body className="antialiased">
        <QueryProvider>
          <ScanProvider>
            <AppShell>{children}</AppShell>
          </ScanProvider>
        </QueryProvider>
      </body>
    </html>
  );
}
