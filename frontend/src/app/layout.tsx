import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Sidebar from "@/components/layout/Sidebar";
import Header from "@/components/layout/Header";
import QueryProvider from "@/lib/QueryProvider";

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
          <Sidebar />
          <Header />
          <main
            className="min-h-screen"
            style={{
              marginLeft: "var(--sidebar-width)",
              paddingTop: "var(--header-height)",
            }}
          >
            <div className="p-6">{children}</div>
          </main>
        </QueryProvider>
      </body>
    </html>
  );
}
