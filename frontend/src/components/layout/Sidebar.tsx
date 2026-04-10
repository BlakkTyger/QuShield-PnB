"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Search,
  LayoutDashboard,
  Server,
  Shield,
  AlertTriangle,
  CheckCircle,
  Network,
  Zap,
} from "lucide-react";

const NAV_ITEMS = [
  { href: "/", label: "Quick Scan", icon: Zap },
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/assets", label: "Assets", icon: Server },
  { href: "/cbom", label: "CBOM Explorer", icon: Shield },
  { href: "/risk", label: "Risk Intelligence", icon: AlertTriangle },
  { href: "/compliance", label: "Compliance", icon: CheckCircle },
  { href: "/topology", label: "Topology Map", icon: Network },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      className="fixed left-0 top-0 h-screen flex flex-col py-6 px-4 z-40"
      style={{
        width: "var(--sidebar-width)",
        background: "var(--sidebar-bg)",
        borderRight: "1px solid var(--border-subtle)",
        boxShadow: "0 0 40px rgba(0,0,0,0.1)",
      }}
    >
      {/* Logo / Brand */}
      <Link href="/" className="flex items-center gap-3 px-3 mb-8">
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center font-black text-sm"
          style={{
            background: "linear-gradient(135deg, #fdb913, #e6a800)",
            color: "#000",
            boxShadow: "0 4px 12px rgba(0,0,0,0.2)",
          }}
        >
          QS
        </div>
        <div>
          <h1 className="text-base font-bold leading-tight" style={{ color: "var(--sidebar-brand-text)" }}>
            QuShield
          </h1>
          <p className="text-[10px] font-bold tracking-widest uppercase" style={{ color: "#fdb913" }}>
            PnB Banking
          </p>
        </div>
      </Link>

      {/* Search */}
      <div className="relative mb-6 px-1">
        <Search
          size={14}
          className="absolute left-4 top-1/2 -translate-y-1/2"
          style={{ color: "var(--sidebar-text-hover)" }}
        />
        <input
          type="text"
          placeholder="Search..."
          className="w-full py-2.5 pl-9 pr-3 text-sm rounded-lg"
          style={{
            background: "var(--sidebar-hover-bg)",
            border: "1px solid transparent",
            color: "var(--sidebar-text-hover)",
            outline: "none",
          }}
        />
      </div>

      {/* Navigation */}
      <nav className="flex-1 flex flex-col gap-1 px-1">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const isActive =
            href === "/" ? pathname === "/" : pathname.startsWith(href);
          return (
            <Link
              key={href}
              href={href}
              className={`sidebar-link ${isActive ? "active" : ""}`}
            >
              <Icon size={18} />
              {label}
            </Link>
          );
        })}
      </nav>

      {/* Footer / Status */}
      <div
        className="mt-auto mx-1 p-3 rounded-lg text-xs"
        style={{ background: "var(--bg-card)", color: "var(--text-muted)" }}
      >
        <div className="flex items-center gap-2 mb-1">
          <span
            className="w-2 h-2 rounded-full"
            style={{ background: "var(--risk-ready)" }}
          />
          <span style={{ color: "var(--text-secondary)" }}>System Online</span>
        </div>
        <span>v0.1.0 — POC</span>
      </div>
    </aside>
  );
}
