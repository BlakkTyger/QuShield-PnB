"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  Server,
  Shield,
  AlertTriangle,
  CheckCircle,
  Network,
  Zap,
  Globe,
  History,
  FileText,
  Bot,
  Activity,
} from "lucide-react";

const NAV_ITEMS = [
  { href: "/", label: "Quick Scan", icon: Zap },
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/assets", label: "Assets", icon: Server },
  { href: "/cbom", label: "CBOM Explorer", icon: Shield },
  { href: "/risk", label: "Risk Intelligence", icon: AlertTriangle },
  { href: "/risk/monte-carlo", label: "Monte Carlo Sim", icon: Activity },
  { href: "/compliance", label: "Compliance", icon: CheckCircle },
  { href: "/topology", label: "Topology Map", icon: Network },
  { href: "/geo", label: "GeoIP Map", icon: Globe },
  { href: "/history", label: "Scan History", icon: History },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/ai", label: "AI Assistant", icon: Bot },
];

interface SidebarProps {
  collapsed: boolean;
  searchQuery: string;
}

export default function Sidebar({ collapsed, searchQuery }: SidebarProps) {
  const pathname = usePathname();

  const filteredNavItems = NAV_ITEMS.filter((item) =>
    item.label.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <aside
      className={`fixed left-0 h-screen flex flex-col py-6 z-30 transition-all duration-300 ${collapsed ? "px-2" : "px-4"
        }`}
      style={{
        top: "var(--header-height)",
        height: "calc(100vh - var(--header-height))",
        width: "var(--sidebar-width)",
        background: "var(--sidebar-bg)",
        borderRight: "1px solid var(--border-subtle)",
        boxShadow: "0 0 40px rgba(0,0,0,0.1)",
      }}
    >
      {/* Logo / Brand */}
      <Link href="/" className={`flex items-center gap-3 mb-8 transition-all ${collapsed ? "justify-center px-0" : "px-3"}`}>
        <div
          className="w-9 h-9 rounded-lg flex items-center justify-center font-black text-sm shrink-0"
          style={{
            background: "linear-gradient(135deg, #fdb913, #e6a800)",
            color: "#000",
            boxShadow: "0 4px 12px rgba(0,0,0,0.2)",
          }}
        >
          QS
        </div>
        {!collapsed && (
          <div className="overflow-hidden whitespace-nowrap">
            <h1 className="text-base font-bold leading-tight" style={{ color: "var(--sidebar-brand-text)" }}>
              QuShield
            </h1>
            <p className="text-[10px] font-bold tracking-widest uppercase" style={{ color: "#fdb913" }}>
              PnB Banking
            </p>
          </div>
        )}
      </Link>

      {/* Navigation */}
      <nav className={`flex-1 flex flex-col gap-1 overflow-x-hidden ${collapsed ? "px-1" : "px-1"}`}>
        {filteredNavItems.map(({ href, label, icon: Icon }) => {
          // Check if this route is active - only highlight the most specific (longest) match
          const isActive =
            href === "/"
              ? pathname === "/"
              : pathname === href ||
                (pathname.startsWith(href + "/") &&
                 !NAV_ITEMS.some(item => item.href !== href && item.href.startsWith(href) && pathname.startsWith(item.href)));
          return (
            <Link
              key={href}
              href={href}
              title={collapsed ? label : undefined}
              className={`sidebar-link transition-all ${isActive ? "active" : ""} ${collapsed ? "justify-center px-0" : ""}`}
            >
              <Icon size={18} className="shrink-0" />
              {!collapsed && <span className="whitespace-nowrap">{label}</span>}
            </Link>
          );
        })}
      </nav>

      {/* Footer / Status */}
      {/* {!collapsed ? (
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
      ) : (
        <div className="mt-auto flex justify-center mb-4">
          <span
            className="w-3 h-3 rounded-full"
            title="System Online (v0.1.0)"
            style={{ background: "var(--risk-ready)" }}
          />
        </div>
      )} */}
    </aside>
  );
}
