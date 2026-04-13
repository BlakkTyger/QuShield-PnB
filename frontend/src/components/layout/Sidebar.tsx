"use client";

import { useState, useEffect } from "react";
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
  Globe,
  History,
  FileText,
  Bot,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

const NAV_ITEMS = [
  { href: "/", label: "Quick Scan", icon: Zap },
  { href: "/dashboard", label: "Dashboard", icon: LayoutDashboard },
  { href: "/assets", label: "Assets", icon: Server },
  { href: "/cbom", label: "CBOM Explorer", icon: Shield },
  { href: "/risk", label: "Risk Intelligence", icon: AlertTriangle },
  { href: "/compliance", label: "Compliance", icon: CheckCircle },
  { href: "/topology", label: "Topology Map", icon: Network },
  { href: "/geo", label: "GeoIP Map", icon: Globe },
  { href: "/history", label: "Scan History", icon: History },
  { href: "/reports", label: "Reports", icon: FileText },
  { href: "/ai", label: "AI Assistant", icon: Bot },
];

export default function Sidebar() {
  const pathname = usePathname();

  const [searchQuery, setSearchQuery] = useState("");
  const [collapsed, setCollapsed] = useState(false);

  useEffect(() => {
    const saved = localStorage.getItem("sidebar_collapsed");
    if (saved === "true") {
      setCollapsed(true);
      document.documentElement.style.setProperty("--sidebar-width", "80px");
    } else {
      document.documentElement.style.setProperty("--sidebar-width", "260px");
    }
  }, []);

  const toggleSidebar = () => {
    const next = !collapsed;
    setCollapsed(next);
    localStorage.setItem("sidebar_collapsed", String(next));
    document.documentElement.style.setProperty("--sidebar-width", next ? "80px" : "260px");
  };

  const filteredNavItems = NAV_ITEMS.filter((item) =>
    item.label.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <aside
      className={`fixed left-0 top-0 h-screen flex flex-col py-6 z-40 transition-all duration-300 ${collapsed ? "px-2" : "px-4"
        }`}
      style={{
        width: "var(--sidebar-width)",
        background: "var(--sidebar-bg)",
        borderRight: "1px solid var(--border-subtle)",
        boxShadow: "0 0 40px rgba(0,0,0,0.1)",
      }}
    >
      <button
        onClick={toggleSidebar}
        className="absolute -right-3 top-8 w-6 h-6 rounded-full flex items-center justify-center border transition-colors hover:bg-[var(--accent-gold)] hover:text-black z-50 shadow-lg"
        style={{
          background: "var(--sidebar-active-bg)",
          borderColor: "var(--accent-gold)",
          color: "var(--accent-gold)",
        }}
        title="Toggle Sidebar"
      >
        {collapsed ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
      </button>

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

      {/* Search */}
      {!collapsed && (
        <div className="relative mb-6 px-1">
          <Search
            size={14}
            className="absolute left-4 top-1/2 -translate-y-1/2"
            style={{ color: "var(--sidebar-text-hover)" }}
          />
          <input
            type="text"
            placeholder="Search..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full py-2.5 pl-9 pr-3 text-sm rounded-lg transition-colors"
            style={{
              background: "var(--sidebar-hover-bg)",
              border: "1px solid transparent",
              color: "var(--sidebar-text-hover)",
              outline: "none",
            }}
          />
        </div>
      )}

      {/* Navigation */}
      <nav className={`flex-1 flex flex-col gap-1 overflow-x-hidden ${collapsed ? "px-1" : "px-1"}`}>
        {filteredNavItems.map(({ href, label, icon: Icon }) => {
          const isActive =
            href === "/" ? pathname === "/" : pathname.startsWith(href);
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
