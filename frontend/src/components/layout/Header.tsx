"use client";

import { Bell } from "lucide-react";

export default function Header() {
  return (
    <header
      className="fixed top-0 right-0 flex items-center justify-between px-8 z-30"
      style={{
        left: "var(--sidebar-width)",
        height: "var(--header-height)",
        background: "rgba(10, 10, 15, 0.85)",
        backdropFilter: "blur(12px)",
        borderBottom: "1px solid var(--border-subtle)",
      }}
    >
      <div>
        <h2
          className="text-sm font-semibold"
          style={{ color: "var(--text-primary)" }}
        >
          Punjab National Bank
        </h2>
        <p className="text-[11px]" style={{ color: "var(--text-muted)" }}>
          Quantum-Safe Crypto Posture Dashboard
        </p>
      </div>

      <div className="flex items-center gap-4">
        {/* Notification Bell */}
        <button
          className="relative p-2 rounded-lg transition-colors"
          style={{ color: "var(--text-secondary)" }}
          title="Notifications"
        >
          <Bell size={18} />
          <span
            className="absolute top-1 right-1 w-2 h-2 rounded-full"
            style={{ background: "var(--accent-magenta)" }}
          />
        </button>
      </div>
    </header>
  );
}
