"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, Sun, Moon, LogOut, User as UserIcon } from "lucide-react";
import { fetchCurrentUser, clearTokens, UserResponse } from "@/lib/auth";

export default function Header() {
  const router = useRouter();
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [user, setUser] = useState<UserResponse | null>(null);

  useEffect(() => {
    // Check initial theme from document (if any) or localStorage
    const savedTheme = localStorage.getItem("theme") as "dark" | "light" | null;
    if (savedTheme) {
      setTheme(savedTheme);
      document.documentElement.setAttribute("data-theme", savedTheme);
    }
  }, []);

  useEffect(() => {
    // Fetch current user
    fetchCurrentUser()
      .then((data) => setUser(data))
      .catch(() => {
        // Token might be invalid or expired, handle gracefully
        clearTokens();
        router.push("/login");
      });
  }, [router]);

  const toggleTheme = () => {
    const newTheme = theme === "dark" ? "light" : "dark";
    setTheme(newTheme);
    document.documentElement.setAttribute("data-theme", newTheme);
    localStorage.setItem("theme", newTheme);
  };

  const handleLogout = () => {
    clearTokens();
    router.push("/login");
  };

  return (
    <header
      className="fixed top-0 right-0 flex items-center justify-between px-8 z-30"
      style={{
        left: "var(--sidebar-width)",
        height: "var(--header-height)",
        background: theme === "light" ? "rgba(255, 255, 255, 0.85)" : "rgba(10, 10, 15, 0.85)",
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
        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 rounded-lg transition-colors hover:bg-black/5 dark:hover:bg-white/5"
          style={{ color: "var(--text-secondary)" }}
          title={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
        >
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        {/* Notification Bell */}
        <button
          className="relative p-2 rounded-lg transition-colors hover:bg-black/5 dark:hover:bg-white/5"
          style={{ color: "var(--text-secondary)" }}
          title="Notifications"
        >
          <Bell size={18} />
          <span
            className="absolute top-1 right-1 w-2 h-2 rounded-full"
            style={{ background: "var(--accent-magenta)" }}
          />
        </button>

        <div className="w-px h-6 bg-current opacity-20 mx-2" style={{ color: "var(--border-subtle)" }}></div>

        {/* User Profile */}
        <div className="flex items-center gap-3">
          <div className="flex flex-col items-end">
            <span className="text-sm font-medium" style={{ color: "var(--text-primary)" }}>
              {user?.email || "Loading..."}
            </span>
            <span className="text-[10px] uppercase tracking-wider font-bold" style={{ color: "var(--accent-gold)" }}>
              Admin
            </span>
          </div>
          <div
            className="w-9 h-9 rounded-full flex items-center justify-center"
            style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}
          >
            <UserIcon size={16} />
          </div>

          {/* Logout Button */}
          <button
            onClick={handleLogout}
            className="ml-2 p-2 rounded-lg transition-colors flex items-center gap-1 text-xs font-semibold hover:bg-red-500/10 hover:text-red-500"
            style={{ color: "var(--text-secondary)" }}
            title="Log Out"
          >
            <LogOut size={16} />
          </button>
        </div>
      </div>
    </header>
  );
}
