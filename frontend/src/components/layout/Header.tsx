"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Bell, Sun, Moon, LogOut, User as UserIcon } from "lucide-react";
import { fetchCurrentUser, clearTokens, UserResponse } from "@/lib/auth";
import { useNotifications } from "@/lib/notifications";

export default function Header() {
  const router = useRouter();
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [user, setUser] = useState<UserResponse | null>(null);
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const { notifications, unreadCount, markAsRead, markAllAsRead } = useNotifications();

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
      className="fixed top-0 right-0 flex items-center justify-between px-8 z-30 transition-all duration-300"
      style={{
        left: "var(--sidebar-width)",
        height: "var(--header-height)",
        background: "var(--header-bg)",
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
        <div className="relative">
          <button
            className="p-2 rounded-lg transition-colors hover:bg-black/5 dark:hover:bg-white/5 relative"
            style={{ color: "var(--text-secondary)" }}
            title="Notifications"
            onClick={() => setNotificationsOpen(!notificationsOpen)}
          >
            <Bell size={18} />
            {unreadCount > 0 && (
              <span
                className="absolute top-1 right-1 w-2 h-2 rounded-full"
                style={{ background: "var(--accent-magenta)" }}
              />
            )}
          </button>

          {notificationsOpen && (
            <div
              className="absolute right-0 mt-2 w-80 rounded-xl shadow-2xl p-4 z-50 text-sm"
              style={{
                background: "var(--bg-document)",
                border: "1px solid var(--border-subtle)",
                color: "var(--text-primary)",
                boxShadow: "0 16px 48px rgba(0,0,0,0.35)",
              }}
            >
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-bold">Notifications</h3>
                {unreadCount > 0 && (
                  <button
                    onClick={() => markAllAsRead()}
                    className="text-xs hover:underline"
                    style={{ color: "var(--accent-magenta)" }}
                  >
                    Mark all read
                  </button>
                )}
              </div>
              <div className="flex flex-col gap-3 max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <p className="text-xs text-center py-4" style={{ color: "var(--text-muted)" }}>
                    No notifications yet.
                  </p>
                ) : (
                  notifications.map((n) => (
                    <div
                      key={n.id}
                      className="p-3 rounded-lg flex flex-col gap-1 cursor-pointer transition-colors"
                      style={{
                        background: n.read
                          ? "var(--bg-secondary)"
                          : theme === "dark"
                            ? "#1e1e28"
                            : "var(--bg-card)",
                        border: "1px solid var(--border-subtle)",
                      }}
                      onClick={() => markAsRead(n.id)}
                    >
                      <h4 className="font-semibold text-xs">{n.title}</h4>
                      <p className="text-[11px]" style={{ color: "var(--text-secondary)" }}>
                        {n.message}
                      </p>
                    </div>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

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
