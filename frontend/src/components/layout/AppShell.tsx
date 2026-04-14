"use client";

import { useState, useEffect, createContext, useContext } from "react";
import { usePathname } from "next/navigation";
import Sidebar from "./Sidebar";
import Header from "./Header";
import AuthGuard from "./AuthGuard";
import ScanAlertCenter from "./ScanAlertCenter";

interface AppShellContextType {
  collapsed: boolean;
  toggleSidebar: () => void;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
}

const AppShellContext = createContext<AppShellContextType>({
  collapsed: false,
  toggleSidebar: () => {},
  searchQuery: "",
  setSearchQuery: () => {},
});

export const useAppShell = () => useContext(AppShellContext);

/**
 * AppShell — conditionally renders the Sidebar + Header chrome.
 * Pages like /login render without the shell for a full-screen experience.
 */
const CHROME_EXCLUDED_ROUTES = ["/login"];

export default function AppShell({ children }: { children: React.ReactNode }) {
    const pathname = usePathname();
    const [collapsed, setCollapsed] = useState(false);
    const [searchQuery, setSearchQuery] = useState("");

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

    const showChrome = !CHROME_EXCLUDED_ROUTES.some((r) =>
        pathname.startsWith(r)
    );

    if (!showChrome) {
        return <AuthGuard>{children}</AuthGuard>;
    }

    return (
        <AppShellContext.Provider value={{ collapsed, toggleSidebar, searchQuery, setSearchQuery }}>
            <AuthGuard>
                <Sidebar collapsed={collapsed} searchQuery={searchQuery} />
                <Header onToggleSidebar={toggleSidebar} searchQuery={searchQuery} setSearchQuery={setSearchQuery} />
                <ScanAlertCenter />
                <main
                    className="min-h-screen transition-all duration-300"
                    style={{
                        marginLeft: "var(--sidebar-width)",
                        paddingTop: "var(--header-height)",
                    }}
                >
                    <div className="p-6">{children}</div>
                </main>
            </AuthGuard>
        </AppShellContext.Provider>
    );
}
