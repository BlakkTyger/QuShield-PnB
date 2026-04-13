"use client";

import { usePathname } from "next/navigation";
import Sidebar from "./Sidebar";
import Header from "./Header";
import AuthGuard from "./AuthGuard";
import ScanAlertCenter from "./ScanAlertCenter";

/**
 * AppShell — conditionally renders the Sidebar + Header chrome.
 * Pages like /login render without the shell for a full-screen experience.
 */
const CHROME_EXCLUDED_ROUTES = ["/login"];

export default function AppShell({ children }: { children: React.ReactNode }) {
    const pathname = usePathname();
    const showChrome = !CHROME_EXCLUDED_ROUTES.some((r) =>
        pathname.startsWith(r)
    );

    if (!showChrome) {
        return <AuthGuard>{children}</AuthGuard>;
    }

    return (
        <AuthGuard>
            <Sidebar />
            <Header />
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
    );
}
