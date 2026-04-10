"use client";

import { useEffect, useState } from "react";
import { useRouter, usePathname } from "next/navigation";
import { isLoggedIn } from "@/lib/auth";

export default function AuthGuard({ children }: { children: React.ReactNode }) {
    const router = useRouter();
    const pathname = usePathname();
    const [isChecking, setIsChecking] = useState(true);

    useEffect(() => {
        // Exclude /login from auth check
        if (pathname === "/login") {
            setIsChecking(false);
            return;
        }

        // Check auth status
        if (!isLoggedIn()) {
            router.replace("/login");
        } else {
            setIsChecking(false);
        }
    }, [pathname, router]);

    // Prevent flashing of protected content
    if (isChecking && pathname !== "/login") {
        return (
            <div className="flex h-screen w-screen items-center justify-center bg-[#0a0a0f]">
                <div className="w-8 h-8 border-4 border-[#fdb913] border-t-transparent rounded-full animate-spin"></div>
            </div>
        );
    }

    return <>{children}</>;
}
