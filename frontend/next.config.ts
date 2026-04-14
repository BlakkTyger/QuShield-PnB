import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async rewrites() {
    // Strip trailing slash if present to avoid double slashes in paths
    const rawUrl = process.env.BACKEND_URL || "http://localhost:8000";
    const backendUrl = rawUrl.replace(/\/$/, "");
    
    return [
      {
        source: "/api/:path*",
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
