"use client";

import { useState, useEffect, useMemo } from "react";
import { useScans, useGeoMapData } from "@/lib/hooks";
import { EmptyState, Skeleton, RiskBadge } from "@/components/ui";
import { RISK_COLORS } from "@/lib/types";
import dynamic from "next/dynamic";
import type { GeoMarker } from "@/lib/types";

// Leaflet must be loaded client-side only (no SSR)
const MapContainer = dynamic(
  () => import("react-leaflet").then((m) => m.MapContainer),
  { ssr: false }
);
const TileLayer = dynamic(
  () => import("react-leaflet").then((m) => m.TileLayer),
  { ssr: false }
);
const CircleMarker = dynamic(
  () => import("react-leaflet").then((m) => m.CircleMarker),
  { ssr: false }
);
const Popup = dynamic(
  () => import("react-leaflet").then((m) => m.Popup),
  { ssr: false }
);

function getMarkerColor(classification: string | null): string {
  if (!classification) return "#6b7280";
  return RISK_COLORS[classification] || "#6b7280";
}

export default function GeoMapPage() {
  const [scanId, setScanId] = useState<string | null>(null);
  const [leafletReady, setLeafletReady] = useState(false);

  const { data: scans } = useScans();
  useEffect(() => {
    const stored = typeof window !== "undefined" ? localStorage.getItem("qushield_scan_id") : null;
    if (stored) { setScanId(stored); return; }
    if (scans?.length) {
      const completed = scans.find((s) => s.status === "completed");
      if (completed) setScanId(completed.scan_id);
    }
  }, [scans]);

  // Import leaflet CSS client-side
  useEffect(() => {
    import("leaflet/dist/leaflet.css");
    setLeafletReady(true);
  }, []);

  const { data: geoData, isLoading, error } = useGeoMapData(scanId);

  // Summary stats
  const stats = useMemo(() => {
    if (!geoData) return null;
    const markers = geoData.markers;
    const countries = Object.values(geoData.country_summary);
    const inIndia = countries.find((c) => c.country === "India")?.count || 0;
    const overseas = geoData.total_markers - inIndia;

    // Top 5 cities
    const cityMap: Record<string, number> = {};
    markers.forEach((m) => {
      const city = m.city || "Unknown";
      cityMap[city] = (cityMap[city] || 0) + 1;
    });
    const topCities = Object.entries(cityMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    // ISP breakdown
    const ispMap: Record<string, number> = {};
    markers.forEach((m) => {
      const org = m.org || "Unknown";
      ispMap[org] = (ispMap[org] || 0) + 1;
    });
    const topISPs = Object.entries(ispMap)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    const vulnerable = markers.filter(
      (m) =>
        m.risk_classification === "quantum_critical" ||
        m.risk_classification === "quantum_vulnerable"
    ).length;

    return { total: geoData.total_markers, inIndia, overseas, topCities, topISPs, vulnerable };
  }, [geoData]);

  if (!scanId) {
    return <EmptyState message="No scan data available. Run a Quick Scan first." />;
  }

  return (
    <div className="animate-fade-in">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
            GeoIP Infrastructure Map
          </h1>
          <p className="text-sm" style={{ color: "var(--text-muted)" }}>
            Visualize discovered IP addresses on an interactive global map
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Map */}
        <div className="lg:col-span-3 glass-card-static overflow-hidden" style={{ minHeight: 550 }}>
          {isLoading || !leafletReady ? (
            <Skeleton height={550} />
          ) : error ? (
            <EmptyState message="Failed to load geo data. Ensure a scan has been completed." />
          ) : geoData && geoData.markers.length > 0 ? (
            <MapContainer
              center={[20.5937, 78.9629]} // India center
              zoom={5}
              style={{ height: 550, width: "100%", borderRadius: 12 }}
              scrollWheelZoom={true}
            >
              <TileLayer
                attribution='&copy; <a href="https://www.openstreetmap.org">OSM</a>'
                url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              />
              {geoData.markers.map((marker: GeoMarker, i: number) => (
                <CircleMarker
                  key={i}
                  center={[marker.lat, marker.lon]}
                  radius={8}
                  pathOptions={{
                    color: getMarkerColor(marker.risk_classification),
                    fillColor: getMarkerColor(marker.risk_classification),
                    fillOpacity: 0.7,
                    weight: 2,
                  }}
                >
                  <Popup>
                    <div style={{ minWidth: 200, fontFamily: "Inter, sans-serif", color: "#000" }}>
                      <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 4 }}>
                        {marker.hostname || marker.ip}
                      </div>
                      <div style={{ fontSize: 12, lineHeight: 1.6 }}>
                        <div><strong>IP:</strong> {marker.ip}</div>
                        <div><strong>City:</strong> {marker.city || "—"}, {marker.country || "—"}</div>
                        <div><strong>Org:</strong> {marker.org || "—"}</div>
                        <div><strong>Type:</strong> {marker.asset_type || "unknown"}</div>
                        <div><strong>Risk:</strong> {marker.risk_score ?? "—"}/1000</div>
                        <div><strong>Status:</strong> {marker.risk_classification?.replace(/_/g, " ") || "unknown"}</div>
                        {marker.hndl_exposed && (
                          <div style={{ color: "#ef4444", fontWeight: 600, marginTop: 4 }}>
                            ⚠ HNDL Exposed
                          </div>
                        )}
                      </div>
                    </div>
                  </Popup>
                </CircleMarker>
              ))}
            </MapContainer>
          ) : (
            <EmptyState message="No geolocatable IP addresses found in this scan." />
          )}
        </div>

        {/* Sidebar Stats */}
        <div className="flex flex-col gap-4">
          <div className="glass-card-static p-5">
            <h3 className="text-xs font-bold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
              Summary
            </h3>
            <div className="space-y-3">
              <div className="flex justify-between items-center">
                <span className="text-sm" style={{ color: "var(--text-secondary)" }}>Total IPs</span>
                <span className="text-lg font-black" style={{ color: "var(--text-primary)" }}>
                  {stats?.total || 0}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm" style={{ color: "var(--text-secondary)" }}>In India</span>
                <span className="text-lg font-bold" style={{ color: "var(--accent-gold)" }}>
                  {stats?.inIndia || 0}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm" style={{ color: "var(--text-secondary)" }}>Overseas</span>
                <span className="text-lg font-bold" style={{ color: "var(--text-primary)" }}>
                  {stats?.overseas || 0}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-sm" style={{ color: "var(--text-secondary)" }}>Vulnerable</span>
                <span className="text-lg font-bold" style={{ color: "var(--risk-critical)" }}>
                  {stats?.vulnerable || 0}
                </span>
              </div>
            </div>
          </div>

          <div className="glass-card-static p-5">
            <h3 className="text-xs font-bold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
              Top Cities
            </h3>
            <div className="space-y-2">
              {stats?.topCities.map(([city, count]) => (
                <div key={city} className="flex justify-between items-center">
                  <span className="text-sm truncate" style={{ color: "var(--text-secondary)" }}>{city}</span>
                  <span className="text-sm font-bold ml-2" style={{ color: "var(--text-primary)" }}>{count}</span>
                </div>
              ))}
              {!stats?.topCities?.length && (
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>No data</span>
              )}
            </div>
          </div>

          <div className="glass-card-static p-5">
            <h3 className="text-xs font-bold uppercase tracking-wider mb-4" style={{ color: "var(--text-muted)" }}>
              ISP / Org Breakdown
            </h3>
            <div className="space-y-2">
              {stats?.topISPs.map(([isp, count]) => (
                <div key={isp} className="flex justify-between items-center">
                  <span className="text-xs truncate max-w-[140px]" style={{ color: "var(--text-secondary)" }}>{isp}</span>
                  <span className="text-sm font-bold ml-2" style={{ color: "var(--text-primary)" }}>{count}</span>
                </div>
              ))}
              {!stats?.topISPs?.length && (
                <span className="text-xs" style={{ color: "var(--text-muted)" }}>No data</span>
              )}
            </div>
          </div>

          {/* Legend */}
          <div className="glass-card-static p-5">
            <h3 className="text-xs font-bold uppercase tracking-wider mb-3" style={{ color: "var(--text-muted)" }}>
              Legend
            </h3>
            <div className="space-y-2 text-xs">
              {Object.entries(RISK_COLORS).map(([key, color]) => (
                <div key={key} className="flex items-center gap-2">
                  <span className="w-3 h-3 rounded-full flex-shrink-0" style={{ background: color }} />
                  <span style={{ color: "var(--text-secondary)" }}>{key.replace(/_/g, " ")}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
