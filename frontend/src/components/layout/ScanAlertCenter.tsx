"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { X } from "lucide-react";
import api from "@/lib/api";
import { notificationStore, type NotificationType } from "@/lib/notifications";
import type { ScanStatus } from "@/lib/types";

type ToastAlert = {
  id: string;
  title: string;
  message: string;
  scanId?: string;
};

const POLL_INTERVAL_MS = 3000;
const TOAST_LIFETIME_MS = 10000;

function isScanNotification(notification: NotificationType) {
  return /scan/i.test(notification.title);
}

export default function ScanAlertCenter() {
  const router = useRouter();
  const seenNotificationIds = useRef<Set<string>>(new Set());
  const [alerts, setAlerts] = useState<ToastAlert[]>([]);

  useEffect(() => {
    for (const notification of notificationStore.getNotifications()) {
      seenNotificationIds.current.add(notification.id);
    }

    return notificationStore.subscribe(() => {
      const notifications = notificationStore.getNotifications();
      const newAlerts: ToastAlert[] = [];

      for (const notification of notifications) {
        if (seenNotificationIds.current.has(notification.id)) continue;
        seenNotificationIds.current.add(notification.id);

        if (isScanNotification(notification)) {
          newAlerts.push({
            id: notification.id,
            title: notification.title,
            message: notification.message,
            scanId: notification.scanId,
          });
        }
      }

      if (newAlerts.length > 0) {
        setAlerts((prev) => [...newAlerts, ...prev].slice(0, 3));
      }
    });
  }, []);

  useEffect(() => {
    const pollActiveScan = async () => {
      const activeScanId = localStorage.getItem("qushield_active_scan");
      if (!activeScanId) return;

      try {
        const { data } = await api.get<ScanStatus>(`/scans/${activeScanId}`);

        if (data.status !== "completed" && data.status !== "failed" && data.status !== "cancelled") {
          return;
        }

        const dedupeKey = `qushield_scan_alerted_${activeScanId}_${data.status}`;
        if (localStorage.getItem(dedupeKey)) return;

        const activeDomain = localStorage.getItem("qushield_active_domain") || "target";
        if (data.status === "completed") {
          notificationStore.addNotification({
            title: "Deep Scan Finished",
            message: `Scan for ${activeDomain} completed. Click to view results.`,
            panelMessage: `Scan finished. ${data.total_assets || 0} assets scanned.`,
            scanId: activeScanId,
          });
        } else if (data.status === "cancelled") {
          notificationStore.addNotification({
            title: "Scan Cancelled",
            message: `Scan for ${activeDomain} was cancelled.`,
            scanId: activeScanId,
          });
        } else {
          notificationStore.addNotification({
            title: "Scan Failed",
            message: data.error_message || `Scan for ${activeDomain} failed.`,
            scanId: activeScanId,
          });
        }

        localStorage.setItem(dedupeKey, "1");
        localStorage.removeItem("qushield_active_scan");
        localStorage.removeItem("qushield_active_domain");
      } catch {
        // Ignore polling errors and keep retrying while scan is active.
      }
    };

    pollActiveScan();
    const id = window.setInterval(pollActiveScan, POLL_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, []);

  useEffect(() => {
    if (alerts.length === 0) return;

    const timer = window.setTimeout(() => {
      setAlerts((prev) => prev.slice(0, -1));
    }, TOAST_LIFETIME_MS);

    return () => window.clearTimeout(timer);
  }, [alerts]);

  const dismissAlert = (id: string) => {
    setAlerts((prev) => prev.filter((alert) => alert.id !== id));
  };

  const viewScanResults = (alert: ToastAlert) => {
    if (alert.scanId) {
      localStorage.setItem("qushield_scan_id", alert.scanId);
    }
    router.push("/assets");
    dismissAlert(alert.id);
  };

  return (
    <div className="fixed right-6 bottom-6 z-[120] flex w-full max-w-sm flex-col gap-3 pointer-events-none">
      {alerts.map((alert) => (
        <div
          key={alert.id}
          className="pointer-events-auto rounded-xl border p-4 shadow-2xl animate-fade-in"
          style={{
            background: "var(--bg-document)",
            borderColor: "var(--accent-gold)",
            boxShadow: "0 16px 40px rgba(0,0,0,0.35)",
          }}
        >
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>
                {alert.title}
              </p>
              <p className="mt-1 text-xs leading-relaxed" style={{ color: "var(--text-secondary)" }}>
                {alert.message}
              </p>
            </div>
            <button
              onClick={() => dismissAlert(alert.id)}
              className="rounded p-1 transition-colors hover:bg-black/10 dark:hover:bg-white/10"
              style={{ color: "var(--text-muted)" }}
              aria-label="Dismiss alert"
            >
              <X size={14} />
            </button>
          </div>

          <button
            onClick={() => viewScanResults(alert)}
            className="mt-3 w-full rounded-lg px-3 py-2 text-xs font-semibold transition-colors"
            style={{
              background: "var(--accent-gold-dim)",
              color: "var(--accent-gold)",
              border: "1px solid var(--accent-gold)",
            }}
          >
            Click here to view results
          </button>
        </div>
      ))}
    </div>
  );
}
