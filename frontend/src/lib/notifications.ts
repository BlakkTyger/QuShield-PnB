import { useState, useEffect } from "react";

export type NotificationType = {
    id: string;
    title: string;
    message: string;
    panelMessage?: string;
    date: string;
    read: boolean;
    scanId?: string;
};

// A simple event-based store since we don't have Zustand
class NotificationStore {
    private notifications: NotificationType[] = [];
    private listeners: Set<() => void> = new Set();

    constructor() {
        if (typeof window !== "undefined") {
            const saved = localStorage.getItem("qushield_notifications");
            if (saved) {
                try {
                    this.notifications = JSON.parse(saved);
                } catch (e) {
                    // ignore
                }
            }
        }
    }

    getNotifications() {
        return this.notifications;
    }

    addNotification(notification: Omit<NotificationType, "id" | "date" | "read">) {
        const newNotif: NotificationType = {
            ...notification,
            id: Math.random().toString(36).substring(2, 9),
            date: new Date().toISOString(),
            read: false,
        };
        this.notifications = [newNotif, ...this.notifications].slice(0, 50); // Keep last 50
        this.save();
        this.notify();
    }

    markAsRead(id: string) {
        this.notifications = this.notifications.map((n) =>
            n.id === id ? { ...n, read: true } : n
        );
        this.save();
        this.notify();
    }

    markAllAsRead() {
        this.notifications = this.notifications.map((n) => ({ ...n, read: true }));
        this.save();
        this.notify();
    }

    subscribe(listener: () => void) {
        this.listeners.add(listener);
        return () => {
            this.listeners.delete(listener);
        };
    }

    private save() {
        if (typeof window !== "undefined") {
            localStorage.setItem("qushield_notifications", JSON.stringify(this.notifications));
        }
    }

    private notify() {
        this.listeners.forEach((l) => l());
    }
}

export const notificationStore = new NotificationStore();

export function useNotifications() {
    const [notifications, setNotifications] = useState<NotificationType[]>(notificationStore.getNotifications());

    useEffect(() => {
        return notificationStore.subscribe(() => {
            setNotifications(notificationStore.getNotifications());
        });
    }, []);

    return {
        notifications,
        unreadCount: notifications.filter((n) => !n.read).length,
        addNotification: (n: Omit<NotificationType, "id" | "date" | "read">) => notificationStore.addNotification(n),
        markAsRead: (id: string) => notificationStore.markAsRead(id),
        markAllAsRead: () => notificationStore.markAllAsRead(),
    };
}
