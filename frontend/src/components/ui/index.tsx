"use client";

import { RISK_COLORS, RISK_LABELS } from "@/lib/types";

export function RiskBadge({ classification }: { classification: string }) {
  const badgeClass =
    classification === "quantum_critical"
      ? "badge-critical"
      : classification === "quantum_vulnerable"
        ? "badge-vulnerable"
        : classification === "quantum_at_risk"
          ? "badge-at-risk"
          : classification === "quantum_aware"
            ? "badge-aware"
            : classification === "quantum_ready"
              ? "badge-ready"
              : "badge-aware";

  return (
    <span className={`badge ${badgeClass}`}>
      {RISK_LABELS[classification] || classification}
    </span>
  );
}

export function ScoreGauge({
  score,
  maxScore = 1000,
  size = 180,
  label,
}: {
  score: number;
  maxScore?: number;
  size?: number;
  label?: string;
}) {
  const radius = (size - 24) / 2;
  const circumference = 2 * Math.PI * radius * 0.75; // 270° arc
  const progress = Math.min(score / maxScore, 1);
  const dashOffset = circumference * (1 - progress);

  const color =
    score < 300
      ? "var(--risk-critical)"
      : score < 500
        ? "var(--risk-vulnerable)"
        : score < 700
          ? "var(--risk-at-risk)"
          : score < 850
            ? "var(--risk-aware)"
            : "var(--risk-ready)";

  return (
    <div className="inline-flex flex-col items-center">
      <div className="relative">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          {/* Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            className="gauge-track"
            strokeDasharray={`${circumference} ${2 * Math.PI * radius - circumference}`}
            strokeDashoffset={0}
            transform={`rotate(135, ${size / 2}, ${size / 2})`}
          />
          {/* Fill */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            className="gauge-fill"
            style={{ stroke: color }}
            strokeDasharray={circumference.toString()}
            strokeDashoffset={dashOffset}
            transform={`rotate(135, ${size / 2}, ${size / 2})`}
          />
        </svg>
        <div
          className="absolute inset-0 flex flex-col items-center justify-center"
        >
          <span
            className="font-black"
            style={{ fontSize: size * 0.22, color, lineHeight: 1 }}
          >
            {score}
          </span>
          <span
            className="text-xs font-semibold mt-1"
            style={{ color: "var(--text-muted)" }}
          >
            / {maxScore}
          </span>
        </div>
      </div>
      {label && (
        <span
          className="mt-2 text-[11px] font-bold uppercase tracking-widest text-center whitespace-nowrap"
          style={{ color }}
        >
          {label}
        </span>
      )}
    </div>
  );
}

export function MetricCard({
  title,
  value,
  subtitle,
  icon,
  color,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ReactNode;
  color?: string;
}) {
  return (
    <div className="glass-card p-5">
      <div className="flex items-start justify-between mb-3">
        <span
          className="text-xs font-semibold uppercase tracking-wider"
          style={{ color: "var(--text-muted)" }}
        >
          {title}
        </span>
        {icon && (
          <span style={{ color: color || "var(--accent-gold)" }}>{icon}</span>
        )}
      </div>
      <div
        className="text-2xl font-black"
        style={{ color: color || "var(--text-primary)" }}
      >
        {value}
      </div>
      {subtitle && (
        <p className="text-xs mt-1" style={{ color: "var(--text-muted)" }}>
          {subtitle}
        </p>
      )}
    </div>
  );
}

export function ProgressBar({
  value,
  max = 100,
  color,
  height = 8,
  showLabel = false,
}: {
  value: number;
  max?: number;
  color?: string;
  height?: number;
  showLabel?: boolean;
}) {
  const pct = Math.min((value / max) * 100, 100);
  return (
    <div className="w-full">
      <div
        className="w-full rounded-full overflow-hidden"
        style={{ height, background: "rgba(255,255,255,0.06)" }}
      >
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{
            width: `${pct}%`,
            background:
              color ||
              `linear-gradient(90deg, var(--accent-gold), #e6a800)`,
          }}
        />
      </div>
      {showLabel && (
        <span
          className="text-xs font-semibold mt-1 inline-block"
          style={{ color: "var(--text-muted)" }}
        >
          {Math.round(pct)}%
        </span>
      )}
    </div>
  );
}

export function Skeleton({
  width,
  height = 20,
  className = "",
}: {
  width?: string | number;
  height?: number;
  className?: string;
}) {
  return (
    <div
      className={`skeleton ${className}`}
      style={{ width: width || "100%", height }}
    />
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-8">
      <div
        className="w-16 h-16 rounded-full flex items-center justify-center mb-4"
        style={{ background: "var(--bg-card)" }}
      >
        <span style={{ color: "var(--text-muted)", fontSize: 28 }}>∅</span>
      </div>
      <p
        className="text-sm text-center max-w-xs"
        style={{ color: "var(--text-muted)" }}
      >
        {message}
      </p>
    </div>
  );
}
