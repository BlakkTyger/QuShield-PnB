"use client";

import { useParams, useRouter } from "next/navigation";
import { useState, useMemo } from "react";
import {
  ArrowLeft, Shield, ShieldCheck, ShieldAlert, ShieldX,
  Lock, Unlock, CheckCircle2, XCircle, AlertTriangle, Info,
  ChevronDown, ChevronUp, Search, ExternalLink,
} from "lucide-react";
import { useTestSSLResults, useTestSSLHistory } from "@/lib/hooks";
import { Skeleton, EmptyState } from "@/components/ui";
import type {
  TLSInspectionSummary, TLSFinding, TLSVulnStatus,
  TLSProtocolSupport,
} from "@/lib/types";

/* ─── Severity colors ────────────────────────────────────── */
const SEV_COLORS: Record<string, string> = {
  CRITICAL: "#ef4444",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  WARN: "#a855f7",
  INFO: "#6b7280",
  OK: "#22c55e",
};

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN", "INFO", "OK"];

const GRADE_COLORS: Record<string, string> = {
  "A+": "#16a34a",
  A: "#22c55e",
  "A-": "#4ade80",
  "B+": "#2563eb",
  B: "#3b82f6",
  "B-": "#60a5fa",
  C: "#eab308",
  D: "#f97316",
  F: "#ef4444",
  T: "#6b7280",
};

/* ─── Grade Badge ─────────────────────────────────────────── */
function GradeBadge({ grade }: { grade: string }) {
  return (
    <div
      className="flex items-center justify-center w-16 h-16 rounded-xl text-3xl font-black shadow-lg"
      style={{
        background: `${GRADE_COLORS[grade] || "#6b7280"}22`,
        color: GRADE_COLORS[grade] || "#6b7280",
        border: `2px solid ${GRADE_COLORS[grade] || "#6b7280"}44`,
      }}
    >
      {grade}
    </div>
  );
}

/* ─── Severity Icon ───────────────────────────────────────── */
function SevIcon({ severity }: { severity: string }) {
  const color = SEV_COLORS[severity] || "#6b7280";
  switch (severity) {
    case "CRITICAL":
      return <ShieldX size={14} style={{ color }} />;
    case "HIGH":
      return <ShieldAlert size={14} style={{ color }} />;
    case "MEDIUM":
      return <AlertTriangle size={14} style={{ color }} />;
    case "OK":
      return <CheckCircle2 size={14} style={{ color }} />;
    default:
      return <Info size={14} style={{ color }} />;
  }
}

/* ─── Donut Chart (pure CSS) ──────────────────────────────── */
function SeverityDonut({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((s, v) => s + v, 0);
  if (total === 0) return null;

  const segments: { color: string; pct: number; label: string; count: number }[] = [];
  let cumulative = 0;
  for (const sev of SEV_ORDER) {
    const count = counts[sev] || 0;
    if (count === 0) continue;
    const pct = (count / total) * 100;
    segments.push({ color: SEV_COLORS[sev], pct, label: sev, count });
    cumulative += pct;
  }

  const gradientParts: string[] = [];
  let offset = 0;
  for (const seg of segments) {
    gradientParts.push(`${seg.color} ${offset}% ${offset + seg.pct}%`);
    offset += seg.pct;
  }
  const gradient = `conic-gradient(${gradientParts.join(", ")})`;

  return (
    <div className="flex items-center gap-6">
      <div
        className="w-32 h-32 rounded-full flex items-center justify-center"
        style={{
          background: gradient,
        }}
      >
        <div
          className="w-20 h-20 rounded-full flex items-center justify-center"
          style={{ background: "var(--bg-primary)" }}
        >
          <span className="text-xl font-black" style={{ color: "var(--text-primary)" }}>
            {total}
          </span>
        </div>
      </div>
      <div className="flex flex-col gap-1">
        {segments.map((seg) => (
          <div key={seg.label} className="flex items-center gap-2 text-xs">
            <div className="w-3 h-3 rounded-sm" style={{ background: seg.color }} />
            <span style={{ color: "var(--text-secondary)" }}>{seg.label}</span>
            <span className="font-bold" style={{ color: "var(--text-primary)" }}>{seg.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Protocol Matrix ─────────────────────────────────────── */
function ProtocolMatrix({ protocols }: { protocols: Record<string, TLSProtocolSupport> }) {
  const order = ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"];
  const labels: Record<string, string> = {
    SSLv2: "SSL 2.0", SSLv3: "SSL 3.0", TLS1: "TLS 1.0",
    TLS1_1: "TLS 1.1", TLS1_2: "TLS 1.2", TLS1_3: "TLS 1.3",
  };
  const deprecated = new Set(["SSLv2", "SSLv3", "TLS1", "TLS1_1"]);

  return (
    <div className="grid grid-cols-6 gap-2">
      {order.map((pid) => {
        const p = protocols[pid];
        const offered = p?.offered ?? false;
        const isDep = deprecated.has(pid);
        const bg = offered && isDep ? "#ef444422" : offered ? "#22c55e22" : "var(--bg-card)";
        const border = offered && isDep ? "#ef444444" : offered ? "#22c55e44" : "var(--border-subtle)";
        const color = offered && isDep ? "#ef4444" : offered ? "#22c55e" : "var(--text-muted)";
        const icon = offered && isDep ? <Unlock size={18} /> : offered ? <Lock size={18} /> : null;

        return (
          <div
            key={pid}
            className="flex flex-col items-center p-3 rounded-lg text-center"
            style={{ background: bg, border: `1px solid ${border}`, color }}
          >
            <div className="mb-1">{icon}</div>
            <span className="text-xs font-bold">{labels[pid] || pid}</span>
            <span className="text-[10px] mt-0.5">{offered ? "Offered" : "No"}</span>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Vulnerability Grid ──────────────────────────────────── */
function VulnGrid({ vulns }: { vulns: Record<string, TLSVulnStatus> }) {
  const vulnNames: Record<string, string> = {
    heartbleed: "Heartbleed", CCS: "CCS Injection", ticketbleed: "Ticketbleed",
    ROBOT: "ROBOT", secure_renego: "Secure Renego", secure_client_renego: "Client Renego",
    CRIME_TLS: "CRIME", BREACH: "BREACH", POODLE_SSL: "POODLE",
    fallback_SCSV: "TLS Fallback", SWEET32: "SWEET32", FREAK: "FREAK",
    DROWN: "DROWN", LOGJAM: "Logjam", BEAST: "BEAST", LUCKY13: "Lucky13",
    winshock: "Winshock", RC4: "RC4", opossum: "Opossum", GREASE: "GREASE",
  };
  const entries = Object.entries(vulns);

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
      {entries.map(([id, v]) => (
        <div
          key={id}
          className="flex items-center gap-2 p-2.5 rounded-lg"
          style={{
            background: v.vulnerable ? "#ef444412" : "#22c55e0a",
            border: `1px solid ${v.vulnerable ? "#ef444433" : "#22c55e22"}`,
          }}
        >
          {v.vulnerable ? (
            <XCircle size={16} style={{ color: "#ef4444", flexShrink: 0 }} />
          ) : (
            <CheckCircle2 size={16} style={{ color: "#22c55e", flexShrink: 0 }} />
          )}
          <div className="min-w-0">
            <span className="text-xs font-semibold block truncate" style={{ color: "var(--text-primary)" }}>
              {vulnNames[id] || id}
            </span>
            {v.cve && <span className="text-[10px]" style={{ color: "var(--text-muted)" }}>{v.cve}</span>}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Cipher Strength Bar ─────────────────────────────────── */
function CipherBar({ strength }: { strength: { strong: number; acceptable: number; weak: number; insecure: number } }) {
  const total = strength.strong + strength.acceptable + strength.weak + strength.insecure;
  if (total === 0) return <span className="text-sm text-muted">No ciphers detected</span>;

  const segments = [
    { label: "Strong", count: strength.strong, color: "#22c55e" },
    { label: "Acceptable", count: strength.acceptable, color: "#3b82f6" },
    { label: "Weak", count: strength.weak, color: "#eab308" },
    { label: "Insecure", count: strength.insecure, color: "#ef4444" },
  ];

  return (
    <div>
      <div className="flex rounded-lg overflow-hidden h-8 mb-3" style={{ background: "var(--bg-card)" }}>
        {segments.map((s) =>
          s.count > 0 ? (
            <div
              key={s.label}
              className="flex items-center justify-center text-[10px] font-bold text-white"
              style={{ width: `${(s.count / total) * 100}%`, background: s.color }}
              title={`${s.label}: ${s.count}`}
            >
              {s.count}
            </div>
          ) : null
        )}
      </div>
      <div className="flex gap-4">
        {segments.map((s) => (
          <div key={s.label} className="flex items-center gap-1.5 text-xs">
            <div className="w-2.5 h-2.5 rounded-sm" style={{ background: s.color }} />
            <span style={{ color: "var(--text-secondary)" }}>{s.label}</span>
            <span className="font-bold" style={{ color: "var(--text-primary)" }}>{s.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ─── Section Card ────────────────────────────────────────── */
function SectionCard({
  title,
  icon,
  children,
  defaultOpen = true,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="glass-card-static overflow-hidden">
      <button
        className="w-full flex items-center justify-between p-4 text-left"
        onClick={() => setOpen(!open)}
      >
        <div className="flex items-center gap-2">
          {icon}
          <h3 className="text-sm font-bold" style={{ color: "var(--text-primary)" }}>{title}</h3>
        </div>
        {open ? <ChevronUp size={16} style={{ color: "var(--text-muted)" }} /> : <ChevronDown size={16} style={{ color: "var(--text-muted)" }} />}
      </button>
      {open && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

/* ─── Findings Table ──────────────────────────────────────── */
function FindingsTable({ findings }: { findings: TLSFinding[] }) {
  const [search, setSearch] = useState("");
  const [sevFilter, setSevFilter] = useState("");
  const [sortField, setSortField] = useState<"severity" | "id">("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const filtered = useMemo(() => {
    let items = [...findings];
    if (search) {
      const q = search.toLowerCase();
      items = items.filter(
        (f) => f.id.toLowerCase().includes(q) || f.finding.toLowerCase().includes(q) || f.cve?.toLowerCase().includes(q)
      );
    }
    if (sevFilter) {
      items = items.filter((f) => f.severity === sevFilter);
    }
    items.sort((a, b) => {
      if (sortField === "severity") {
        const aIdx = SEV_ORDER.indexOf(a.severity);
        const bIdx = SEV_ORDER.indexOf(b.severity);
        return sortDir === "asc" ? aIdx - bIdx : bIdx - aIdx;
      }
      return sortDir === "asc" ? a.id.localeCompare(b.id) : b.id.localeCompare(a.id);
    });
    return items;
  }, [findings, search, sevFilter, sortField, sortDir]);

  return (
    <div>
      <div className="flex gap-2 mb-3">
        <div className="relative flex-1">
          <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2" style={{ color: "var(--text-muted)" }} />
          <input
            type="text"
            placeholder="Search findings…"
            className="w-full py-2 pl-8 pr-3 text-xs rounded-lg"
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-subtle)",
              color: "var(--text-primary)",
              outline: "none",
            }}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="py-2 px-3 text-xs rounded-lg"
          style={{
            background: "var(--bg-card)",
            border: "1px solid var(--border-subtle)",
            color: "var(--text-primary)",
            outline: "none",
          }}
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
        >
          <option value="">All Severities</option>
          {SEV_ORDER.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      <div className="overflow-x-auto max-h-[400px] overflow-y-auto rounded-lg" style={{ border: "1px solid var(--border-subtle)" }}>
        <table className="data-table text-xs">
          <thead>
            <tr>
              <th className="cursor-pointer" onClick={() => { setSortField("severity"); setSortDir(sortDir === "asc" ? "desc" : "asc"); }}>
                Severity {sortField === "severity" && (sortDir === "asc" ? "↑" : "↓")}
              </th>
              <th className="cursor-pointer" onClick={() => { setSortField("id"); setSortDir(sortDir === "asc" ? "desc" : "asc"); }}>
                ID {sortField === "id" && (sortDir === "asc" ? "↑" : "↓")}
              </th>
              <th>Finding</th>
              <th>CVE</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 200).map((f, i) => (
              <tr key={`${f.id}-${i}`}>
                <td>
                  <span
                    className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold"
                    style={{
                      background: `${SEV_COLORS[f.severity] || "#6b7280"}22`,
                      color: SEV_COLORS[f.severity] || "#6b7280",
                    }}
                  >
                    <SevIcon severity={f.severity} />
                    {f.severity}
                  </span>
                </td>
                <td className="font-mono text-[10px]">{f.id}</td>
                <td className="max-w-[400px]" style={{ color: "var(--text-primary)" }}>{f.finding}</td>
                <td>
                  {f.cve ? (
                    <a
                      href={`https://nvd.nist.gov/vuln/detail/${f.cve}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[10px] underline flex items-center gap-1"
                      style={{ color: "var(--accent)" }}
                    >
                      {f.cve} <ExternalLink size={10} />
                    </a>
                  ) : "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {filtered.length === 0 && (
          <div className="p-4 text-center text-xs" style={{ color: "var(--text-muted)" }}>No findings match your filter.</div>
        )}
      </div>
      <div className="mt-2 text-xs" style={{ color: "var(--text-muted)" }}>
        Showing {Math.min(filtered.length, 200)} of {filtered.length} findings
      </div>
    </div>
  );
}

/* ─── Header Section ──────────────────────────────────────── */
function HeadersChecklist({ headers }: { headers: TLSFinding[] }) {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
      {headers.map((h, i) => {
        const isGood = h.severity === "OK";
        const isBad = h.severity === "HIGH" || h.severity === "CRITICAL";
        return (
          <div
            key={`${h.id}-${i}`}
            className="flex items-center gap-2 p-2 rounded-lg"
            style={{
              background: isGood ? "#22c55e0a" : isBad ? "#ef444412" : "var(--bg-card)",
              border: `1px solid ${isGood ? "#22c55e22" : isBad ? "#ef444433" : "var(--border-subtle)"}`,
            }}
          >
            {isGood ? (
              <CheckCircle2 size={14} style={{ color: "#22c55e", flexShrink: 0 }} />
            ) : isBad ? (
              <XCircle size={14} style={{ color: "#ef4444", flexShrink: 0 }} />
            ) : (
              <Info size={14} style={{ color: "var(--text-muted)", flexShrink: 0 }} />
            )}
            <div className="min-w-0">
              <span className="text-xs font-semibold block truncate" style={{ color: "var(--text-primary)" }}>{h.id}</span>
              <span className="text-[10px] block truncate" style={{ color: "var(--text-muted)" }}>{h.finding}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Certificate Details ─────────────────────────────────── */
function CertDetails({ certs }: { certs: TLSFinding[] }) {
  const certMap: Record<string, string> = {};
  certs.forEach((c) => { certMap[c.id] = c.finding; });

  const fields = [
    { key: "cert_commonName", label: "Common Name" },
    { key: "cert_keySize", label: "Key Size" },
    { key: "cert_signatureAlgorithm", label: "Signature Algorithm" },
    { key: "cert_validFrom", label: "Valid From" },
    { key: "cert_validTo", label: "Valid To" },
    { key: "cert_caIssuers", label: "CA Issuer" },
    { key: "cert_chain_of_trust", label: "Chain of Trust" },
    { key: "cert_trust", label: "Trust" },
    { key: "OCSP_stapling", label: "OCSP Stapling" },
    { key: "CT_log", label: "CT Logging" },
    { key: "cert_subjectAltName", label: "Subject Alt Names" },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
      {fields.map((f) => {
        const val = certMap[f.key];
        if (!val) return null;
        return (
          <div key={f.key}>
            <span className="text-[10px] uppercase font-semibold" style={{ color: "var(--text-muted)" }}>{f.label}</span>
            <p className="text-xs font-medium mt-0.5" style={{ color: "var(--text-primary)" }}>{val}</p>
          </div>
        );
      })}
    </div>
  );
}

/* ─── Main Page ───────────────────────────────────────────── */
export default function TLSInspectionPage() {
  const params = useParams();
  const router = useRouter();
  const assetId = params.id as string;

  const { data, isLoading, isError } = useTestSSLResults(assetId);
  const { data: history } = useTestSSLHistory(assetId);

  if (isLoading) {
    return (
      <div className="animate-fade-in p-6 space-y-4">
        <Skeleton height={60} />
        {[...Array(6)].map((_, i) => <Skeleton key={i} height={120} />)}
      </div>
    );
  }

  if (isError || !data?.summary) {
    return (
      <div className="animate-fade-in p-6">
        <button
          className="flex items-center gap-2 text-sm mb-4"
          style={{ color: "var(--accent)" }}
          onClick={() => router.push("/assets")}
        >
          <ArrowLeft size={16} /> Back to Assets
        </button>
        <EmptyState message="No TLS inspection results found. Run a scan from the asset detail panel first." />
      </div>
    );
  }

  const summary: TLSInspectionSummary = data.summary;

  return (
    <div className="animate-fade-in space-y-5">
      {/* Back + Header */}
      <div>
        <button
          className="flex items-center gap-2 text-sm mb-3"
          style={{ color: "var(--accent)" }}
          onClick={() => router.push("/assets")}
        >
          <ArrowLeft size={16} /> Back to Assets
        </button>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-black" style={{ color: "var(--text-primary)" }}>
              TLS Security Inspection
            </h1>
            <p className="text-sm mt-1" style={{ color: "var(--text-muted)" }}>
              {data.hostname}:{data.port} &bull; Scanned {data.completed_at ? new Date(data.completed_at).toLocaleString() : "N/A"}
              &bull; {summary.total_findings} findings
            </p>
          </div>
          <GradeBadge grade={summary.grade} />
        </div>
      </div>

      {/* Severity Overview */}
      <SectionCard title="Severity Overview" icon={<Shield size={16} style={{ color: "var(--accent)" }} />}>
        <SeverityDonut counts={summary.severity_counts} />
      </SectionCard>

      {/* Protocol Support */}
      <SectionCard title="Protocol Support" icon={<Lock size={16} style={{ color: "var(--accent)" }} />}>
        <ProtocolMatrix protocols={summary.protocol_support} />
      </SectionCard>

      {/* Cipher Strength */}
      <SectionCard title="Cipher Strength" icon={<ShieldCheck size={16} style={{ color: "var(--accent)" }} />}>
        <CipherBar strength={summary.cipher_strength} />
      </SectionCard>

      {/* Vulnerability Scanner */}
      <SectionCard title="Vulnerability Assessment" icon={<ShieldAlert size={16} style={{ color: "var(--accent)" }} />}>
        <VulnGrid vulns={summary.vuln_status} />
      </SectionCard>

      {/* Certificate Details */}
      {summary.sections.certificates?.length > 0 && (
        <SectionCard title="Certificate Details" icon={<CheckCircle2 size={16} style={{ color: "var(--accent)" }} />}>
          <CertDetails certs={summary.sections.certificates} />
        </SectionCard>
      )}

      {/* HTTP Security Headers */}
      {summary.sections.headers?.length > 0 && (
        <SectionCard title="HTTP Security Headers" icon={<ShieldCheck size={16} style={{ color: "var(--accent)" }} />}>
          <HeadersChecklist headers={summary.sections.headers} />
        </SectionCard>
      )}

      {/* Forward Secrecy */}
      {summary.sections.forward_secrecy?.length > 0 && (
        <SectionCard
          title="Forward Secrecy"
          icon={<Lock size={16} style={{ color: "var(--accent)" }} />}
          defaultOpen={false}
        >
          <div className="space-y-1">
            {summary.sections.forward_secrecy.map((f, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <SevIcon severity={f.severity} />
                <span className="font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>{f.id}</span>
                <span style={{ color: "var(--text-primary)" }}>{f.finding}</span>
              </div>
            ))}
          </div>
        </SectionCard>
      )}

      {/* Server Preferences */}
      {summary.sections.server_preferences?.length > 0 && (
        <SectionCard
          title="Server Preferences"
          icon={<Info size={16} style={{ color: "var(--accent)" }} />}
          defaultOpen={false}
        >
          <div className="space-y-1">
            {summary.sections.server_preferences.map((f, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <SevIcon severity={f.severity} />
                <span className="font-mono text-[10px]" style={{ color: "var(--text-muted)" }}>{f.id}</span>
                <span style={{ color: "var(--text-primary)" }}>{f.finding}</span>
              </div>
            ))}
          </div>
        </SectionCard>
      )}

      {/* Full Findings Table */}
      <SectionCard
        title={`All Findings (${summary.total_findings})`}
        icon={<Search size={16} style={{ color: "var(--accent)" }} />}
        defaultOpen={false}
      >
        <FindingsTable findings={summary.all_findings} />
      </SectionCard>

      {/* Inspection History */}
      {history && history.length > 1 && (
        <SectionCard
          title="Inspection History"
          icon={<Info size={16} style={{ color: "var(--accent)" }} />}
          defaultOpen={false}
        >
          <div className="space-y-2">
            {history.map((h) => (
              <div
                key={h.inspection_id}
                className="flex items-center justify-between p-2 rounded-lg text-xs"
                style={{ background: "var(--bg-card)", border: "1px solid var(--border-subtle)" }}
              >
                <div className="flex items-center gap-2">
                  {h.grade && (
                    <span className="font-bold" style={{ color: GRADE_COLORS[h.grade] || "#6b7280" }}>{h.grade}</span>
                  )}
                  <span style={{ color: "var(--text-primary)" }}>
                    {h.started_at ? new Date(h.started_at).toLocaleDateString() : "—"}
                  </span>
                  <span style={{ color: "var(--text-muted)" }}>
                    {h.total_findings} findings
                  </span>
                </div>
                <span
                  className="px-2 py-0.5 rounded text-[10px] font-semibold"
                  style={{
                    background: h.status === "completed" ? "#22c55e22" : h.status === "failed" ? "#ef444422" : "#eab30822",
                    color: h.status === "completed" ? "#22c55e" : h.status === "failed" ? "#ef4444" : "#eab308",
                  }}
                >
                  {h.status}
                </span>
              </div>
            ))}
          </div>
        </SectionCard>
      )}
    </div>
  );
}
