"use client";

import { useState } from "react";
import {
  Award,
  AlertTriangle,
  Shield,
  Zap,
  CheckCircle,
  Clock,
  ArrowRight,
  Info,
  TrendingUp,
  AlertOctagon,
  Target,
  ChevronDown,
  ChevronRight,
} from "lucide-react";

interface TierCardProps {
  tier: string;
  scoreRange: string;
  color: string;
  bgColor: string;
  borderColor: string;
  icon: React.ElementType;
  description: string;
  characteristics: string[];
  actions: string[];
  isExpanded: boolean;
  onToggle: () => void;
}

function TierCard({
  tier,
  scoreRange,
  color,
  bgColor,
  borderColor,
  icon: Icon,
  description,
  characteristics,
  actions,
  isExpanded,
  onToggle,
}: TierCardProps) {
  return (
    <div
      className="rounded-xl overflow-hidden transition-all duration-300"
      style={{
        background: bgColor,
        border: `2px solid ${borderColor}`,
        boxShadow: isExpanded ? `0 8px 32px ${borderColor}40` : "none",
      }}
    >
      <button
        onClick={onToggle}
        className="w-full p-5 flex items-center justify-between text-left"
      >
        <div className="flex items-center gap-4">
          <div
            className="w-14 h-14 rounded-xl flex items-center justify-center shrink-0"
            style={{ background: color }}
          >
            <Icon size={28} className="text-black" />
          </div>
          <div>
            <div className="flex items-center gap-3 mb-1">
              <h3 className="text-xl font-bold text-white">{tier}</h3>
              <span
                className="px-3 py-1 rounded-full text-sm font-semibold"
                style={{ background: color, color: "#000" }}
              >
                {scoreRange}
              </span>
            </div>
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              {description}
            </p>
          </div>
        </div>
        {isExpanded ? (
          <ChevronDown size={24} style={{ color }} />
        ) : (
          <ChevronRight size={24} style={{ color }} />
        )}
      </button>

      {isExpanded && (
        <div
          className="px-5 pb-5"
          style={{ borderTop: `1px solid ${borderColor}` }}
        >
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-5">
            {/* Characteristics */}
            <div>
              <h4
                className="font-semibold mb-3 flex items-center gap-2"
                style={{ color }}
              >
                <Info size={16} />
                Key Characteristics
              </h4>
              <ul className="space-y-2">
                {characteristics.map((char, idx) => (
                  <li
                    key={idx}
                    className="flex items-start gap-2 text-sm"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    <span style={{ color }}>•</span>
                    {char}
                  </li>
                ))}
              </ul>
            </div>

            {/* Recommended Actions */}
            <div>
              <h4
                className="font-semibold mb-3 flex items-center gap-2"
                style={{ color }}
              >
                <Target size={16} />
                Recommended Actions
              </h4>
              <ul className="space-y-2">
                {actions.map((action, idx) => (
                  <li
                    key={idx}
                    className="flex items-start gap-2 text-sm"
                    style={{ color: "var(--text-secondary)" }}
                  >
                    <ArrowRight size={14} style={{ color }} className="mt-0.5" />
                    {action}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

interface ScoreDimensionProps {
  name: string;
  weight: string;
  description: string;
}

function ScoreDimension({ name, weight, description }: ScoreDimensionProps) {
  return (
    <div
      className="p-4 rounded-lg"
      style={{
        background: "var(--bg-card)",
        border: "1px solid var(--border-subtle)",
      }}
    >
      <div className="flex items-center justify-between mb-2">
        <span
          className="font-semibold"
          style={{ color: "var(--text-primary)" }}
        >
          {name}
        </span>
        <span
          className="px-2 py-1 rounded text-xs font-bold"
          style={{
            background: "var(--accent-primary)",
            color: "var(--text-primary)",
          }}
        >
          {weight}
        </span>
      </div>
      <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
        {description}
      </p>
    </div>
  );
}

const TIERS = [
  {
    tier: "Quantum Critical",
    scoreRange: "0–299",
    color: "#ef4444",
    bgColor: "rgba(239, 68, 68, 0.1)",
    borderColor: "rgba(239, 68, 68, 0.3)",
    icon: AlertOctagon,
    description: "Immediate regulatory and HNDL risk. Board-level disclosure required.",
    characteristics: [
      "Using deprecated TLS 1.0/1.1 or weak cipher suites",
      "RSA/ECC certificates with no PQC migration plan",
      "High-value data with long shelf life at risk",
      "No crypto-agility infrastructure in place",
      "Migration time + Data shelf life > CRQC arrival estimate",
    ],
    actions: [
      "Emergency board notification required",
      "Immediate disable TLS 1.0/1.1 and RC4/3DES",
      "Deploy hybrid ML-KEM + X25519 within 90 days",
      "Escalate to CISO and board risk committee",
      "Engage external PQC migration consultants",
      "Document incident response plan for quantum breach",
    ],
  },
  {
    tier: "Quantum Vulnerable",
    scoreRange: "300–550",
    color: "#f97316",
    bgColor: "rgba(249, 115, 22, 0.1)",
    borderColor: "rgba(249, 115, 22, 0.3)",
    icon: AlertTriangle,
    description: "Migration behind schedule vs. CRQC probability curve.",
    characteristics: [
      "TLS 1.2 deployed but no PQC algorithms active",
      "Certificate lifecycle management partially automated",
      "Some crypto-agility but limited to specific stacks",
      "Vendor roadmaps identified but not committed",
      "HNDL exposure window still open for sensitive data",
    ],
    actions: [
      "Accelerate PQC migration timeline immediately",
      "Prioritize hybrid deployment on all external-facing endpoints",
      "Negotiate binding PQC commitments with critical vendors",
      "Implement automated certificate lifecycle management",
      "Conduct quarterly PQC readiness reviews",
      "Update risk register with quantum threat scenarios",
    ],
  },
  {
    tier: "Quantum Progressing",
    scoreRange: "550–750",
    color: "#f59e0b",
    bgColor: "rgba(245, 158, 11, 0.1)",
    borderColor: "rgba(245, 158, 11, 0.3)",
    icon: TrendingUp,
    description: "Hybrid deployment active; migration on track.",
    characteristics: [
      "ML-KEM hybrid mode deployed on internet-facing assets",
      "Automated certificate management (ACME/SCEP) operational",
      "Crypto-agility infrastructure in place for major stacks",
      "Vendor PQC roadmaps committed and tracked",
      "Migration velocity positive over last 90 days",
    ],
    actions: [
      "Expand hybrid deployment to internal services",
      "Begin ML-DSA signature migration for critical workflows",
      "Document crypto-agility procedures and SLAs",
      "Conduct PQC penetration testing and validation",
      "Plan Phase 2: Full PQC (remove classical algorithms)",
      "Prepare regulatory compliance documentation",
    ],
  },
  {
    tier: "Quantum Ready",
    scoreRange: "750–900",
    color: "#22c55e",
    bgColor: "rgba(34, 197, 94, 0.1)",
    borderColor: "rgba(34, 197, 94, 0.3)",
    icon: Shield,
    description: "Full PQC deployed on critical assets; classical deprecated.",
    characteristics: [
      "ML-KEM and ML-DSA deployed across all critical assets",
      "Classical RSA/ECC key exchange deprecated",
      "Full crypto-agility with documented update procedures",
      "Automated key rotation and certificate management",
      "HNDL exposure window closed for all data classifications",
    ],
    actions: [
      "Complete PQC deployment on non-critical assets",
      "Obtain third-party PQC audit certification",
      "Implement continuous PQC compliance monitoring",
      "Maintain vendor PQC readiness tracking",
      "Update security policies to mandate PQC minimums",
      "Share best practices with industry working groups",
    ],
  },
  {
    tier: "Quantum Elite",
    scoreRange: "900–1000",
    color: "#10b981",
    bgColor: "rgba(16, 185, 129, 0.1)",
    borderColor: "rgba(16, 185, 129, 0.3)",
    icon: Award,
    description: "Full PQC across all assets, crypto-agility documented, audit-ready.",
    characteristics: [
      "100% PQC coverage - all assets using ML-KEM/ML-DSA",
      "Zero classical-only cryptography in production",
      "Industry-leading crypto-agility metrics",
      "Published PQC migration case studies",
      "Active contribution to PQC standards development",
    ],
    actions: [
      "Maintain Quantum Elite status through continuous monitoring",
      "Lead industry PQC working groups and standards bodies",
      "Publish quantum security research and best practices",
      "Provide PQC advisory services to partners",
      "Prepare for next-generation PQC algorithms (NIST Round 2+)",
      "Benchmark and optimize PQC performance continuously",
    ],
  },
];

const SCORE_DIMENSIONS = [
  {
    name: "PQC Algorithm Deployment",
    weight: "30%",
    description: "Percentage of critical assets using NIST PQC algorithms (ML-KEM, ML-DSA, SLH-DSA)",
  },
  {
    name: "HNDL Exposure Reduction",
    weight: "25%",
    description: "Percentage of traffic protected by hybrid or full PQC key encapsulation mechanisms",
  },
  {
    name: "Crypto-Agility Readiness",
    weight: "15%",
    description: "Average crypto-agility score across portfolio - ability to swap algorithms without code changes",
  },
  {
    name: "Certificate Hygiene",
    weight: "10%",
    description: "Expiry management, key lengths, Certificate Transparency compliance, CA trust chain health",
  },
  {
    name: "Regulatory Compliance",
    weight: "10%",
    description: "RBI IT Framework, SEBI CSCRF, PCI DSS 4.0, IT Act 2000, DPDP Act 2023 compliance scores",
  },
  {
    name: "Migration Velocity",
    weight: "10%",
    description: "Rate of PQC adoption over rolling 90-day window - trend analysis of migration progress",
  },
];

export default function TiersPage() {
  const [expandedTier, setExpandedTier] = useState<number | null>(0);
  const [showFormula, setShowFormula] = useState(false);

  return (
    <div className="max-w-5xl mx-auto">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <div
            className="p-2 rounded-lg"
            style={{ background: "var(--accent-primary)" }}
          >
            <Award size={24} style={{ color: "var(--text-primary)" }} />
          </div>
          <h1
            className="text-3xl font-bold"
            style={{ color: "var(--text-primary)" }}
          >
            PQC Tier Levels
          </h1>
        </div>
        <p
          className="text-lg leading-relaxed max-w-3xl"
          style={{ color: "var(--text-secondary)" }}
        >
          The Enterprise Cyber Quantum Rating classifies your organization&apos;s 
          post-quantum cryptography readiness into five tiers based on a 
          comprehensive 0–1000 scoring model.
        </p>
      </div>

      {/* Score Overview Card */}
      <div
        className="rounded-2xl p-6 mb-8"
        style={{
          background: "var(--bg-card)",
          border: "1px solid var(--border-subtle)",
        }}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Zap size={24} style={{ color: "var(--accent-primary)" }} />
            <h2
              className="text-xl font-semibold"
              style={{ color: "var(--text-primary)" }}
            >
              Understanding Your PQC Score
            </h2>
          </div>
          <button
            onClick={() => setShowFormula(!showFormula)}
            className="text-sm flex items-center gap-2 px-4 py-2 rounded-lg transition-colors"
            style={{
              background: "var(--bg-tertiary)",
              color: "var(--text-secondary)",
            }}
          >
            {showFormula ? "Hide Formula" : "Show Formula"}
            {showFormula ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          </button>
        </div>

        <div className="grid grid-cols-5 gap-2 mb-4">
          {[
            { label: "Critical", color: "#ef4444", range: "0-299" },
            { label: "Vulnerable", color: "#f97316", range: "300-550" },
            { label: "Progressing", color: "#f59e0b", range: "550-750" },
            { label: "Ready", color: "#22c55e", range: "750-900" },
            { label: "Elite", color: "#10b981", range: "900-1000" },
          ].map((item) => (
            <div key={item.label} className="text-center">
              <div
                className="h-3 rounded-full mb-2"
                style={{ background: item.color }}
              />
              <span
                className="text-xs font-semibold block"
                style={{ color: item.color }}
              >
                {item.label}
              </span>
              <span className="text-xs" style={{ color: "var(--text-muted)" }}>
                {item.range}
              </span>
            </div>
          ))}
        </div>

        {showFormula && (
          <div
            className="mt-4 p-4 rounded-xl"
            style={{
              background: "var(--bg-secondary)",
              border: "1px solid var(--border-subtle)",
            }}
          >
            <h3
              className="font-semibold mb-3 flex items-center gap-2"
              style={{ color: "var(--text-primary)" }}
            >
              <Clock size={18} />
              Mosca&apos;s Theorem
            </h3>
            <p className="text-sm mb-4" style={{ color: "var(--text-secondary)" }}>
              The risk scoring is grounded in Mosca&apos;s Theorem:
            </p>
            <div
              className="p-4 rounded-lg font-mono text-center mb-4"
              style={{
                background: "var(--bg-tertiary)",
                color: "var(--accent-primary)",
              }}
            >
              If X (migration time) + Y (data shelf life) &gt; Z (time to CRQC)
              <br />
              → <strong>Data is at risk</strong>
            </div>
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Where X is estimated from crypto-agility scores, Y is determined by 
              data classification, and Z is modeled using Global Risk Institute 
              quantum threat timeline probabilities.
            </p>
          </div>
        )}
      </div>

      {/* Score Dimensions */}
      <h2
        className="text-xl font-bold mb-4 flex items-center gap-2"
        style={{ color: "var(--text-primary)" }}
      >
        <CheckCircle size={20} style={{ color: "var(--accent-primary)" }} />
        Scoring Dimensions
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-10">
        {SCORE_DIMENSIONS.map((dim) => (
          <ScoreDimension key={dim.name} {...dim} />
        ))}
      </div>

      {/* Tier Cards */}
      <h2
        className="text-xl font-bold mb-4 flex items-center gap-2"
        style={{ color: "var(--text-primary)" }}
      >
        <Shield size={20} style={{ color: "var(--accent-primary)" }} />
        Tier Classifications
      </h2>
      <div className="space-y-4">
        {TIERS.map((tier, index) => (
          <TierCard
            key={tier.tier}
            {...tier}
            isExpanded={expandedTier === index}
            onToggle={() =>
              setExpandedTier(expandedTier === index ? null : index)
            }
          />
        ))}
      </div>

      {/* Footer Note */}
      <div
        className="mt-8 p-4 rounded-xl"
        style={{
          background: "var(--bg-secondary)",
          border: "1px solid var(--border-subtle)",
        }}
      >
        <div className="flex items-start gap-3">
          <Info
            size={20}
            className="shrink-0 mt-0.5"
            style={{ color: "var(--accent-primary)" }}
          />
          <div>
            <h4
              className="font-semibold mb-1"
              style={{ color: "var(--text-primary)" }}
            >
              Regulatory Note
            </h4>
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              Under RBI IT Framework 2023 and anticipated DORA-equivalent regulations 
              for Indian banks, organizations in the Quantum Critical tier may face 
              regulatory scrutiny. Board-level disclosure of quantum risk is recommended 
              for all tiers below Quantum Ready.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
