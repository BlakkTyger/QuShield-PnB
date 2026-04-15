"use client";

import { useState } from "react";
import {
  Zap,
  LayoutDashboard,
  Server,
  Shield,
  AlertTriangle,
  CheckCircle,
  Network,
  Globe,
  History,
  FileText,
  Bot,
  Activity,
  Scan,
  Lock,
  Cpu,
  BarChart3,
  ChevronDown,
  ChevronRight,
  ExternalLink,
  BookOpen,
  HelpCircle,
  PlayCircle,
} from "lucide-react";

interface FeatureCardProps {
  icon: React.ElementType;
  title: string;
  description: string;
  href: string;
}

function FeatureCard({ icon: Icon, title, description, href }: FeatureCardProps) {
  return (
    <a
      href={href}
      className="group block p-6 rounded-xl border transition-all duration-200 hover:shadow-lg"
      style={{
        background: "var(--bg-card)",
        borderColor: "var(--border-subtle)",
      }}
    >
      <div className="flex items-start gap-4">
        <div
          className="p-3 rounded-lg shrink-0 transition-colors"
          style={{ background: "var(--bg-tertiary)" }}
        >
          <Icon size={24} style={{ color: "var(--accent-primary)" }} />
        </div>
        <div className="flex-1 min-w-0">
          <h3
            className="font-semibold text-lg mb-2 group-hover:text-[var(--accent-primary)] transition-colors"
            style={{ color: "var(--text-primary)" }}
          >
            {title}
          </h3>
          <p style={{ color: "var(--text-secondary)" }} className="text-sm leading-relaxed">
            {description}
          </p>
        </div>
        <ExternalLink
          size={16}
          className="opacity-0 group-hover:opacity-100 transition-opacity shrink-0 mt-1"
          style={{ color: "var(--text-muted)" }}
        />
      </div>
    </a>
  );
}

interface AccordionItemProps {
  title: string;
  children: React.ReactNode;
  isOpen: boolean;
  onToggle: () => void;
}

function AccordionItem({ title, children, isOpen, onToggle }: AccordionItemProps) {
  return (
    <div
      className="rounded-xl overflow-hidden mb-4"
      style={{ border: "1px solid var(--border-subtle)" }}
    >
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between p-5 text-left transition-colors"
        style={{ background: "var(--bg-card)" }}
      >
        <span
          className="font-semibold text-lg"
          style={{ color: "var(--text-primary)" }}
        >
          {title}
        </span>
        {isOpen ? (
          <ChevronDown size={20} style={{ color: "var(--text-secondary)" }} />
        ) : (
          <ChevronRight size={20} style={{ color: "var(--text-secondary)" }} />
        )}
      </button>
      {isOpen && (
        <div
          className="p-5 text-sm leading-relaxed"
          style={{
            background: "var(--bg-secondary)",
            color: "var(--text-secondary)",
            borderTop: "1px solid var(--border-subtle)",
          }}
        >
          {children}
        </div>
      )}
    </div>
  );
}

const FEATURES = [
  {
    icon: Zap,
    title: "Quick Scan",
    description: "Instantly scan any domain to discover cryptographic assets and assess quantum vulnerability. Get immediate PQC scores and risk classification.",
    href: "/",
  },
  {
    icon: LayoutDashboard,
    title: "Dashboard",
    description: "Centralized view of your entire cryptographic posture. Monitor aggregate risk scores, asset inventory, and migration progress at a glance.",
    href: "/dashboard",
  },
  {
    icon: Server,
    title: "Assets",
    description: "Comprehensive asset inventory with deep TLS inspection. View certificate details, cipher suites, and protocol configurations for each endpoint.",
    href: "/assets",
  },
  {
    icon: Shield,
    title: "CBOM Explorer",
    description: "Cryptographic Bill of Materials - complete inventory of all cryptographic components across your infrastructure with NIST quantum security levels.",
    href: "/cbom",
  },
  {
    icon: AlertTriangle,
    title: "Risk Intelligence",
    description: "Advanced risk scoring based on Mosca's Theorem. Identify Harvest Now, Decrypt Later (HNDL) exposure and prioritize migration efforts.",
    href: "/risk",
  },
  {
    icon: Activity,
    title: "Monte Carlo Sim",
    description: "Probabilistic modeling of CRQC (Cryptographically Relevant Quantum Computer) arrival and its impact on your data shelf life.",
    href: "/risk/monte-carlo",
  },
  {
    icon: CheckCircle,
    title: "Compliance",
    description: "Track regulatory compliance against RBI IT Framework, SEBI CSCRF, PCI DSS 4.0, and IT Act 2000 requirements.",
    href: "/compliance",
  },
  {
    icon: Network,
    title: "Topology Map",
    description: "Visualize asset relationships and shared certificate dependencies. Understand blast radius of quantum-vulnerable components.",
    href: "/topology",
  },
  {
    icon: Globe,
    title: "GeoIP Map",
    description: "Geographic distribution of your cryptographic assets. Identify cross-border data flows and regional compliance considerations.",
    href: "/geo",
  },
  {
    icon: History,
    title: "Scan History",
    description: "Historical record of all scans with trend analysis. Track your PQC migration progress over time.",
    href: "/history",
  },
  {
    icon: FileText,
    title: "Reports",
    description: "Generate executive summaries, compliance reports, and detailed technical findings. Export to PDF, CSV, or CycloneDX CBOM format.",
    href: "/reports",
  },
  {
    icon: Bot,
    title: "AI Assistant",
    description: "RAG-powered chat interface for querying your CBOM data. Ask natural language questions about your quantum risk posture.",
    href: "/ai",
  },
];

const FAQS = [
  {
    title: "What is Post-Quantum Cryptography (PQC)?",
    content: (
      <>
        Post-Quantum Cryptography refers to cryptographic algorithms that are secure against attacks from both classical and quantum computers. With the anticipated arrival of Cryptographically Relevant Quantum Computers (CRQC), current RSA and ECC algorithms will become vulnerable. PQC algorithms like ML-KEM and ML-DSA, standardized by NIST, provide protection against quantum attacks.
      </>
    ),
  },
  {
    title: "What is Harvest Now, Decrypt Later (HNDL)?",
    content: (
      <>
        HNDL is an attack strategy where adversaries collect encrypted data today to decrypt it later when quantum computers become available. Even if your data is currently secure, any data transmitted using quantum-vulnerable algorithms is at risk if an adversary is storing it for future decryption. This is particularly critical for long-sensitive data like financial records, healthcare data, and state secrets.
      </>
    ),
  },
  {
    title: "How is the PQC Score calculated?",
    content: (
      <>
        The PQC Score (0-1000) is derived from multiple dimensions: PQC algorithm deployment (30%), HNDL exposure reduction (25%), crypto-agility readiness (15%), certificate hygiene (10%), regulatory compliance (10%), and migration velocity (10%). Assets are then classified into tiers: Quantum Critical, Quantum Vulnerable, Quantum Progressing, Quantum Ready, and Quantum Elite.
      </>
    ),
  },
  {
    title: "What is Mosca's Theorem?",
    content: (
      <>
        Mosca's Theorem states: <em>If X (migration time) + Y (data shelf life) &gt; Z (time to CRQC), then the data is at risk.</em> This mathematical model helps organizations prioritize migration efforts by considering how long data must remain confidential versus how quickly they can migrate to PQC.
      </>
    ),
  },
  {
    title: "How do I start my PQC migration?",
    content: (
      <>
        Start with a Quick Scan to establish your baseline. Review the Risk Intelligence dashboard to identify Quantum Critical assets. Use the CBOM Explorer to understand your cryptographic inventory. The AI Assistant can generate specific migration roadmaps for your infrastructure. Begin with Phase 0: disable deprecated protocols (TLS 1.0/1.1), then move to hybrid deployment (ML-KEM + classical), and finally full PQC.
      </>
    ),
  },
  {
    title: "What is a CBOM?",
    content: (
      <>
        CBOM (Cryptographic Bill of Materials) is a comprehensive inventory of all cryptographic components in your software and infrastructure. It catalogs algorithms, protocols, certificates, key lengths, and their NIST quantum security levels. QuShield generates CBOMs in CycloneDX 1.6 format, the international standard for cryptographic inventory.
      </>
    ),
  },
];

export default function AboutPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(0);

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="mb-10">
        <div className="flex items-center gap-3 mb-4">
          <div
            className="p-2 rounded-lg"
            style={{ background: "var(--accent-primary)" }}
          >
            <BookOpen size={24} style={{ color: "var(--text-primary)" }} />
          </div>
          <h1
            className="text-3xl font-bold"
            style={{ color: "var(--text-primary)" }}
          >
            About QuShield
          </h1>
        </div>
        <p
          className="text-lg leading-relaxed max-w-3xl"
          style={{ color: "var(--text-secondary)" }}
        >
          QuShield is a Post-Quantum Cryptographic Bill of Materials (CBOM) Scanner 
          designed for Indian Banking Infrastructure. Discover, inventory, and assess 
          quantum risk across your organization with actionable migration intelligence.
        </p>
      </div>

      {/* Quick Start */}
      <div
        className="rounded-2xl p-6 mb-10"
        style={{
          background: "linear-gradient(135deg, var(--bg-card) 0%, var(--bg-secondary) 100%)",
          border: "1px solid var(--border-subtle)",
        }}
      >
        <div className="flex items-center gap-3 mb-4">
          <PlayCircle size={24} style={{ color: "var(--accent-primary)" }} />
          <h2
            className="text-xl font-semibold"
            style={{ color: "var(--text-primary)" }}
          >
            Quick Start Guide
          </h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { step: "1", text: "Run a Quick Scan on your domain to discover assets" },
            { step: "2", text: "Review your PQC Score and Risk Classification" },
            { step: "3", text: "Explore CBOM and generate migration roadmap" },
          ].map((item) => (
            <div
              key={item.step}
              className="flex items-start gap-3 p-4 rounded-lg"
              style={{ background: "var(--bg-tertiary)" }}
            >
              <span
                className="w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm shrink-0"
                style={{
                  background: "var(--accent-primary)",
                  color: "var(--text-primary)",
                }}
              >
                {item.step}
              </span>
              <p style={{ color: "var(--text-secondary)" }} className="text-sm">
                {item.text}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* Features Grid */}
      <h2
        className="text-2xl font-bold mb-6 flex items-center gap-2"
        style={{ color: "var(--text-primary)" }}
      >
        <Scan size={24} style={{ color: "var(--accent-primary)" }} />
        Platform Features
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-12">
        {FEATURES.map((feature) => (
          <FeatureCard key={feature.title} {...feature} />
        ))}
      </div>

      {/* FAQ Section */}
      <h2
        className="text-2xl font-bold mb-6 flex items-center gap-2"
        style={{ color: "var(--text-primary)" }}
      >
        <HelpCircle size={24} style={{ color: "var(--accent-primary)" }} />
        Frequently Asked Questions
      </h2>
      <div className="mb-12">
        {FAQS.map((faq, index) => (
          <AccordionItem
            key={index}
            title={faq.title}
            isOpen={openFaq === index}
            onToggle={() => setOpenFaq(openFaq === index ? null : index)}
          >
            {faq.content}
          </AccordionItem>
        ))}
      </div>

      {/* Key Concepts */}
      <h2
        className="text-2xl font-bold mb-6 flex items-center gap-2"
        style={{ color: "var(--text-primary)" }}
      >
        <Lock size={24} style={{ color: "var(--accent-primary)" }} />
        Key Concepts
      </h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-12">
        {[
          {
            icon: Cpu,
            title: "ML-KEM (FIPS 203)",
            desc: "Module Lattice-based Key Encapsulation Mechanism - NIST standardized key exchange algorithm resistant to quantum attacks.",
          },
          {
            icon: Lock,
            title: "ML-DSA (FIPS 204)",
            desc: "Module Lattice-based Digital Signature Algorithm - NIST standardized digital signature scheme for post-quantum authentication.",
          },
          {
            icon: Shield,
            title: "Hybrid Mode",
            desc: "Combining classical (X25519) and post-quantum (ML-KEM) key exchange for transitional security during migration.",
          },
          {
            icon: BarChart3,
            title: "Crypto-Agility",
            desc: "The ability to rapidly switch cryptographic algorithms without rewriting application code - essential for future-proofing.",
          },
        ].map((concept) => (
          <div
            key={concept.title}
            className="p-5 rounded-xl"
            style={{
              background: "var(--bg-card)",
              border: "1px solid var(--border-subtle)",
            }}
          >
            <div className="flex items-center gap-3 mb-3">
              <concept.icon size={20} style={{ color: "var(--accent-primary)" }} />
              <h3
                className="font-semibold"
                style={{ color: "var(--text-primary)" }}
              >
                {concept.title}
              </h3>
            </div>
            <p className="text-sm" style={{ color: "var(--text-secondary)" }}>
              {concept.desc}
            </p>
          </div>
        ))}
      </div>

      {/* Footer */}
    </div>
  );
}
