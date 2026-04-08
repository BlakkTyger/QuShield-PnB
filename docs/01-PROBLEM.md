
# Problem Statement Research

## Part I — The Real Threat Landscape (Research Synthesis)

### 1.1 Where the Cryptographic World Stands Today

NIST finalized its principal set of post-quantum encryption algorithms in August 2024, releasing three Federal Information Processing Standards — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) — and has urged system administrators to begin transitioning immediately. A fourth standard, FIPS 206 (FN-DSA, derived from FALCON), is in late-stage development. In March 2025, NIST selected HQC as a fifth algorithm to serve as a backup for ML-KEM, based on different mathematics, so that if a weakness is ever found in ML-KEM, an independent fallback exists.

These are not theoretical future standards — they are finalized, implementation-ready law for any organisation touching US federal systems or global financial infrastructure. The algorithms break down as follows:

- **ML-KEM (FIPS 203):** Replaces RSA and ECDH for key encapsulation/key exchange in TLS and APIs. Every time a browser establishes an HTTPS connection, it negotiates a session key; ML-KEM is what replaces the quantum-vulnerable step in that process. Key sizes are larger — approximately 800–1,500 bytes for public keys versus 32 bytes for a typical ECDH key — but performance is fast enough for real-time key exchange.
- **ML-DSA (FIPS 204):** Module-Lattice-Based Digital Signature Standard, used to detect unauthorised modifications to data and authenticate the identity of the signatory.
- **SLH-DSA (FIPS 205):** A stateless hash-based signature scheme that serves as a backup to ML-DSA based on a different mathematical approach.
- **HQC (backup KEM):** Based on different mathematics than ML-KEM, providing a second line of defense in case ML-KEM is found to be vulnerable; a draft standard is expected by 2027.

### 1.2 The HNDL Threat Is Not Theoretical — It Is Active

In HNDL attacks, adversaries capture and store encrypted data with the intention of decrypting it once cryptographically relevant quantum computers exist. Major cybersecurity agencies — the US Department of Homeland Security, UK NCSC, ENISA, and the Australian Cyber Security Centre — all base their official post-quantum guidance on the premise that adversaries are currently exfiltrating and storing sensitive, long-lived data.

Financial data recorded today — correspondent banking messages, settlement instructions, cardholder authentication flows — could be decrypted retroactively, enabling transaction forgery, identity theft, and account takeover.

There is also a second, underappreciated threat. Unlike HNDL, which targets confidentiality, "Trust Now, Forge Later" (TNFL) targets integrity. A future quantum adversary would not merely read past encrypted messages — it would forge digital signatures. A forged signature on a firmware update could compromise an entire fleet of payment terminals. A forged SWIFT message could redirect settlement funds. A forged certificate could create cloned cards that pass offline authentication.

### 1.3 The Banking Sector's Unique Exposure

A cryptographically relevant quantum computer could break the fundamental security protecting trillions of dollars in assets, leading to systemic risk, catastrophic investor losses, and a complete erosion of market confidence.

Hardware Security Modules (HSMs), which store and manage cryptographic keys, represent another vital use case for banks. They act as the digital vaults of banks and financial institutions, and if their encryption is broken, the breach could be catastrophic.

The Global Risk Institute's 2024 survey of 32 quantum computing experts places the probability of a cryptographically relevant quantum computer at 19–34% within 10 years and 60–82% by 2044. Algorithmic advances — particularly Gidney's 2025 improvements to quantum factoring — have meaningfully reduced theoretical CRQC resource estimates, with one analysis suggesting the timeline may have shifted approximately seven years closer.

### 1.4 Regulatory Pressure Is Accelerating — Including in India

Data protection and cybersecurity laws already require security measures that are "appropriate" to the "state of the art." In the EU, the Digital Operational Resilience Act (DORA) establishes specific obligations for managing ICT risk in the financial sector, while the NIS2 Directive does the same for critical infrastructure.

The SWIFT Customer Security Programme (CSP) is beginning to include guidance on PQC readiness. In a joint statement in 2024, the cyber agencies of 18 EU member states formally called for immediate action, recommending that all public and private organisations begin the transition to PQC, including migrations of PKI and systems manipulating sensitive information by end of 2030.

The RBI continues to strengthen expectations around vendor risk management, cryptographic controls, and system resilience. Regulators are already demanding proof of crypto-agility — the ability to rapidly swap out deprecated algorithms for quantum-safe alternatives. Without a robust CBOM, updating encryption across a massive enterprise is a blind, manual, and error-prone process.

The SEBI cybersecurity and cyber resilience framework requires regulated entities to manage software supply chain risk and maintain detailed software inventories for critical systems, creating pressure to understand embedded cryptography, certificate usage, and algorithm strength — which SBOMs alone cannot fully address. For banks and financial institutions in India, being able to demonstrate where cryptography is used, how strong it is, and how it is governed is becoming essential for audit readiness.

Singapore's MAS has issued advisory guidance recommending cryptographic asset inventories and migration strategies. The HKMA announced a Quantum Preparedness Index in February 2026 to score banking sector readiness. The UK NCSC set phased targets: crypto discovery by 2028, high-priority systems by 2031, and full transition by 2035.

### 1.5 What a CBOM Actually Is (and Why the Original Spec Falls Short)

You cannot transition to quantum-safe algorithms if you don't know what algorithms you're using today, and CBOM is designed to provide that knowledge. A US White House memorandum mandated federal agencies to inventory their cryptographic systems as part of a transition to post-quantum cryptography. NIST SP 1800-38B explicitly mentions CBOMs as having "the potential to enable organisations to manage and report usage of cryptography in a standardised way."

A CBOM alone cannot provide a full picture of an organisation's cryptographic posture. A comprehensive cryptographic inventory must extend beyond static software capabilities to capture every cryptographic asset and operation across the enterprise, including organisation-specific configurations, key provisioning, and update pipelines — not just built-in capabilities.

CBOM based on IBM's research has been integrated and upstreamed to the CycloneDX 1.6 specification. The property `nistQuantumSecurityLevel` defines the quantum security level of the crypto asset, with a value from 0 to 6 corresponding to the security strength categories defined by NIST for the PQC standardization process.

---

## Part II — Reframed & Upgraded Problem Statement

### 2.1 The Core Problem (Precision-Reframed)

Indian public sector banks (PNB, SBI, Bank of Baroda) and private banks (HDFC, ICICI, Axis) operate thousands of externally-facing digital surfaces — internet banking portals, UPI gateways, API bridges to NPCI/RBI, SWIFT messaging endpoints, mobile banking backends, and third-party fintech integrations. Every one of these surfaces currently relies on RSA, ECDH, ECDSA, and ECC — the entire family of public-key cryptosystems that a Cryptographically Relevant Quantum Computer (CRQC) will render cryptographically trivial.

The problem has three distinct dimensions that the original statement collapses into one:

**Dimension 1 — Cryptographic Blindness:** Banks do not have a real-time, machine-readable inventory of every algorithm, key length, certificate, protocol version, and cryptographic library in use across their external attack surface. Without this, no migration is possible.

**Dimension 2 — Active HNDL Exposure:** Nation-state adversaries are harvesting and archiving encrypted Indian banking traffic today. SWIFT messages, RTGS/NEFT transaction payloads, Aadhaar-linked authentication flows, and correspondent banking communications all carry data whose economic and strategic value extends years into the future — precisely the profile HNDL attacks target.

**Dimension 3 — Regulatory Non-Compliance Gap:** RBI, SEBI, and incoming international frameworks (DORA-equivalent mandates for Indian systemically important banks) will require demonstrable PQC readiness by 2030. Banks that have not begun discovery and inventory cannot demonstrate compliance, cannot plan migration timelines, and cannot quantify their quantum risk exposure to boards and regulators.

**QuShield-PnB must solve all three simultaneously**, not just perform surface-level TLS scanning.

---