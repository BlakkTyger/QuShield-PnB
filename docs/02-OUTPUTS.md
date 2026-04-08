# Platform Outputs

### Module 1 — External Attack Surface Discovery Engine

**What the original spec missed:** The original treats discovery as a passive enumeration exercise. In reality, discovery for banking infrastructure must cover the full EASM (External Attack Surface Management) scope, including shadow IT, third-party API integrations (payment gateways, NPCI, CBS vendors), and CDN/load balancer termination points where TLS is decrypted and re-encrypted (creating invisible cryptographic seams).

**Outputs this module must generate:**

**1.1 Asset Universe Map**

| Field | Detail |
|---|---|
| Asset Name | Canonical hostname/identifier |
| Asset Class | Internet Banking Portal / UPI Gateway / SWIFT Endpoint / API Gateway / Mobile Backend / CBS Interface / Third-Party Integration |
| Discovery Method | DNS enumeration / Certificate Transparency / ASN sweep / Shodan correlation / Passive BGP |
| IPv4 / IPv6 | Full dual-stack with geolocation |
| Hosting Entity | Bank-owned DC / AWS / Azure / Akamai / NIC / NPCI cloud |
| Internet-Exposed | Yes / No / Partial (behind WAF/CDN) |
| TLS Termination Point | Identified endpoint where quantum-vulnerable handshake occurs |
| Last Verified | Timestamp |
| Confidence Score | 0–100% (probabilistic discovery flagged separately) |

**1.2 Third-Party & Supply Chain Crypto Exposure**

Banks do not operate in isolation. A critical missing piece in the original spec: the platform must map cryptographic exposure through third-party connections — payment processors, fintech APIs, NPCI/UPI rails, CBS (Core Banking System) vendors (Finacle, BaNCS, Flexcube), and cloud-hosted middleware. Each third-party endpoint must be scanned for its own TLS configuration, and its risk must be attributed back to the bank that depends on it.

**1.3 Shadow Asset Detection**

Automated detection of externally-reachable assets not in the bank's official CMDB — development servers, test portals, legacy subdomains, abandoned microservices — that may use old, weak, or misconfigured TLS cipher suites.

---

### Module 2 — Deep Cryptographic Inventory (Full CBOM Engine)

This goes far beyond TLS certificate enumeration. A production-grade CBOM for a bank must cover:

**2.1 Protocol-Level Cryptographic Inventory**

For every discovered asset:

| Attribute | Values Captured |
|---|---|
| TLS Version | SSLv3 / TLS 1.0 / TLS 1.1 / TLS 1.2 / TLS 1.3 |
| Key Exchange Algorithm | RSA / DHE / ECDHE / ML-KEM (hybrid or pure) |
| Authentication Algorithm | RSA / ECDSA / ML-DSA / SLH-DSA |
| Symmetric Cipher | AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 / 3DES |
| MAC/HMAC | SHA-1 / SHA-256 / SHA-384 / POLY1305 |
| Certificate Public Key Type | RSA / EC / ML-KEM / ML-DSA |
| Certificate Key Length | e.g., RSA-2048, RSA-4096, P-256, P-384 |
| NIST Quantum Security Level | 0–6 (per CycloneDX 1.6 / IBM CBOM standard) |
| Hybrid Mode | Classical + PQC running simultaneously (Yes/No) |
| Forward Secrecy | Yes / No |
| Certificate Transparency Logged | Yes / No |

**2.2 Certificate Lifecycle Intelligence**

Beyond expiry dates, the platform must track:

- **Quantum Vulnerability Date:** Estimated date at which the certificate's key algorithm (RSA/ECC) becomes computationally breakable — modeled against CRQC arrival probability curves (Monte Carlo simulation using Mosca's Theorem)
- **Effective Security Remaining:** `min(cert_expiry, CRQC_arrival_estimate)` — the actual window of meaningful protection
- **Chain of Trust Depth:** Full CA chain analysis, flagging roots and intermediates that are themselves quantum-vulnerable
- **Certificate Authority PQC Readiness:** Whether the issuing CA (DigiCert, GlobalSign, Let's Encrypt, NPKI/NIC India) has committed to issuing PQC or hybrid certificates and on what timeline
- **Multi-SAN Exposure:** One certificate covering many subdomains — breach of the key = breach of all

**2.3 API Cryptographic Fingerprinting**

For each discovered API endpoint (REST/SOAP/GraphQL):

| Attribute | Captured |
|---|---|
| API Auth Mechanism | JWT / OAuth2 / mTLS / API Key / HMAC-signed request |
| JWT Signing Algorithm | HS256 / RS256 / ES256 / ML-DSA (PQC-ready) |
| Token Key Length | e.g., RSA-2048, EC P-256 |
| Transport Protocol | HTTPS / HTTP/2 / QUIC |
| PQC Readiness of Auth Layer | Yes / No / Hybrid |
| Data-in-Transit Algorithm | Derived from TLS scan |
| Sensitive Data Indicator | PAN / Aadhaar / Account Number / IFSC detected in schema |

**2.4 HSM & Key Management Inventory** *(for agent-based or API-connected deployments)*

HSM vendors are racing to add PQC support. Thales Luna firmware v7.9, released mid-2025, delivers native ML-KEM and ML-DSA support. Entrust nShield 5 firmware v13.8.0 provides native ML-DSA support, with ML-KEM added in v13.8.3. The platform must detect whether HSMs protecting banking keys are quantum-safe firmware versions or still running legacy cryptographic engines.

---

### Module 3 — Quantum Risk Scoring & Classification

**3.1 Mosca's Theorem–Based Risk Model**

The original spec uses a simple risk label (Critical/High/Medium/Low). This must be replaced with a mathematically-grounded model rooted in Mosca's Theorem: **if (migration time X) + (data shelf life Y) > (time to CRQC Z), the data is at risk.**

For each asset, the platform computes:

- **Migration Time (X):** Estimated time for this specific asset/system to be migrated to PQC, based on complexity scoring (number of dependent services, custom integrations, HSM vendor support status, CB vendor roadmap)
- **Data Shelf Life (Y):** How long the data transacted through this asset must remain confidential. For SWIFT messages → years; for OTP tokens → minutes; for core account data → decades
- **CRQC Arrival Estimate (Z):** Probability-weighted distribution (pessimistic/median/optimistic) drawn from Global Risk Institute quantum threat timeline models
- **Quantum Risk Score:** Continuous 0–1000 score. Assets where X+Y > Z (at even the pessimistic CRQC estimate) are **CRITICAL — HNDL exposure confirmed**

**3.2 Asset Classification (Refined from Original)**

| Class | Score | Meaning |
|---|---|---|
| Quantum Critical | 800–1000 | Currently being harvested; migration is an emergency |
| Quantum Vulnerable | 600–799 | Will be exposed before migration completes at current pace |
| Quantum at Risk | 400–599 | Safe only if CRQC timeline is at the optimistic end |
| Quantum Aware | 200–399 | Classical security adequate short-term; PQC migration planned |
| Quantum Ready | 0–199 | NIST PQC algorithms deployed; HNDL risk eliminated |

**3.3 "Trust Now, Forge Later" (TNFL) Risk Flags**

A separate risk category for digital signature integrity threats — specific to SWIFT message signing, UPI transaction authorization, software update signing, device certificate issuance. These assets get a TNFL flag indicating that quantum forgery, not just decryption, is the primary threat vector.

---

### Module 4 — PQC Compliance Dashboard

**4.1 Algorithm Compliance Matrix**

For each asset, a real-time compliance matrix against:

| Standard | Status |
|---|---|
| FIPS 203 (ML-KEM) deployed | ✅ / ❌ / ⚡ Hybrid |
| FIPS 204 (ML-DSA) deployed | ✅ / ❌ / ⚡ Hybrid |
| FIPS 205 (SLH-DSA) available | ✅ / ❌ |
| TLS 1.3 enforced | ✅ / ❌ |
| Forward Secrecy enabled | ✅ / ❌ |
| Hybrid KEM active (classical + ML-KEM) | ✅ / ❌ |
| RSA / ECC deprecated on this asset | ✅ / ❌ |
| NIST Quantum Security Level ≥ 3 | ✅ / ❌ |
| RBI Crypto Governance Documented | ✅ / ❌ |

**4.2 Crypto-Agility Readiness Score**

Hardcoded algorithms will slow migration. Systems must be designed to support swapping cryptographic components without rewriting application logic. The platform assesses each asset for crypto-agility:

- Is the cipher suite negotiated dynamically (TLS) or hardcoded?
- Is the certificate management automated (ACME/SCEP) or manual?
- Is key rotation automated or operator-triggered?
- Is there an abstraction layer (HSM API, crypto library version) that allows algorithm swap without application code changes?
- Is there a documented cryptographic owner and update SLA?

Crypto-Agility score: 0–100. Assets below 40 are flagged as **Migration-Blocked** even if their current algorithms are adequate.

**4.3 Hybrid Deployment Tracker**

NIST permits hybrid key exchange using schemes like ML-KEM + X25519, but it doesn't yet support hybrid signatures. Hybrid crypto is a bridge, not a destination — the goal remains full PQC adoption, but it helps reduce risk, preserve interoperability, and give implementers time to transition.

The dashboard tracks how many assets have moved to hybrid mode (Phase 1 of migration) versus still classical-only versus already full PQC.

---

### Module 5 — Banking-Specific Threat Intelligence Correlation

**5.1 HNDL Exposure Window Calculator**

For each asset, the platform visualises:

- The **HNDL Exposure Window** — the period during which data is being transmitted in quantum-vulnerable ciphertext and may be harvested
- The **Retroactive Decryption Risk Horizon** — looking backward, how far back in time could an adversary with a CRQC decrypt archived traffic from this asset
- **Data Sensitivity Multiplier** — applies a weight based on whether the asset transacts PAN data, Aadhaar numbers, SWIFT messages, or corporate treasury positions

**5.2 India-Specific Regulatory Compliance Tracker**

| Regulation | Requirement | Current Status | Gap |
|---|---|---|---|
| RBI IT Framework | Crypto controls documentation | Scanned | Computed gap |
| RBI Cyber Security Framework | Vendor crypto risk assessment | Scanned | Computed gap |
| SEBI CSCRF | Supply chain crypto inventory (CBOM) | Generated | Coverage % |
| NPCI UPI Security Guidelines | mTLS for UPI API | Detected | Pass/Fail |
| SWIFT CSP | PQC readiness acknowledged | Self-attested + verified | Status |
| PCI DSS 4.0 | TLS 1.2+ minimum, key mgmt | Scanned | Pass/Fail |
| IT Act 2000 / DPDP Act 2023 | Data protection via strong crypto | Risk-mapped | Findings |

**5.3 Threat Actor Attribution (Nation-State HNDL)**

Cross-reference discovered assets against public threat intelligence on known data-harvesting campaigns targeting Indian financial infrastructure (e.g., campaigns attributed to adversaries known to stockpile financial sector encrypted traffic). Flag assets that match the targeting profile of active HNDL collectors.

---

### Module 6 — Migration Intelligence Engine

**6.1 Prioritized Migration Roadmap (Auto-Generated)**

Not a generic checklist — a system-specific, sequenced migration plan generated from the scan data:

- **Phase 0 — Immediate (0–90 days):** Disable TLS 1.0/1.1 and all RC4/3DES cipher suites. Enforce TLS 1.3. Automate certificate renewal. Identify all RSA ≤ 2048 certificates for emergency replacement.
- **Phase 1 — Hybrid Deployment (90 days–18 months):** Deploy ML-KEM + X25519 hybrid TLS on all internet-facing endpoints. This eliminates HNDL risk for new sessions without breaking compatibility. Prioritize: payment gateways → internet banking portals → UPI API → SWIFT endpoints.
- **Phase 2 — Full PQC (18 months–36 months):** Replace classical key exchange entirely with ML-KEM. Migrate digital signatures (JWT signing, code signing, certificate issuance) to ML-DSA or SLH-DSA. Upgrade HSMs to PQC-capable firmware. Ensure CBS vendor (Finacle/BaNCS/Flexcube) has delivered PQC-compatible API.
- **Phase 3 — Verification & Certification (36+ months):** Achieve full CBOM coverage. Submit to third-party PQC audit. Obtain "PQC Ready" label for all Quantum Critical assets.

**6.2 Developer-Facing Technical Migration Playbooks**

Per-asset, per-technology-stack migration instructions:

- **OpenSSL 3.5.0** (now supports ML-KEM/ML-DSA): Exact config changes for nginx/Apache/HAProxy
- **Java (BouncyCastle / JCA):** Library upgrade paths and code samples for ML-KEM key exchange
- **Node.js / Python:** PQC library integration (liboqs, oqs-provider)
- **HSM Vendor:** Firmware upgrade checklist for Thales Luna / Entrust nShield / SafeNet
- **Certificate Authority:** Steps to request PQC or hybrid certificates from DigiCert, GlobalSign, or NIC India

**6.3 Vendor Readiness Tracker**

For every third-party product identified in the crypto inventory:

| Vendor/Product | PQC Roadmap Published | Target Version | Expected Date | Risk if Delayed |
|---|---|---|---|---|
| OpenSSL | ✅ 3.5.0 | 3.5.0+ | Available now | Low |
| Infosys Finacle | In progress | TBD | H2 2026 est. | HIGH — CBS core |
| IBM BaNCS | In progress | TBD | 2026 est. | HIGH — CBS core |
| Nginx | ✅ OpenSSL-based | Post 3.5.0 | 2025 | Medium |
| Thales Luna HSM | ✅ v7.9 released | v7.9+ | Available now | Low |

---

### Module 7 — Certificate Intelligence & Lifecycle Management

Beyond the original expiry tracking, the platform must add:

- **Post-Quantum Certificate Readiness:** Is the CA issuing PQC hybrid certs yet? If not, what is the bank's plan when the CA's own root becomes quantum-vulnerable?
- **CRQC-Adjusted Effective Expiry:** Every certificate shows not just its calendar expiry but its "effective security expiry" — the earlier of its calendar expiry and the estimated CRQC breach date for its key algorithm
- **Certificate Pinning Detector:** Banks with mobile apps that pin certificates face an additional migration barrier — pinned classical certificates cannot be silently replaced with PQC certs without app updates. These are flagged as **Pinning-Blocked migration assets**
- **CT Log Anomaly Detection:** Monitor Certificate Transparency logs for unauthorized certificate issuance against bank domains — a classical attack vector that becomes more dangerous once signature forgery is possible

---

### Module 8 — Topology & Asset Relationship Graph

**Enhanced from the original** with cryptographic-relationship edges:

- **Shared Certificate Risk Propagation:** If one certificate covers 40 subdomains and its key is quantum-vulnerable, the graph visualises the blast radius — how many assets are simultaneously compromised if that key is broken
- **Cipher Suite Dependency Graph:** Which backend services share the same TLS termination point / load balancer — changing cipher suites in one place affects all
- **HSM Key Dependency Graph:** Which certificates and services depend on keys stored in which HSM — maps the upgrade dependency chain
- **Trust Chain Visualization:** Full certificate chain from leaf → intermediate CA → root CA, with PQC-readiness colour-coding at every level

---

### Module 9 — Enterprise Cyber Quantum Rating

**Scoring Model (0–1000):**

| Dimension | Weight | Computed From |
|---|---|---|
| PQC Algorithm Deployment | 30% | % of critical assets using NIST PQC algorithms |
| HNDL Exposure Reduction | 25% | % of traffic protected by hybrid or full PQC KEM |
| Crypto-Agility Readiness | 15% | Average crypto-agility score across portfolio |
| Certificate Hygiene | 10% | Expiry management, key lengths, CT compliance |
| Regulatory Compliance | 10% | RBI/SEBI/PCI gap score |
| Migration Velocity | 10% | Rate of PQC adoption over rolling 90-day window |

**Labels:**
- **Quantum Critical** (<300): Immediate regulatory and HNDL risk. Board-level disclosure required.
- **Quantum Vulnerable** (300–550): Migration behind schedule vs. CRQC probability curve.
- **Quantum Progressing** (550–750): Hybrid deployment active; on track.
- **Quantum Ready** (750–900): Full PQC deployed on critical assets; classical deprecated.
- **Quantum Elite** (900–1000): Full PQC across all assets, crypto-agility documented, audit-ready.

---

### Module 10 — AI-Powered Capabilities

**10.1 AI CBOM Analyst (Chat Interface)**

A RAG-based chatbot grounded entirely on the bank's own scan data — not generic internet knowledge. Questions it must answer accurately:

- *"Which of our internet banking portals are using cipher suites that will be deprecated by NIST in 2035?"*
- *"How many of our certificates will expire before we can realistically complete PQC migration?"*
- *"What is our HNDL exposure window for our SWIFT messaging endpoint?"*
- *"Which of our third-party vendors have not yet published a PQC roadmap?"*
- *"Generate a board-level executive summary of our current quantum risk position."*

**10.2 AI-Generated Migration Plans** *(using local LLM inference as per original spec)*

Given a specific asset's full CBOM fingerprint (technology stack, hosting provider, TLS configuration, HSM vendor, dependent services), the local LLM generates a detailed, step-by-step migration plan including specific library versions, configuration file changes, testing protocol, rollback procedure, and expected performance impact of algorithm change.

**10.3 AI Anomaly Detection**

Detect cryptographic downgrade attacks — adversary-in-the-middle attempts to force a TLS session to negotiate a weaker cipher suite. ML model trained on the bank's normal cipher negotiation patterns; anomalies trigger real-time alerts.

---

### Module 11 — Reporting & Compliance Artifacts

**11.1 Regulatory-Ready CBOM Export**

Machine-readable CBOM in CycloneDX 1.6 format (the current international standard) — directly submittable to RBI auditors, SEBI inspections, or PCI QSA assessments. Includes the `nistQuantumSecurityLevel` field per asset, crypto-agility metadata, and migration status.

**11.2 Board-Level Quantum Risk Report**

A non-technical executive report quantifying:

- Total financial data at HNDL risk (transaction volume × data shelf life × CRQC probability)
- Estimated regulatory fine exposure if not migrated before DORA/RBI-equivalent deadlines
- Benchmark against peer banks (anonymized industry data where available)
- Board-approved migration budget recommendation

**11.3 Scheduled Compliance Snapshots**

Automated weekly CBOM snapshots that create an auditable cryptographic history — demonstrating to regulators that the bank is actively reducing quantum risk over time, not just generating a one-time report.

**11.4 Third-Party Audit Package**

A structured evidence package for external PQC audits — full CBOM, migration velocity metrics, vendor readiness confirmations, and Quantum Cyber Rating with supporting evidence, formatted for submission to RBI's Information Security Audit framework.

---

## Part IV — Key Problems the Original Specification Missed

**Problem 1 — No TNFL (Trust Now, Forge Later) Coverage:** Digital signature integrity — SWIFT, UPI authorization, code signing — is as urgent as confidentiality. The platform must assess both confidentiality and integrity quantum risk separately.

**Problem 2 — No Third-Party / Supply Chain Crypto Risk:** A bank's own endpoints may be upgraded, but if NPCI's UPI rail or a core banking vendor's API still runs RSA-2048, the bank inherits that risk. Supply chain crypto mapping is mandatory.

**Problem 3 — No Mosca's Theorem–Based Quantification:** Simple "High/Medium/Low" labels do not convey whether the HNDL window is open today or five years from now. Mathematical risk quantification against CRQC timelines is the difference between audit readiness and audit failure.

**Problem 4 — No Crypto-Agility Assessment:** Knowing what algorithms are deployed now is necessary but not sufficient. If replacing an algorithm requires rewriting three years of bespoke CBS integrations, the bank is blocked even if it knows what to do. Crypto-agility gaps are migration-blockers that must be surfaced.

**Problem 5 — No HSM Coverage:** HSMs are the cryptographic root of trust in every bank. If the HSM firmware doesn't support ML-KEM or ML-DSA, no amount of TLS configuration change matters — the key material itself is quantum-vulnerable. HSM PQC readiness must be a first-class output.

**Problem 6 — No Certificate Authority Readiness Tracking:** Banks depend on CAs to issue PQC certificates. If the CA (including NIC India for government-facing systems) has no published PQC roadmap, the bank cannot migrate even if it wants to. This dependency must be mapped and tracked.

**Problem 7 — No Regulatory Deadline Countdown:** Indian banks need to see their migration progress against explicit, named regulatory deadlines — not abstract risk levels. A countdown to RBI audit dates, SEBI CSCRF requirements, and PCI DSS 4.0 enforcement creates the urgency that drives executive action.

**Problem 8 — No Mobile App Crypto Coverage:** Mobile banking apps implement cryptography independently — JWT signing, local key storage, biometric binding, TLS certificate pinning. These are entirely absent from TLS surface scanning and require a separate CBOM methodology for APK/IPA analysis.

---