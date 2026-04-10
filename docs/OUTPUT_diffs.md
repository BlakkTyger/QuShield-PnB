# OUTPUT Diffs — Expected vs Implemented

## Last Updated: 2026-04-10 12:45

This document compares every output specified in `02-OUTPUTS.md` against the current codebase implementation (through Phase 7). Items marked ❌ are missing; ✅ are implemented; ⚠️ are partially implemented; 🔮 are deferred by design (require internal access, AI, or agent-based deployment).

---

## Module 1 — External Attack Surface Discovery Engine

### 1.1 Asset Universe Map — ✅ Fully Implemented
All fields from `02-OUTPUTS.md` table are captured:

| Spec Field | Implementation | Status |
|---|---|---|
| Asset Name | `Asset.hostname` | ✅ |
| Asset Class | `Asset.asset_type` (auto-classified: web_server, internet_banking, upi_gateway, api_gateway, mail_server, dns_server, cdn_endpoint, vpn_gateway, swift_endpoint) | ✅ |
| Discovery Method | `Asset.discovery_method` (dns, portscan, httpx, tls, osint_fallback) | ✅ |
| IPv4 / IPv6 | `Asset.ip_v4`, `Asset.ip_v6` | ✅ |
| Hosting Entity | `Asset.hosting_provider` (detected via IP lookup + headers) | ✅ |
| Internet-Exposed | Implicit (all discovered assets are internet-exposed) | ✅ |
| TLS Termination Point | `Asset.cdn_detected`, `Asset.waf_detected` (Cloudflare, Akamai, Citrix NetScaler etc.) | ✅ |
| Last Verified | `Asset.last_seen_at` | ✅ |
| Confidence Score | `Asset.confidence_score` (0–1.0) | ✅ |

### 1.2 Third-Party & Supply Chain Crypto Exposure — ✅ Implemented
- `is_third_party` + `third_party_vendor` in Asset model
- Heuristic vendor detection for NPCI, SBI, HDFC, payment gateways, CBS vendors in `asset_manager.py`
- API: `GET /api/v1/assets/third-party` — lists all third-party endpoints with vendor names
- **⚠️ Gap**: Cannot map internal CBS vendor dependencies (Finacle/BaNCS/Flexcube) from external scanning alone — requires CMDB integration

### 1.3 Shadow Asset Detection — ✅ Implemented
- `is_shadow` flag with heuristic matching `dev|test|staging|uat|legacy|sandbox|demo|internal|debug|beta|alpha|preprod|qa|digi` patterns
- API: `GET /api/v1/assets/shadow`
- E2E Validated: PNB scan found `digigoldloan.pnb.bank.in` as shadow asset
- **⚠️ Gap**: No CMDB cross-reference (requires bank's internal asset inventory — out of scope for external POC)

---

## Module 2 — Deep Cryptographic Inventory (Full CBOM Engine)

### 2.1 Protocol-Level Cryptographic Inventory — ✅ Fully Implemented

| Spec Attribute | Implementation | Status |
|---|---|---|
| TLS Version | `Certificate.tls_version`, `fp["tls"]["versions_supported"]` | ✅ |
| Key Exchange Algorithm | `fp["tls"]["key_exchange"]` | ✅ |
| Authentication Algorithm | `Certificate.signature_algorithm` | ✅ |
| Symmetric Cipher | `fp["tls"]["negotiated_cipher"]` | ✅ |
| MAC/HMAC | Extracted from cipher suite name | ✅ |
| Certificate Public Key Type | `Certificate.key_type` | ✅ |
| Certificate Key Length | `Certificate.key_length` | ✅ |
| NIST Quantum Security Level | `Certificate.nist_quantum_level`, `CBOMComponent.nist_quantum_level` | ✅ |
| Hybrid Mode | Detected via PQC OID check + cipher name check | ✅ |
| Forward Secrecy | `Certificate.forward_secrecy`, `fp["tls"]["forward_secrecy"]` | ✅ |
| Certificate Transparency Logged | `Certificate.is_ct_logged` | ✅ |

### 2.2 Certificate Lifecycle Intelligence — ✅ Fully Implemented
- **✅ Quantum Vulnerability Date**: `Certificate.effective_security_expiry` — CRQC-adjusted using `compute_effective_security_expiry()`
- **✅ Chain of Trust**: Full CA chain parsed via `parse_certificate_chain()`
- **✅ CA PQC Readiness**: `Certificate.ca_pqc_ready` — lookup against known CA roadmap data
- **✅ Multi-SAN Exposure**: `Certificate.san_count`, `Certificate.san_list`

### 2.3 API Cryptographic Fingerprinting — ⚠️ Partial

| Spec Attribute | Implementation | Status |
|---|---|---|
| API Auth Mechanism | `Asset.auth_mechanisms` (JWT, Bearer, API-Key, OIDC, mTLS detected) | ✅ |
| JWT Signing Algorithm | `Asset.jwt_algorithm` — detects JWT presence; extracts `alg` header when possible | ⚠️ |
| Token Key Length | Inferred from JWT `alg` (RS256=RSA-2048, ES256=P-256) | ⚠️ |
| Transport Protocol | HTTPS detected; HTTP/2 via httpx probing | ✅ |
| PQC Readiness of Auth Layer | Computed from JWT algo + PQC OID detection | ✅ |
| Data-in-Transit Algorithm | Derived from TLS cipher suite | ✅ |
| Sensitive Data Indicator | ❌ Not implemented (requires API response body analysis, out of scope for passive scanning) | ❌ |

### 2.4 HSM & Key Management Inventory — 🔮 Deferred
Requires agent-based or API-connected deployment. Cannot be determined from external TLS scanning. Explicitly deferred in `06-DEVELOPMENT_PLAN.md`.

---

## Module 3 — Quantum Risk Scoring & Classification — ✅ Fully Implemented

### 3.1 Mosca's Theorem-Based Risk Model — ✅
- Migration Time (X): Per-asset via `data_shelf_life_defaults.json`
- Data Shelf Life (Y): Asset-type-specific defaults
- CRQC Arrival (Z): 3 scenarios (pessimistic=2029, median=2032, optimistic=2035)
- Quantum Risk Score: 0–1000 continuous, 5-factor weighted
- API: `POST /api/v1/risk/mosca/simulate`, `GET /api/v1/risk/asset/{id}`

### 3.2 Asset Classification — ✅

| Class | Score Range | Status |
|---|---|---|
| Quantum Critical | 800–1000 | ✅ |
| Quantum Vulnerable | 600–799 | ✅ |
| Quantum at Risk | 400–599 | ✅ |
| Quantum Aware | 200–399 | ✅ |
| Quantum Ready | 0–199 | ✅ |

### 3.3 TNFL Risk Flags — ✅
- SWIFT endpoint → CRITICAL
- JWT-signed API → MEDIUM
- PQC-signed → SAFE
- API: `GET /api/v1/risk/asset/{id}` returns `tnfl_risk` + `tnfl_severity`

---

## Module 4 — PQC Compliance Dashboard — ✅ Fully Implemented

### 4.1 Algorithm Compliance Matrix — ✅

| Spec Check | Implementation | API |
|---|---|---|
| FIPS 203 (ML-KEM) | `ComplianceResult.fips_203_deployed` | `/compliance/scan/{id}/fips-matrix` |
| FIPS 204 (ML-DSA) | `ComplianceResult.fips_204_deployed` | ✅ |
| FIPS 205 (SLH-DSA) | `ComplianceResult.fips_205_deployed` | ✅ |
| TLS 1.3 enforced | `ComplianceResult.tls_13_enforced` | ✅ |
| Forward Secrecy | `ComplianceResult.forward_secrecy` | ✅ |
| Hybrid KEM active | `ComplianceResult.hybrid_mode_active` | ✅ |
| RSA/ECC deprecated | `ComplianceResult.classical_deprecated` | ✅ |
| RBI Crypto Governance | `ComplianceResult.rbi_compliant` | ✅ |

### 4.2 Crypto-Agility Readiness Score — ✅
- 5-factor scoring (0–100): Dynamic cipher negotiation, automated cert renewal, key rotation, crypto abstraction layer, documented ownership
- API: `GET /api/v1/compliance/scan/{id}/agility`

### 4.3 Hybrid Deployment Tracker — ✅
- `hybrid_mode_active` flag per asset in compliance results
- FIPS matrix shows hybrid vs classical vs full-PQC per asset

---

## Module 5 — Banking-Specific Threat Intelligence Correlation

### 5.1 HNDL Exposure Window Calculator — ✅
- HNDL exposure per asset via `RiskScore.hndl_exposed`
- Mosca X (migration time) + Y (data shelf life) exposed via API
- API: `GET /api/v1/risk/scan/{id}/hndl` — exposed vs safe breakdown
- **⚠️ Gap**: Data Sensitivity Multiplier not yet weighted per data type (PAN/Aadhaar/SWIFT) — uses asset-type defaults

### 5.2 India-Specific Regulatory Compliance — ✅ Implemented (Phase 7 fix)

| Regulation | Spec Requirement | Implementation | Status |
|---|---|---|---|
| RBI IT Framework | Crypto controls documentation | `ComplianceResult.rbi_compliant` (TLS 1.2+, key >= 2048, FS) | ✅ |
| RBI Cyber Security | Vendor crypto risk | Third-party vendor detection + risk scoring | ✅ |
| SEBI CSCRF | Supply chain CBOM | `ComplianceResult.sebi_compliant` (CBOM exists) | ✅ |
| NPCI UPI Security | mTLS for UPI API | `ComplianceResult.npci_compliant` (mTLS detection on UPI endpoints) | ✅ |
| SWIFT CSP | PQC readiness | TNFL risk flagging for SWIFT endpoints | ✅ |
| PCI DSS 4.0 | TLS 1.2+ minimum | `ComplianceResult.pci_compliant` | ✅ |
| IT Act 2000 / DPDP | Data protection | Risk-mapped via quantum risk score | ⚠️ |

- API: `GET /api/v1/compliance/scan/{id}/regulatory`
- API: `GET /api/v1/compliance/deadlines` — regulatory deadline countdown data

### 5.3 Threat Actor Attribution — 🔮 Deferred
Requires threat intelligence feed integration. Out of scope for POC.

---

## Module 6 — Migration Intelligence Engine — ⚠️ Partial

- 6.1 Prioritized Migration Roadmap — ✅ Implemented (rule-based, `GET /api/v1/risk/scan/{id}/migration-plan`)
- 6.2 Developer Migration Playbooks — 🔮 (requires local LLM)
- 6.3 Vendor Readiness Tracker — ✅ Implemented (`GET /api/v1/compliance/vendor-readiness` with 12 vendors)

---

## Module 7 — Certificate Intelligence & Lifecycle Management — ✅ Mostly Implemented

| Feature | Implementation | Status |
|---|---|---|
| Post-Quantum Certificate Readiness | `Certificate.ca_pqc_ready` via CA lookup | ✅ |
| CRQC-Adjusted Effective Expiry | `Certificate.effective_security_expiry` | ✅ |
| Certificate Pinning Detector | `Certificate.is_pinned` via HPKP/Expect-CT header check | ✅ |
| CT Log Anomaly Detection | Requires CT log API monitoring (crt.sh integration) | 🔮 |

---

## Module 8 — Topology & Asset Relationship Graph — ✅ Implemented

| Feature | Implementation | Status |
|---|---|---|
| Shared Certificate Risk Propagation | `compute_blast_radius()` via NetworkX BFS | ✅ |
| Domain-IP-Cert-Issuer graph | NetworkX DiGraph with typed nodes and edges | ✅ |
| Trust Chain Visualization | Certificate → Issuer chain edges | ✅ |
| HSM Key Dependency Graph | Requires agent-based HSM discovery | 🔮 |

- API: `GET /api/v1/topology/scan/{id}`, `GET /api/v1/topology/scan/{id}/blast-radius`

---

## Module 9 — Enterprise Cyber Quantum Rating — ✅ Fully Implemented

- **✅** Per-asset quantum risk score (0–1000) with 5-factor weighted model
- **✅** Risk classification labels (Critical/Vulnerable/At-Risk/Aware/Ready)
- **✅** Aggregate organizational rating using 6-dimension weighted model:
  PQC Deployment (30%), HNDL Reduction (25%), Crypto-Agility (15%), Certificate Hygiene (10%), Regulatory Compliance (10%), Migration Velocity (10%)
- **✅** Organization-level labels (Quantum Critical/Vulnerable/Progressing/Ready/Elite)
- API: `GET /api/v1/risk/scan/{id}/enterprise-rating`
- PNB result: 167/1000 — Quantum Critical

---

## Module 10 — AI-Powered Capabilities — 🔮 Phase 9

- ❌ AI CBOM Analyst chat interface
- ❌ AI-Generated Migration Plans
- ❌ AI Anomaly Detection

---

## Module 11 — Reporting & Compliance Artifacts — ⚠️ Partial

| Feature | Implementation | Status |
|---|---|---|
| CycloneDX CBOM Export | `GET /api/v1/cbom/asset/{id}/export` | ✅ |
| Board-Level Quantum Risk Report | Requires PDF generation + AI summary | 🔮 Phase 9 |
| Scheduled Compliance Snapshots | Requires cron job / scheduler | 🔮 Phase 9 |
| Third-Party Audit Package | Data available via API; structured package not yet assembled | ⚠️ |

---

## Summary

| Module | Status | Coverage |
|---|---|---|
| 1. Discovery Engine | ✅ | 95% |
| 2. Deep Crypto Inventory | ✅ | 90% (HSM deferred) |
| 3. Quantum Risk Scoring | ✅ | 100% |
| 4. PQC Compliance Dashboard | ✅ | 100% |
| 5. Threat Intelligence | ✅ | 85% (threat actor attribution deferred) |
| 6. Migration Intelligence | ⚠️ | 50% (rule-based roadmap + vendor tracker done; playbooks Phase 9) |
| 7. Certificate Intelligence | ✅ | 90% (CT anomaly deferred) |
| 8. Topology Graph | ✅ | 90% (HSM graph deferred) |
| 9. Enterprise Quantum Rating | ✅ | 100% |
| 10. AI Capabilities | 🔮 | 0% (Phase 8+) |
| 11. Reporting Artifacts | ⚠️ | 40% (CBOM export done; reports Phase 9) |

### Additional Phase 7B Completions
- **✅** Scan Tier System: Quick (<1s), Shallow (30-90s), Deep (5-10min)
- **✅** JWT Authentication with user isolation
- **✅** Smart Scan Cache with tier hierarchy
- **✅** Incremental (delta) scanning
- **✅** GeoIP service with map endpoints
- **✅** Hybrid PQC TLS group detection
- **✅** TLS cipher suite decomposition
- **✅** HNDL data sensitivity multipliers
- **✅** Dynamic migration complexity scoring

### Remaining Actionable Items (Pre-Phase 8)
1. **Deep Scan streaming** — SSE/WebSocket progress streaming during long scans
2. **JWT algorithm deep parsing** — extract `alg` from JWT header more reliably
3. **HQC detection** — pre-populate NIST level mapping for HQC-128/192/256
4. **FN-DSA detection** — add FALCON/FN-DSA OIDs when FIPS 206 is published
5. **Monte Carlo CRQC simulation** — probability-weighted distribution endpoint
6. **Certificate expiry vs CRQC race** — new comparison endpoint
7. **AI features** — RAG chatbot, migration roadmap generation, report generation
