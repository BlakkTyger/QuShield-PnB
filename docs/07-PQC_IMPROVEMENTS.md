# QuShield-PnB — PQC Improvements & Research Recommendations

## Last Updated: 2026-04-10

This document analyzes the current QuShield-PnB backend outputs, compares them against the latest PQC standards and industry developments (as of Q2 2026), and proposes concrete improvements categorized by priority and effort.

---

## Part I — Analysis of Current Outputs

### What QuShield-PnB Currently Detects (PNB Bank E2E Scan)

| Metric | Value | Interpretation |
|---|---|---|
| Total Assets | 96 | Comprehensive subdomain coverage via DNS + OSINT + port scan |
| Certificates | 4 unique | Shared certs across many subdomains (common for banks) |
| Quantum Vulnerable | 92/96 (96%) | Nearly all assets use classical-only crypto |
| Quantum Critical | 1 (mail.pnb.bank.in) | High data shelf life + no forward secrecy |
| Avg Risk Score | 763/1000 | Firmly in "Quantum Vulnerable" range |
| FIPS 203/204/205 Deployed | 0% | No PQC algorithms detected anywhere |
| TLS 1.3 Enforced | 0% | All assets negotiating TLS 1.2 or below in compliance checks |
| Forward Secrecy | 0% | Classical key exchange without ECDHE/DHE |
| RBI Compliant | 0% | Fails crypto governance requirements |
| PCI DSS Compliant | 0% | Below TLS 1.2+ threshold |
| Avg Crypto-Agility | 44/100 | Moderate — some cipher negotiation, but no automation |
| Shadow Assets | 1 | digigoldloan.pnb.bank.in |
| Third-Party (NPCI) | 2 | npciservices.pnb.bank.in, upi.pnb.bank.in |
| Enterprise Rating | ~116/1000 | "Quantum Critical" — zero PQC, 100% HNDL exposed |

### Key Observations

1. **PNB is entirely classical**: No ML-KEM, ML-DSA, or SLH-DSA detected on any endpoint. This is expected — Indian banks have not yet begun PQC deployment.
2. **TLS 1.3 adoption is uneven**: While assets respond on TLS 1.3 at the transport level, the compliance service was not detecting it correctly due to a data-passing bug (now fixed).
3. **Shared certificates create blast radius**: 4 certificates covering 96 subdomains means a single key compromise affects the entire bank.
4. **Crypto-agility is low**: Scores of 30–50 indicate hardcoded cipher configurations, manual cert management, and no documented cryptographic ownership.
5. **HNDL exposure is 100%**: Every single asset is currently subject to "Harvest Now, Decrypt Later" attacks.

---

## Part II — Latest PQC Standards Landscape (Q2 2026)

### NIST Finalized Standards

| Standard | Algorithm | Type | Status (April 2026) |
|---|---|---|---|
| **FIPS 203** | ML-KEM (Kyber) | Key Encapsulation Mechanism | Finalized Aug 2024 |
| **FIPS 204** | ML-DSA (Dilithium) | Digital Signature | Finalized Aug 2024 |
| **FIPS 205** | SLH-DSA (SPHINCS+) | Hash-based Digital Signature | Finalized Aug 2024 |
| **FIPS TBD** | FN-DSA (FALCON) | Lattice-based Signature | Draft expected H2 2026 |
| **FIPS TBD** | HQC | Code-based KEM (backup for ML-KEM) | Selected Mar 2025; draft ~2027 |

### Key Industry Developments

1. **OpenSSL 3.5.0** (Apr 2025): Native ML-KEM and ML-DSA support. Hybrid TLS 1.3 key exchange (X25519+ML-KEM-768) available out of the box. Nginx, Apache, HAProxy can use it with config changes.

2. **India National PQC Roadmap** (Feb 2026): India's Task Force under C-DOT published national roadmap:
   - Critical infrastructure (finance, defense, telecom) must implement PQC by **2027**
   - Full nationwide adoption by **2033**
   - 4-tier certification framework proposed
   - Emphasis on crypto-agility and vendor CBOMs
   - "Hybrid solutions" (PQC + QKD) recommended for high-assurance applications

3. **IETF TLS ML-KEM Draft** (draft-ietf-tls-mlkem-07): Standardizes ML-KEM key exchange in TLS 1.3. Hybrid groups X25519MLKEM768 and SecP256r1MLKEM768 defined.

4. **Java JEP 527**: Post-quantum hybrid key exchange in JDK TLS 1.3 (X25519MLKEM768, SecP256r1MLKEM768, SecP384r1MLKEM1024).

5. **HQC Selection**: NIST selected HQC (code-based KEM) as backup for ML-KEM, providing algorithm diversity against potential lattice-based attacks.

6. **HSM Readiness**: Thales Luna v7.9+ and Entrust nShield 5 v13.8+ now support ML-KEM/ML-DSA natively.

---

## Part III — Proposed Improvements

### A. Algorithm & Detection Improvements

#### A1. Detect Hybrid PQC Key Exchanges in TLS 1.3 ⭐ HIGH PRIORITY — ✅ DONE (Phase 7B.5)
**Problem**: Current scanner detects ML-KEM/ML-DSA OIDs but doesn't identify hybrid TLS groups (X25519MLKEM768, SecP256r1MLKEM768) which are the most likely first deployment step for banks.
**Solution**: Extended `detect_pqc()` with Layer 3 (shared ciphers scan) + Layer 4 (hybrid group decomposition).
- Named group map: X25519MLKEM768 (0x4588), SecP256r1MLKEM768 (0x4589), SecP384r1MLKEM1024 (0x4590), X25519Kyber768 (0x6399)
- Returns `hybrid_groups` with classical/PQC component breakdown and IANA IDs
**Status**: ✅ Implemented in `crypto_inspector.py` — Layer 3 + Layer 4 detection active

#### A2. HQC Detection (Backup KEM) ⭐ MEDIUM PRIORITY
**Problem**: NIST selected HQC (Mar 2025) as backup KEM. Current scanner has no HQC awareness.
**Solution**: Add HQC OIDs and cipher indicators to the quantum level mapping when HQC FIPS standard is drafted (~2027). Pre-populate the NIST level mapping now as Level 1/3/5 for HQC-128/192/256.
**Effort**: Low (config table update)
**Impact**: Medium — HQC won't appear in production for 2+ years, but being ready signals completeness

#### A3. FN-DSA (FALCON) Detection ⭐ MEDIUM PRIORITY
**Problem**: FN-DSA is the upcoming 4th signature standard (compact signatures, fast verification). Not yet in our detection.
**Solution**: Add FALCON/FN-DSA OIDs when draft is published (expected H2 2026). Useful for detecting early adopters.
**Effort**: Low (OID table + NIST level mapping)
**Impact**: Medium — early detection capability

#### A4. TLS 1.3 Cipher Suite Decomposition ⭐ HIGH PRIORITY — ✅ DONE (Phase 7B.6)
**Problem**: Current CBOM lists cipher suites as monolithic strings (e.g., "TLS_AES_256_GCM_SHA384"). The spec requires decomposed components.
**Solution**: Implemented `decompose_cipher_suite()` in `cbom_builder.py`:
- TLS 1.3 lookup table (5 suites) + TLS 1.2 lookup table (14 suites) + heuristic fallback
- Splits: key_exchange, authentication, symmetric, mac, tls_version
- Integrated into `build_cbom()` — each component includes `decomposition` field
**Status**: ✅ Fully implemented and integrated

#### A5. Certificate Transparency Log Monitoring ⭐ MEDIUM PRIORITY
**Problem**: `02-OUTPUTS.md` Module 7 specifies CT Log Anomaly Detection. Currently deferred.
**Solution**: Integrate crt.sh API to:
1. Fetch all certificates issued for the scanned domain
2. Compare against discovered certificates
3. Flag any certificates NOT found in our scan (unauthorized issuance)
4. Alert on certificates issued by unexpected CAs
```python
# Example: GET https://crt.sh/?q=%.pnb.bank.in&output=json
```
**Effort**: Medium (API integration + comparison logic)
**Impact**: High — detects MitM, rogue certs, unauthorized CA usage

---

### B. Scoring & Risk Model Improvements

#### B1. Data Sensitivity Multiplier for HNDL ⭐ HIGH PRIORITY — ✅ DONE (Phase 7B.7)
**Problem**: HNDL exposure window currently treats all assets equally.
**Solution**: Implemented `SENSITIVITY_MULTIPLIERS` in risk_engine.py: swift=5.0x, core_banking=3.5x, internet_banking=3.0x, web=1.0x, dns=0.5x.
`compute_hndl_window()` now accepts `asset_type`, returns `weighted_exposure`.
HNDL API endpoint returns per-asset sensitivity multiplier, sorted by criticality.
**Status**: ✅ Fully implemented + tested

#### B2. Monte Carlo CRQC Arrival Simulation ⭐ MEDIUM PRIORITY
**Problem**: Current Mosca implementation uses 3 discrete CRQC scenarios. The spec mentions "probability-weighted distribution" and "Monte Carlo simulation."
**Solution**: Add Monte Carlo simulation endpoint:
- Sample CRQC arrival year from log-normal distribution (mode=2032, σ=3)
- Run 10,000 simulations for each asset
- Output: probability of exposure at each year, expected year of first CRQC exposure
- Visualizable as a probability curve on the frontend
**Effort**: Medium (NumPy already available; need simulation logic + new API endpoint)
**Impact**: Medium — more sophisticated risk quantification for board-level reporting

#### B3. Migration Complexity Scoring ⭐ HIGH PRIORITY — ✅ DONE (Phase 7B.8)
**Problem**: Migration time (X in Mosca's theorem) is currently a static default per asset type.
**Solution**: Implemented `compute_migration_complexity()`: base time + penalties for low agility (+2yr), 3rd-party (+1yr), pinning (+1yr), no FS (+0.5yr), capped at 8yr. Migration-plan endpoint computes per-asset dynamic complexity.
**Status**: ✅ Fully implemented + tested

---

### C. New Features / Tabs

#### C1. Migration Readiness Dashboard ⭐ HIGH PRIORITY — ✅ DONE (Phase 7.9)
**Problem**: Module 6 (Migration Intelligence) was deferred to Phase 9 (AI), but a rule-based version was needed.
**Solution**: Implemented `GET /api/v1/risk/scan/{id}/migration-plan` — auto-generates a prioritized 4-phase migration roadmap from scan data.
- Phase 0 (0–90 days): Critical assets with weak crypto
- Phase 1 (90d–18mo): Hybrid ML-KEM deployment
- Phase 2 (18mo–36mo): Full PQC migration
- Phase 3 (36mo+): Verification
**Status**: ✅ Fully implemented + tested — PNB: 1 critical, 91 hybrid deploy, 22 blocked

#### C2. Certificate Expiry vs CRQC Race Visualization ⭐ MEDIUM PRIORITY
**Problem**: Spec mentions "how many certificates will expire before we can realistically complete PQC migration." This is not computed.
**Solution**: New endpoint that for each certificate computes:
- `cert_expiry_date` vs `estimated_pqc_migration_completion_date`
- Flag certs that will expire BEFORE migration completes (good — natural rotation opportunity)
- Flag certs that will NOT expire before CRQC arrival (bad — classical cert could be compromised while still valid)
**Effort**: Low (computed from existing cert + risk data)
**Impact**: Medium — useful for migration planning prioritization

#### C3. Vendor PQC Readiness Tracker (Dynamic) ⭐ MEDIUM PRIORITY
**Problem**: Current vendor data is static in `regulatory_deadlines.json`.
**Solution**: Expand with a `vendor_readiness.json` data file containing:
- OpenSSL, BouncyCastle, Nginx, Apache, HAProxy, Thales Luna, Entrust nShield, Infosys Finacle, TCS BaNCS, Oracle Flexcube
- For each: PQC roadmap status, target version, expected date, risk-if-delayed
- Endpoint: `GET /api/v1/compliance/vendor-readiness`
**Effort**: Low (static data + simple API endpoint)
**Impact**: Medium — valuable context for migration planning

#### C4. Regulatory Countdown Timer ⭐ LOW PRIORITY — ✅ DONE (Phase 7.9)
**Problem**: Spec Problem 7 calls for countdown to specific regulatory deadlines.
**Solution**: Enhanced `/api/v1/compliance/deadlines` includes `days_remaining`, `urgency_level` (critical/warning/info/overdue/ongoing), color-coded for frontend.
**Status**: ✅ Fully implemented

---

### D. Efficiency Improvements

#### D1. Parallel CBOM Generation ⭐ MEDIUM PRIORITY — ✅ DONE (Phase 7B.3)
**Problem**: CBOM generation was sequential per asset.
**Solution**: Parallelized CBOM generation with ThreadPoolExecutor (10 workers) in orchestrator.
**Status**: ✅ Implemented in `orchestrator.py`

#### D2. Incremental Scanning ⭐ HIGH PRIORITY — ✅ DONE (Phase 7B)
**Problem**: Every scan starts from scratch.
**Solution**: Implemented `incremental.py` with fingerprint_hash (sha256 of IP + TLS + cipher + cert). On new scan, compares with previous; clones unchanged data.
**Status**: ✅ Fully implemented + integrated in orchestrator

#### D3. Async Scan Orchestration ⭐ MEDIUM PRIORITY
**Problem**: Scan runs in a background thread. If the server restarts, the scan is lost.
**Solution**: Replace `threading.Thread` with `asyncio` task management or a simple task queue (Redis-backed). Store scan progress checkpoints in DB so interrupted scans can resume.
**Effort**: High (architectural change)
**Impact**: Medium — production reliability improvement

#### D4. Batch Certificate Chain Parsing ⭐ LOW PRIORITY
**Problem**: Certificate chains are parsed per-asset. Many PNB subdomains share the same chain.
**Solution**: Deduplicate by fingerprint before parsing. If cert fingerprint already parsed, reuse result.
**Effort**: Low (add fingerprint-keyed cache dict)
**Impact**: Low — small speedup, reduces redundant work

---

### E. Accuracy & Quality Improvements

#### E1. TLS 1.3 Enforcement Detection Fix ⭐ HIGH PRIORITY — ✅ DONE
**Status**: ✅ Fixed in Phase 7.8

#### E2. JWT Algorithm Deep Parsing ⭐ MEDIUM PRIORITY
**Problem**: `detect_api_auth()` detects JWT presence but doesn't always extract the `alg` header reliably.
**Solution**: When a JWT is detected in `Authorization: Bearer` or response headers:
1. Split by `.` to get header
2. Base64-decode the header
3. Extract `alg` field (HS256, RS256, ES256, PS256, EdDSA, ML-DSA-44, etc.)
4. Map `alg` to quantum vulnerability level
**Effort**: Low (JWT parsing is straightforward)
**Impact**: Medium — fills the Module 2.3 gap in API crypto fingerprinting

#### E3. Per-CBOM Component Quantum Level Accuracy ⭐ MEDIUM PRIORITY
**Problem**: Some CBOM components inherit NIST level from the cipher suite as a whole rather than being individually assessed.
**Solution**: Apply the NIST quantum level mapping individually:
- Symmetric AES-128 → Level 1, AES-256 → Level 5
- Hash SHA-256 → Level 1, SHA-384 → Level 3
- Key exchange ECDHE → Level 0 (quantum-vulnerable)
- Signature RSA → Level 0, ML-DSA-65 → Level 3
**Effort**: Low (refine existing mapping logic)
**Impact**: Medium — more granular CBOM, better aggregate stats

---

## Part IV — Prioritized Implementation Roadmap

### Immediate (This Sprint — Pre-Phase 8)
1. ✅ E1: TLS 1.3 enforcement detection fix (DONE)
2. ✅ B1: Data sensitivity multiplier for HNDL (DONE)
3. ✅ B3: Migration complexity scoring (DONE)
4. ✅ C4: Regulatory countdown timer enhancement (DONE)

### Short-Term (Phase 7B — COMPLETED)
5. ✅ A1: Hybrid PQC key exchange detection (DONE)
6. ✅ A4: TLS cipher suite decomposition (DONE)
7. ✅ C1: Migration readiness dashboard (DONE — rule-based)
8. E2: JWT algorithm deep parsing — **TODO**
9. ✅ D1: Parallel CBOM generation (DONE)

### Medium-Term (Phase 8 — NEXT)
10. A5: CT Log monitoring (crt.sh integration)
11. B2: Monte Carlo CRQC simulation — **TODO**
12. C2: Certificate expiry vs CRQC race — **TODO**
13. ✅ C3: Dynamic vendor readiness tracker (DONE)
14. ✅ D2: Incremental scanning (DONE)
15. E3: Per-component quantum level accuracy

### Long-Term (Production)
16. A2: HQC detection — **TODO** (pre-populate now)
17. A3: FN-DSA detection — **TODO** (pre-populate now)
18. D3: Async scan orchestration with checkpointing — **TODO (streaming)**

---

## Part V — References

1. NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
2. NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
3. NIST FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
4. NIST IR 8545 — HQC Selection: https://csrc.nist.gov/news/2025/hqc-announced-as-a-4th-round-selection
5. OpenSSL 3.5.0 PQC Support: https://openssl-foundation.org/post/2025-04-22-pqc/
6. India PQC National Roadmap (Feb 2026): https://thequantuminsider.com/2026/02/09/india-reveals-national-plan-for-quantum-safe-security/
7. IETF TLS ML-KEM Draft: https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/
8. Java JEP 527 (PQ Hybrid TLS): https://openjdk.org/jeps/527
9. NSA CNSA 2.0 Suite: https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF
10. Palo Alto PQC Standards Guide: https://www.paloaltonetworks.com/cyberpedia/pqc-standards
