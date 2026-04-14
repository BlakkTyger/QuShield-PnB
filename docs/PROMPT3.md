# Phase 9 — Comprehensive Backend Testing & Verification Loop (PROMPT3.md)

> **Generated**: 2026-04-10
> **Status**: 🔧 IN PROGRESS
> **Predecessor**: Phase 8 (AI Features — ✅ COMPLETE)
> **Target Domain**: `https://pnb.bank.in`

---

## Overview

Phase 9 is a verification-only phase. No new features are built; we close the last Phase 8 items (H.6.4–H.7.4), then run exhaustive E2E tests against every backend feature documented in `02-OUTPUTS.md`, `04-SYSTEM_ARCHITECTURE.md`, and the PLAN directory. Every result is logged to `TESTING_RESULTS.md`.

---

## Track 0: Finalize Phase 8 Unchecked Items

### 0.1 — API Completion
- [x] **0.1.1** — `PATCH /api/v1/ai/settings` — update `deployment_mode`, `ai_tier`, `cloud_api_keys` *(H.6.4 — already in `ai.py:145`)*
- [x] **0.1.2** — `GET /api/v1/ai/models` — list models by deployment_mode + tier *(H.6.5 — already in `ai.py:164`)*
- [x] **0.1.3** — DEV_LOG entry for H.6.4–H.6.5 *(H.6.6)*

### 0.2 — Documentation Updates
- [x] **0.2.1** — `03-FRONTEND.md`: AI chat page, report builder, tier selection UI *(H.7.1)*
- [x] **0.2.2** — `04-SYSTEM_ARCHITECTURE.md`: AI service architecture, provider abstraction, vector store *(H.7.2)*
- [x] **0.2.3** — `06-DEVELOPMENT_PLAN.md`: Phase 8 AI milestones *(H.7.3)*
- [x] **0.2.4** — `06g-PLAN_P9.md`: Revised with verification plan *(H.7.4)*

### 0.3 — Bug Fixes Before Testing
- [x] **0.3.1** — Fix `report_generator.py`: wrong model attributes (`quantum_readiness_level`→`risk_classification`, `base_score`→`quantum_risk_score`, `ip_address`→`ip_v4`, `mitigation_recommendation` removed)
- [x] **0.3.2** — Mark all H.6.x/H.7.x items complete in `PROMPT2.md`

---

## Track 1: Authentication & Security (Module: Auth)

### 1.1 — User Registration & Login
- [x] **1.1.1** — `POST /api/v1/auth/register` — create user, verify 200 + user ID returned
- [x] **1.1.2** — `POST /api/v1/auth/login` — verify JWT access_token + refresh_token returned
- [x] **1.1.3** — `GET /api/v1/auth/me` — verify user profile with valid Bearer token
- [x] **1.1.4** — Reject login with wrong password (401)
- [x] **1.1.5** — Reject protected endpoints without Bearer (401)

### 1.2 — Tenant Isolation
- [ ] **1.2.1** — Create User A and User B
- [ ] **1.2.2** — User A creates a scan → scan.user_id == A
- [ ] **1.2.3** — User B cannot access User A's scan via `GET /api/v1/scans/{id}` (404)
- [ ] **1.2.4** — `GET /api/v1/scans/` (list) only returns current user's scans

### 1.3 — AI Settings Management
- [x] **1.3.1** — `PATCH /api/v1/ai/settings` — change `deployment_mode` to `cloud`
- [x] **1.3.2** — `GET /api/v1/ai/models` — verify model list changes with tier
- [x] **1.3.3** — `GET /api/v1/ai/status` — verify deployment mode + tier reported

---

## Track 2: External Attack Surface Discovery (Module 1)

### 2.1 — Deep Scan Discovery (pnb.bank.in)
- [x] **2.1.1** — `POST /api/v1/scans/` with `{"targets": ["pnb.bank.in"]}` — returns scan_id
- [x] **2.1.2** — Scan enters "running" status → poll `GET /api/v1/scans/{id}` until "completed"
- [x] **2.1.3** — Verify `total_assets > 0` in scan summary
- [x] **2.1.4** — Verify at least 5 unique subdomains discovered
- [x] **2.1.5** — Verify IP resolution (ip_v4 populated) for discovered assets

### 2.2 — Asset Classification & Shadow Detection
- [x] **2.2.1** — `GET /api/v1/assets/?scan_id={id}` — paginated list
- [x] **2.2.2** — Verify `asset_type` is set (web_server/api/mail_server/etc.)
- [x] **2.2.3** — Verify `is_shadow` flag is populated (some true, most false)
- [x] **2.2.4** — Verify `is_third_party` flag is populated
- [x] **2.2.5** — Verify `hosting_provider` and `cdn_detected` fields populated
- [x] **2.2.6** — `GET /api/v1/assets/{id}` — single asset detail with ports, certs, risk

### 2.3 — Quick Scan
- [x] **2.3.1** — `POST /api/v1/scans/quick` with `{"domain": "pnb.bank.in"}` — returns <8s
- [x] **2.3.2** — Verify TLS version, cipher, cert info, risk score in response
- [x] **2.3.3** — Verify NIST quantum level assignment

### 2.4 — Shallow Scan
- [x] **2.4.1** — `POST /api/v1/scans/shallow` with `{"domain": "pnb.bank.in"}` — returns <90s
- [x] **2.4.2** — Verify discovered subdomains (>1)
- [ ] **2.4.3** — Verify TLS data for top-N subdomains

---

## Track 3: Deep Cryptographic Inventory (Module 2)

### 3.1 — TLS Protocol Analysis
- [ ] **3.1.1** — Verify negotiated TLS version per asset (TLS 1.2 or 1.3)
- [ ] **3.1.2** — Verify negotiated cipher suite name is populated
- [ ] **3.1.3** — Verify `forward_secrecy` boolean per asset
- [ ] **3.1.4** — Verify `key_exchange` algorithm extracted (ECDHE/DHE/RSA)

### 3.2 — Certificate Chain Parsing
- [x] **3.2.1** — `GET /api/v1/assets/{id}` — certificates array populated
- [x] **3.2.2** — Verify leaf cert: subject, issuer, not_after, key_type, key_length
- [ ] **3.2.3** — Verify chain depth ≥ 1 (leaf + intermediate)
- [x] **3.2.4** — Verify `signature_algorithm` extracted (e.g., RSA-SHA256)

### 3.3 — NIST Quantum Level Assignment
- [x] **3.3.1** — RSA-2048 → NIST Level 0 (quantum_vulnerable=true)
- [x] **3.3.2** — ECDHE-RSA → NIST Level 0 (quantum_vulnerable=true)
- [x] **3.3.3** — AES-256-GCM → NIST Level 5 (quantum_vulnerable=false)
- [x] **3.3.4** — ML-KEM-768 → NIST Level 3 (quantum_vulnerable=false)
- [x] **3.3.5** — FN-DSA-512 → NIST Level 1 (status=pqc_draft)
- [x] **3.3.6** — HQC-128 → NIST Level 1 (status=pqc_draft)
- [x] **3.3.7** — X25519MLKEM768 → NIST Level 3 (status=hybrid)

### 3.4 — PQC Detection
- [x] **3.4.1** — Run `detect_pqc("pnb.bank.in")` — expect `pqc_key_exchange=False` (classical bank)
- [x] **3.4.2** — Verify 4-layer detection: OID check → cipher name → shared ciphers → hybrid groups
- [x] **3.4.3** — Verify hybrid group decomposition returns classical/PQC components

### 3.5 — JWT Algorithm Deep Parsing
- [ ] **3.5.1** — Verify `parse_jwt_algorithm()` extracts `alg` from token header
- [ ] **3.5.2** — Verify JWT quantum mapping: RS256→vulnerable, ES256→vulnerable, ML-DSA→safe
- [ ] **3.5.3** — Verify `jwt_algorithm` field populated on assets where JWT detected

### 3.6 — Cipher Suite Decomposition
- [x] **3.6.1** — `decompose_cipher_suite("TLS_AES_256_GCM_SHA384")` returns kex, auth, enc, mac
- [x] **3.6.2** — `decompose_cipher_suite("ECDHE-RSA-AES128-GCM-SHA256")` returns components
- [ ] **3.6.3** — CBOM components include `decomposition` metadata field

---

## Track 4: CBOM & CycloneDX (Module 2 + 11)

### 4.1 — Per-Asset CBOM Generation
- [x] **4.1.1** — `GET /api/v1/cbom/scan/{id}` — list CBOMs for scan, count > 0
- [x] **4.1.2** — `GET /api/v1/cbom/asset/{id}` — components array populated
- [x] **4.1.3** — Each component has: name, component_type, nist_quantum_level, is_quantum_vulnerable
- [x] **4.1.4** — `quantum_ready_pct` computed correctly per asset

### 4.2 — CycloneDX Export
- [x] **4.2.1** — `GET /api/v1/cbom/asset/{id}/export` — returns valid JSON
- [x] **4.2.2** — JSON has `specVersion: "1.6"`, `bomFormat: "CycloneDX"` fields
- [ ] **4.2.3** — JSON has `components[]` array with `nistQuantumSecurityLevel`

### 4.3 — Aggregate CBOM
- [x] **4.3.1** — `GET /api/v1/cbom/scan/{id}/aggregate` — enterprise CBOM
- [x] **4.3.2** — `GET /api/v1/cbom/scan/{id}/algorithms` — algo breakdown *(endpoint is `/algorithms` not `/algorithm-distribution`)*

---

## Track 5: Quantum Risk Scoring (Module 3)

### 5.1 — Mosca's Inequality
- [x] **5.1.1** — `POST /api/v1/risk/mosca/simulate` — verify X+Y > Z logic
- [x] **5.1.2** — Test: X=2, Y=5, Z(pessimistic)=3 → exposed=True
- [x] **5.1.3** — Test: X=0.5, Y=0.5, Z(pessimistic)=3 → exposed=False

### 5.2 — Per-Asset Risk Scores
- [x] **5.2.1** — `GET /api/v1/risk/scan/{id}` — risk scores for all assets
- [x] **5.2.2** — `quantum_risk_score` in 0–1000 range, no nulls
- [x] **5.2.3** — `risk_classification` is one of: quantum_critical, quantum_vulnerable, quantum_at_risk, quantum_aware, quantum_ready
- [x] **5.2.4** — `mosca_x`, `mosca_y` populated (non-null floats)
- [x] **5.2.5** — `hndl_exposed` boolean populated
- [x] **5.2.6** — `tnfl_risk` boolean populated for signature-related assets

### 5.3 — Risk Heatmap & Detail
- [x] **5.3.1** — `GET /api/v1/risk/scan/{id}/heatmap` — classification distribution
- [x] **5.3.2** — `GET /api/v1/risk/asset/{id}` — detailed factors breakdown
- [x] **5.3.3** — Each risk factor has name, score, weight, rationale

### 5.4 — HNDL Exposure
- [x] **5.4.1** — `GET /api/v1/risk/scan/{id}/hndl` — exposed vs safe
- [x] **5.4.2** — `sensitivity_multiplier` applied per asset_type
- [x] **5.4.3** — `weighted_exposure` computed and sorted descending

### 5.5 — Monte Carlo Simulation
- [x] **5.5.1** — `POST /api/v1/risk/monte-carlo/simulate` — probability curve returned
- [x] **5.5.2** — `POST /api/v1/risk/monte-carlo/asset-exposure` — per-asset probability
- [x] **5.5.3** — `GET /api/v1/risk/scan/{id}/monte-carlo` — portfolio simulation
- [x] **5.5.4** — Verify percentile estimates (5%, 25%, 50%, 75%, 95%)

### 5.6 — Certificate Expiry vs CRQC Race
- [x] **5.6.1** — `GET /api/v1/risk/scan/{id}/cert-race` — returns per-cert race analysis
- [x] **5.6.2** — Verify categories: natural_rotation, at_risk, safe
- [ ] **5.6.3** — Summary counts match individual entries

### 5.7 — Enterprise Quantum Rating
- [x] **5.7.1** — `GET /api/v1/risk/scan/{id}/enterprise-rating` — composite 0–1000
- [x] **5.7.2** — 6 weighted dimensions present
- [x] **5.7.3** — Label matches score range (Critical/Vulnerable/Progressing/Ready/Elite)

### 5.8 — Migration Plan
- [x] **5.8.1** — `GET /api/v1/risk/scan/{id}/migration-plan` — 4-phase plan
- [x] **5.8.2** — Phase 0 (immediate) contains critical assets
- [x] **5.8.3** — Each asset has `migration_complexity` breakdown
- [x] **5.8.4** — `migration_blocked_assets` count populated

---

## Track 6: Compliance Engine (Module 4 + 5)

### 6.1 — Per-Asset Compliance
- [x] **6.1.1** — `GET /api/v1/compliance/scan/{id}` — compliance results for all assets
- [x] **6.1.2** — FIPS 203/204/205 deployed booleans populated
- [x] **6.1.3** — `tls_13_enforced`, `forward_secrecy` populated
- [x] **6.1.4** — `rbi_compliant`, `sebi_compliant`, `pci_compliant`, `npci_compliant` populated
- [x] **6.1.5** — `crypto_agility_score` in 0–100 range
- [x] **6.1.6** — `compliance_pct` populated

### 6.2 — FIPS Matrix
- [x] **6.2.1** — `GET /api/v1/compliance/scan/{id}/fips-matrix` — per-asset FIPS status
- [x] **6.2.2** — Summary counts: fips_203_deployed, fips_204_deployed, fips_205_deployed

### 6.3 — Regulatory Compliance
- [x] **6.3.1** — `GET /api/v1/compliance/scan/{id}/regulatory` — RBI/SEBI/PCI/NPCI percentages
- [x] **6.3.2** — Each regulation has compliant/non_compliant counts and pct

### 6.4 — Crypto-Agility Distribution
- [x] **6.4.1** — `GET /api/v1/compliance/scan/{id}/agility` — bucketed distribution (0-20, 21-40, etc.)
- [x] **6.4.2** — `average_agility`, `min_agility`, `max_agility` computed

### 6.5 — Regulatory Deadlines
- [x] **6.5.1** — `GET /api/v1/compliance/deadlines` — deadline list with countdown
- [x] **6.5.2** — Each deadline has `days_remaining` and `urgency`

### 6.6 — Vendor PQC Readiness
- [x] **6.6.1** — `GET /api/v1/compliance/vendor-readiness` — 19 vendors returned
- [x] **6.6.2** — Each vendor has `pqc_support_status`, `supported_algorithms`, `target_version`
- [x] **6.6.3** — Summary: ready / in_progress / unknown counts

---

## Track 7: Topology & Graph (Module 8)

- [x] **7.1** — `GET /api/v1/topology/scan/{id}` — graph JSON
- [x] **7.2** — `node_count > 0`, `edge_count > 0`
- [x] **7.3** — Nodes include asset, certificate, and cipher-suite types
- [x] **7.4** — `GET /api/v1/topology/scan/{id}/blast-radius?cert_fingerprint=...` — blast radius endpoint *(verified exists; returns 404 detail when fingerprint not in graph)*

---

## Track 8: GeoIP (Module 1 extension)

- [x] **8.1** — `GET /api/v1/geo/scan/{id}` — GeoJSON FeatureCollection
- [x] **8.2** — `GET /api/v1/geo/scan/{id}/map-data` — markers + country_summary
- [x] **8.3** — At least one marker has lat/lng populated

---

## Track 9: Deep Scan Streaming & Background

### 9.1 — SSE Stream
- [x] **9.1.1** — `GET /api/v1/scans/{id}/stream` — returns `text/event-stream`
- [x] **9.1.2** — Events emitted: phase_start, crypto_result, phase_complete, scan_complete

### 9.2 — Scan Cache
- [ ] **9.2.1** — Second deep scan for same domain returns cached result
- [ ] **9.2.2** — Quick scan returns cached shallow/deep if available
- [ ] **9.2.3** — Cache TTL: quick=1h, shallow=6h, deep=24h

### 9.3 — Incremental Scanning
- [ ] **9.3.1** — `fingerprint_hash` stored on assets
- [ ] **9.3.2** — Re-scan clones unchanged assets, only re-scans changed ones

---

## Track 10: AI Features (Module 10 + 11)

### 10.1 — RAG Chatbot
- [ ] **10.1.1** — `POST /api/v1/ai/chat` with `{"message": "How many assets were discovered?"}` → SQL mode
- [ ] **10.1.2** — `POST /api/v1/ai/chat` with `{"message": "What is our quantum risk posture?"}` → RAG mode
- [ ] **10.1.3** — Verify `user_id` isolation in VectorStore queries

### 10.2 — Migration Roadmap
- [ ] **10.2.1** — `POST /api/v1/ai/migration-roadmap/{scan_id}` — structured 4-phase roadmap
- [ ] **10.2.2** — Roadmap includes per-asset recommendations

### 10.3 — Report Generation
- [ ] **10.3.1** — `POST /api/v1/reports/generate/{scan_id}` — returns PDF bytes
- [ ] **10.3.2** — PDF contains AI narrative, asset count, risk summary

### 10.4 — Vector Store
- [ ] **10.4.1** — `POST /api/v1/ai/embed/refresh` — accepted status
- [ ] **10.4.2** — VectorStore.embed_and_store() injects `user_id` metadata

### 10.5 — SQL Agent
- [ ] **10.5.1** — TabularAgent loads only authenticated user's data
- [ ] **10.5.2** — Executes read-only queries only (no INSERT/UPDATE/DELETE)

---

## Track 11: End-to-End Master Test Sequence

Execute full pipeline against `https://pnb.bank.in`:

- [ ] **11.1** — Register test user, login, extract JWT
- [ ] **11.2** — Dispatch deep scan `{"targets": ["pnb.bank.in"]}`
- [ ] **11.3** — Poll scan status until completed (or timeout at 15 min)
- [ ] **11.4** — Fetch scan summary → verify all counts > 0
- [ ] **11.5** — Fetch all assets → verify hostnames, IPs, asset_types
- [ ] **11.6** — Fetch all certificates → verify fields populated
- [ ] **11.7** — Fetch all risk scores → verify 0–1000 range, classifications
- [ ] **11.8** — Fetch all compliance results → verify booleans + scores
- [ ] **11.9** — Fetch CBOM records → verify components present
- [ ] **11.10** — Fetch heatmap, HNDL, enterprise-rating, migration-plan
- [ ] **11.11** — Fetch Monte Carlo simulation → verify probability curves
- [ ] **11.12** — Fetch cert-race → verify classifications
- [ ] **11.13** — Fetch topology graph → verify nodes + edges
- [ ] **11.14** — Fetch GeoIP data → verify locations
- [ ] **11.15** — Fetch regulatory deadlines → verify countdown
- [ ] **11.16** — Fetch vendor readiness → verify 19 vendors
- [ ] **11.17** — Run AI chat query → verify response
- [ ] **11.18** — Generate PDF report → verify content
- [ ] **11.19** — Run Quick Scan → verify fast response
- [ ] **11.20** — Run Shallow Scan → verify subdomain discovery
- [ ] **11.21** — Verify PQC algorithm accuracy across all discovered assets
- [ ] **11.22** — Log comprehensive results to `TESTING_RESULTS.md`

---

## Artifact Files Updated

| File | Updated |
|---|---|
| `TESTING_RESULTS.md` | ☐ |
| `DEV_LOG.md` | ☐ |
| `03-FRONTEND.md` | ☐ |
| `04-SYSTEM_ARCHITECTURE.md` | ☐ |
| `06-DEVELOPMENT_PLAN.md` | ☐ |
| `06g-PLAN_P9.md` | ☐ |
| `07-PQC_IMPROVEMENTS.md` | ☐ |
| `OUTPUT_diffs.md` | ☐ |
| `IMPL_SCRATCHPAD.md` | ☐ |