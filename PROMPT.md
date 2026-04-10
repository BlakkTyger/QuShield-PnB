# Phase 7B — Feature Expansion Plan

> **Generated**: 2026-04-10
> **Status**: 🔧 IN PROGRESS
> **Predecessor**: Phase 7 (REST API Layer — ✅ COMPLETE)

---

## Bottleneck Analysis

### Current Scan Timing Breakdown (PNB: 96 assets, ~7 min total)

| Phase | Service | Duration | Bottleneck? |
|---|---|---|---|
| **Phase 1**: Discovery | Go binary (DNS + CT + ports) | ~30s | ❌ Fast |
| **Phase 2**: Crypto Inspection | Python (`inspect_asset` × 96, 10 workers) | **~5–6 min** | **🔴 PRIMARY** |
| Phase 3: CBOM Generation | Python (sequential) | ~10s | ❌ |
| Phase 4: Risk Assessment | Python (sequential) | ~5s | ❌ |
| Phase 5: Compliance | Python (sequential) | ~10s | ❌ |
| Phase 6: Topology Graph | Python (networkx) | ~2s | ❌ |

### Phase 2 Sub-Step Breakdown (per asset)

| Step | Function | Timeout | Avg Time | Network Calls |
|---|---|---|---|---|
| TLS scan (SSLyze) | `_scan_with_sslyze()` | 15s | 3–8s | 4 TLS version probes |
| TLS fallback (stdlib) | `_scan_with_stdlib()` | 15s | 1–3s | 1 connection |
| Cert chain parse | `parse_certificate_chain()` | — | <50ms | 0 (CPU only) |
| NIST level assignment | `get_nist_quantum_level()` | — | <1ms | 0 |
| PQC detection | `detect_pqc()` | 10s | 1–10s | 1 SSL connection |
| Auth fingerprint | `detect_api_auth()` | 10s | 2–10s | 2–3 HTTP requests |
| Cert pinning | `detect_certificate_pinning()` | **20s** | **10–20s** | 1 HTTP + header parse |
| CDN/WAF/Hosting | `detect_hosting_and_cdn()` | 10s | 2–5s | 1–2 HTTP requests |
| Asset classification | `classify_asset_type()` | — | <1ms | 0 |

**Root cause**: Each asset makes **5–8 network connections** with high timeouts. With 10 workers for 96 assets, the wall clock is dominated by the slowest assets (pinning detection timeout = 20s).

### Scan Tier Design

| Tier | Target Latency | What It Does | Network Calls |
|---|---|---|---|
| **Quick Scan** | 3–8 seconds | Root domain only: 1 TLS handshake + cert parse + NIST levels + risk score + compliance | **1** (single SSL) |
| **Shallow Scan** | 30–90 seconds | Quick + subdomain discovery (DNS/CT only, no port scan) + crypto on top-10 subdomains | ~12 |
| **Deep Scan** | 5–10 minutes | Full pipeline: Go discovery + all subdomains + all crypto steps + CBOM + risk + compliance + topology | 500+ |

---

## Execution Plan

### Track A — Scan Tiers & Performance (Features 1, 9)

- [x] **A.0** — Doc updates: Update `04-SYSTEM_ARCHITECTURE.md`, `05-ALGORITHM_RESEARCH.md`, `PLAN/06-DEVELOPMENT_PLAN.md` with scan tier architecture, Quick/Shallow/Deep definitions, auth system design, GeoIP design
- [x] **A.1** — Quick Scan service: New `quick_scanner.py` — single-domain TLS+cert+risk in <8s ✅
  - [x] A.1.1 — Implement `quick_scan(domain)` function: 1 SSL handshake, cert parse, NIST levels, risk score, compliance snapshot ✅
  - [x] A.1.2 — Standalone test script: `tests/standalone/test_quick_scan.py` ✅
  - [x] A.1.3 — API endpoint: `POST /api/v1/scans/quick` (returns result synchronously) ✅
  - [x] A.1.4 — Integration test + DEV_LOG entry ✅
- [x] **A.2** — Shallow Scan service: New `shallow_scanner.py` — DNS/CT discovery + top-N crypto ✅
  - [x] A.2.1 — Implement lightweight discovery (DNS + crt.sh + brute-force fallback) ✅
  - [x] A.2.2 — Implement shallow crypto: TLS scan + cert parse only (skip pinning, auth, CDN) ✅
  - [x] A.2.3 — Standalone test script ✅
  - [x] A.2.4 — API endpoint: `POST /api/v1/scans/shallow` (synchronous, 30-90s) ✅
  - [x] A.2.5 — Integration test + DEV_LOG entry ✅
- [x] **A.3** — Deep Scan optimization: Reduce timeouts, increase parallelism ✅
  - [x] A.3.1 — Reduce `detect_certificate_pinning` timeout from 10s → 5s ✅
  - [x] A.3.2 — Increase crypto workers from 10 → 20 ✅
  - [x] A.3.3 — Parallelize CBOM generation (ThreadPoolExecutor) ✅
  - [x] A.3.4 — Integration tests pass, no regressions ✅
- [x] **A.4** — `ScanJob` model update: Add `scan_type` field (quick/shallow/deep) ✅
  - [x] A.4.1 — DB migration + model update ✅
  - [x] A.4.2 — Scan type passed via dedicated endpoints (quick/shallow/deep) ✅
- [x] **A.5** — Incremental scanning (delta scan) ✅
  - [x] A.5.1 — Add `fingerprint_hash` column to Asset (sha256 of IP + TLS negotiated cipher + cert fingerprint) ✅
  - [x] A.5.2 — On new scan, compare fingerprint_hash with last scan for same hostname ✅
  - [x] A.5.3 — If unchanged, clone previous crypto/CBOM/risk/compliance data to new scan ✅
  - [x] A.5.4 — Only re-scan changed or new assets ✅
  - [x] A.5.5 — Standalone test + integration test + DEV_LOG entry ✅

### Track B — Authentication & Scan Cache (Feature 2)

- [x] **B.1** — User model + DB schema ✅
  - [x] B.1.1 — Create `User` SQLAlchemy model: id, email, password_hash, email_verified, created_at ✅
  - [x] B.1.2 — Create `EmailVerification` model: token, user_id, expires_at ✅
  - [x] B.1.3 — Add `user_id` FK to `ScanJob` model ✅
  - [x] B.1.4 — DB tables auto-created via Base.metadata ✅
- [x] **B.2** — Auth service ✅
  - [x] B.2.1 — Implement `auth_service.py`: register, login, verify_email, hash_password, verify_password ✅
  - [x] B.2.2 — JWT token generation + validation (access + refresh tokens) ✅
  - [x] B.2.3 — FastAPI dependency `get_current_user` for protected endpoints ✅
  - [x] B.2.4 — Standalone test script ✅
- [x] **B.3** — Auth API endpoints ✅
  - [x] B.3.1 — `POST /api/v1/auth/register` — signup with email ✅
  - [x] B.3.2 — `POST /api/v1/auth/login` — returns JWT tokens ✅
  - [x] B.3.3 — `POST /api/v1/auth/verify-email/{token}` — email verification ✅
  - [x] B.3.4 — `POST /api/v1/auth/refresh` — refresh token ✅
  - [x] B.3.5 — `GET /api/v1/auth/me` — current user info ✅
  - [x] B.3.6 — Integration tests + DEV_LOG entry ✅
- [x] **B.4** — Scan result caching (smart tier upgrade) ✅
  - [x] B.4.1 — Create `ScanCache` model: domain, scan_type, scan_id, cached_at, expires_at ✅
  - [x] B.4.2 — On scan request, check ScanCache: if same/higher tier exists and fresh → return cached ✅
  - [x] B.4.3 — Tier hierarchy: deep > shallow > quick (request for quick returns shallow if available) ✅
  - [x] B.4.4 — Cache TTL: quick=1h, shallow=6h, deep=24h (configurable) ✅
  - [x] B.4.5 — Integration test + DEV_LOG entry ✅
- [x] **B.5** — Protect scan endpoints: require auth, associate scans with user_id ✅
  - [x] B.5.1 — Add auth dependency to scan/create endpoints ✅
  - [x] B.5.2 — `GET /api/v1/scans/my` — list current user's scans ✅
  - [x] B.5.3 — Ensure users can only access their own scan results (data isolation) ✅

### Track C — GeoIP Location & Map Data (Feature 3)

- [x] **C.1** — GeoIP service ✅
  - [x] C.1.1 — Implemented `geo_service.py`: MaxMind primary + ip-api.com fallback ✅
  - [x] C.1.2 — Standalone test: PNB→Noida, SBI→Navi Mumbai, HDFC→France/Canada ✅
- [x] **C.2** — Integrate GeoIP into discovery/orchestrator ✅
  - [x] C.2.1 — Added `GeoLocation` model + DB table ✅
  - [x] C.2.2 — On-demand resolution: first API call resolves+persists, subsequent calls use cache ✅
  - [x] C.2.3 — Batch geolocate with parallel workers ✅
- [x] **C.3** — GeoIP API endpoints ✅
  - [x] C.3.1 — `GET /api/v1/geo/scan/{id}` — GeoJSON FeatureCollection ✅
  - [x] C.3.2 — `GET /api/v1/geo/scan/{id}/map-data` — markers + country_summary + risk overlay ✅
  - [x] C.3.3 — Integration tests (29/29 passing) + DEV_LOG entry ✅

### Track D — Crypto Algorithm Improvements (Features 4, 5, 6, 7)

- [x] **D.1** — Hybrid PQC TLS group detection (Feature 4) ✅
  - [x] D.1.1 — Added hybrid named group map with IANA IDs (X25519MLKEM768, SecP256r1MLKEM768, etc.) ✅
  - [x] D.1.2 — Extended `detect_pqc()` with Layer 3 (shared ciphers) + Layer 4 (hybrid group decomposition) ✅
  - [x] D.1.3 — Returns `hybrid_groups` with classical/PQC component breakdown ✅
  - [x] D.1.4 — Integration tests pass ✅
  - [x] D.1.5 — Integration test + DEV_LOG entry ✅
- [x] **D.2** — TLS cipher suite decomposition (Feature 5) ✅
  - [x] D.2.1 — Implemented `decompose_cipher_suite()` with TLS 1.3/1.2 lookup tables + heuristic fallback ✅
  - [x] D.2.2 — Updated `build_cbom()` to store decomposed components in metadata ✅
  - [x] D.2.3 — CBOM components include `decomposition` field ✅
  - [x] D.2.4 — Standalone test verified all cipher patterns ✅
  - [x] D.2.5 — Integration test + DEV_LOG entry ✅
- [x] **D.3** — Data sensitivity multiplier for HNDL (Feature 6) ✅
  - [x] D.3.1 — Added `SENSITIVITY_MULTIPLIERS` dict (swift=5.0x, internet_banking=3.0x, etc.) ✅
  - [x] D.3.2 — Modified `compute_hndl_window()` with asset_type param + weighted_exposure ✅
  - [x] D.3.3 — HNDL API endpoint returns `sensitivity_multiplier` and `weighted_exposure` per asset ✅
  - [x] D.3.4 — Exposed assets sorted by weighted_exposure descending ✅
  - [x] D.3.5 — Standalone test + integration test verified ✅
- [x] **D.4** — Migration complexity scoring (Feature 7) ✅
  - [x] D.4.1 — Implemented `compute_migration_complexity()`: base + agility/3rd-party/pinning/FS penalties, capped at 8yr ✅
  - [x] D.4.2 — Migration-plan endpoint computes per-asset dynamic complexity ✅
  - [x] D.4.3 — Each asset entry includes full `migration_complexity` breakdown ✅
  - [x] D.4.4 — Standalone test verified across all asset types ✅
  - [x] D.4.5 — Integration tests pass ✅

### Track E — Already Implemented (Verify & Close)

- [x] **E.1** — Migration Readiness Dashboard (Feature 8) — `GET /api/v1/risk/scan/{id}/migration-plan` ✅
- [x] **E.2** — Enterprise Quantum Rating — `GET /api/v1/risk/scan/{id}/enterprise-rating` ✅
- [x] **E.3** — Vendor PQC Readiness — `GET /api/v1/compliance/vendor-readiness` ✅
- [x] **E.4** — Regulatory Countdown — enhanced `/api/v1/compliance/deadlines` ✅

### Track F — Documentation Updates

- [x] **F.1** — Update `04-SYSTEM_ARCHITECTURE.md`: scan tiers, auth service, GeoIP service, scan cache ✅
- [x] **F.2** — Update `05-ALGORITHM_RESEARCH.md`: quick scan algorithm, shallow scan strategy, cipher decomposition, hybrid PQC detection ✅
- [x] **F.3** — Update `03-FRONTEND.md`: Quick Scan page UX, map visualization page, auth pages (login/register), scan history page ✅
- [x] **F.4** — Create `PLAN/06h-PLAN_P7B.md`: detailed phase plan for all new features ✅
- [x] **F.5** — Update `07-PQC_IMPROVEMENTS.md` as features are implemented (in progress)
- [x] **F.6** — Update `OUTPUT_diffs.md` as gaps are closed (in progress)

---

## Execution Order

**Priority**: Documentation first → Quick Scan (highest user impact) → Auth → GeoIP → Algorithm improvements → Incremental scanning

| Step | Checkpoint | Depends On |
|---|---|---|
| 1 | F.1–F.4 (doc updates) | — |
| 2 | A.1 (Quick Scan) | F.1 |
| 3 | A.4 (ScanJob model update) | A.1 |
| 4 | A.2 (Shallow Scan) | A.1, A.4 |
| 5 | A.3 (Deep Scan optimization) | — |
| 6 | D.1 (Hybrid PQC detection) | — |
| 7 | D.2 (Cipher decomposition) | — |
| 8 | D.3 (HNDL sensitivity) | — |
| 9 | D.4 (Migration complexity) | — |
| 10 | B.1–B.3 (Auth) | — |
| 11 | B.4 (Scan cache) | A.4, B.1 |
| 12 | B.5 (Protected endpoints) | B.2 |
| 13 | C.1–C.3 (GeoIP) | — |
| 14 | A.5 (Incremental scanning) | A.4, B.4 |
| 15 | F.5–F.6 (Final doc updates) | All above |

---

## Rules

- Test each feature independently before integrating
- Do not break existing Deep Scan pipeline
- Log every feature addition and test result to `DEV_LOG.md`
- Use `IMPL_SCRATCHPAD.md` for reasoning and research
- Do not start frontend — only update `03-FRONTEND.md` for documentation
- Keep `07-PQC_IMPROVEMENTS.md` and `OUTPUT_diffs.md` current