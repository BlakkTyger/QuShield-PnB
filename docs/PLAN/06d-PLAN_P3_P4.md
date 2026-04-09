# Phase 3 — CBOM Builder

> **Goal**: Build the CycloneDX CBOM generator that takes crypto inspection results and produces a standards-compliant Cryptographic Bill of Materials.
> **Estimated time**: 3–4 hours
> **Dependencies**: P2 complete (crypto inspection results exist in DB)

---

## Checklist

### P3.1 — Standalone: CycloneDX BOM Assembly
- [x] Create `backend/app/services/cbom_builder.py`:
  - Function `build_cbom(asset_id: str, crypto_fingerprint: dict) -> dict`
  - Uses `cyclonedx-python-lib` to create a CycloneDX 1.6 BOM
  - For each cipher suite detected → create CycloneDX `Component` with:
    - `type`: `CRYPTOGRAPHIC_ASSET`
    - `name`: algorithm name
    - `properties`: `nistQuantumSecurityLevel`, `keyLength`, `quantumVulnerable`
  - For each certificate → create CycloneDX `Component` with cert metadata
  - For detected crypto library (e.g., OpenSSL version from server banner) → `Component` type `LIBRARY`
  - Sets `dependencies[]` between components (e.g., cipher depends on key exchange)
  - Serializes to JSON string
  - Logs: component count, vulnerable count, output size

- [x] Create `backend/tests/standalone/test_cbom_build.py`:
  - Test 1: Build CBOM from a mock crypto fingerprint (RSA-2048, AES-256-GCM, TLS 1.2)
    - Assert: 3+ components created
    - Assert: RSA-2048 component has `nistQuantumSecurityLevel = 0`
    - Assert: AES-256-GCM has `nistQuantumSecurityLevel = 5`
    - Assert: valid JSON output parseable by CycloneDX schema
  - Test 2: Build CBOM from real `google.com` crypto inspection (run inspect first)
    - Assert: at least 5 components (ciphers + cert + key exchange)

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_cbom_build.py -v
```

**📝 Log to DEV_LOG.md**: Component counts, quantum level distribution, JSON output size

---

### P3.2 — CBOM File Storage
- [x] Add function to `cbom_builder.py`:
  - Function `save_cbom(scan_id: str, asset_id: str, cbom_json: str) -> str`
  - Writes CBOM JSON to filesystem: `data/cbom/{scan_id}/{asset_id}.cdx.json`
  - Creates directories if needed
  - Returns file path
  - Logs: file path, file size

- [x] Add function `save_cbom_to_db(scan_id: str, asset_id: str, cbom_data: dict, file_path: str, db: Session)`
  - Creates `CBOMRecord` in database (metadata only — not the full JSON)
  - Creates `CBOMComponent` records for each component (for fast DB queries)
  - Logs: records created

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_cbom_build.py::test_save_cbom -v
# Verify: data/cbom/test_scan/test_asset.cdx.json exists and is valid JSON
# Verify: cbom_records and cbom_components tables have entries
```

---

### P3.3 — CBOM Aggregate (Org-Wide)
- [x] Add function to `cbom_builder.py`:
  - Function `build_aggregate_cbom(scan_id: str, db: Session) -> dict`
  - Queries all CBOM components for the scan
  - Builds an org-wide BOM merging all per-asset components
  - Deduplicates algorithms (same algorithm appearing on multiple assets counted once)
  - Adds summary statistics: `total_assets`, `total_components`, `vulnerable_components`, `quantum_ready_pct`
  - Returns aggregate data as dict

**✅ Standalone Test**: Create 3 mock CBOMs, build aggregate, verify stats are correct

---

### P3.4 — CVE Cross-Referencing (Optional for POC)
- [x] Add function to `cbom_builder.py`:
  - Function `lookup_cves(library_name: str, version: str) -> list[dict]`
  - Queries NVD API v2: `GET /rest/json/cves/2.0?keywordSearch={lib}+{version}`
  - Returns list of CVE IDs + severity + description
  - Rate limited: max 5 req/30s without API key
  - Cache results in memory (same version always returns same CVEs)
  - Graceful degradation: if NVD is slow/down, return empty list with warning log

**✅ Standalone Test**:
```bash
# Test: lookup CVEs for "openssl 1.1.1" — should find multiple CVEs
cd backend && python -m pytest tests/standalone/test_cbom_build.py::test_cve_lookup -v
```

**📝 Log to DEV_LOG.md**: CVE count found, API response time

---

**✅ Phase 3 Complete** when:
1. `build_cbom()` produces valid CycloneDX 1.6 JSON for any crypto fingerprint
2. CBOM files saved to filesystem with correct directory structure
3. CBOM metadata and components saved to PostgreSQL
4. NIST quantum levels correctly assigned to all components
5. All standalone tests pass
6. `DEV_LOG.md` has entries for P3.1 through P3.4


---

# Phase 4 — Risk Engine

> **Goal**: Implement Mosca's theorem, the 5-factor quantum risk scoring model, HNDL exposure window, and TNFL risk assessment.
> **Estimated time**: 4–5 hours
> **Dependencies**: P3 complete (CBOM data exists in DB)

---

## Checklist

### P4.1 — Standalone: Mosca's Inequality Calculator
- [x] Create `backend/app/services/risk_engine.py`:
  - Function `compute_mosca(migration_time_years: float, data_shelf_life_years: float, crqc_scenarios: dict) -> dict`
  - Computes: `X + Y > Z` for pessimistic, median, and optimistic CRQC scenarios
  - Returns: `{"exposed_pessimistic": bool, "exposed_median": bool, "exposed_optimistic": bool, "years_until_exposure": float}`
  - Uses `numpy` for vectorized computation (handles batch of assets)
  - Logs: input values, exposure status for each scenario

- [x] Create `backend/tests/standalone/test_risk_score.py`:
  - Test 1: SWIFT endpoint (X=2yr migration, Y=10yr shelf life, Z_pessimistic=2029≈3yr) → exposed_pessimistic=True (2+10>3)
  - Test 2: OTP endpoint (X=0.5yr, Y=0.01yr, Z_pessimistic=3yr) → exposed=False (0.5+0.01<3)
  - Test 3: Batch compute for 5 different asset types → verify all results

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_risk_score.py::test_mosca -v
```

**📝 Log to DEV_LOG.md**: Mosca results for each test case, computation time

---

### P4.2 — Standalone: Quantum Risk Score (0–1000)
- [x] Add function to `risk_engine.py`:
  - Function `compute_risk_score(asset_data: dict, cbom_data: dict, compliance_data: dict = None) -> dict`
  - Implements 5-factor model (from `05-ALGORITHM_RESEARCH.md` § 4.3):
    1. PQC Algorithm Deployment (30%) — from CBOM components
    2. HNDL Exposure (25%) — from Mosca result
    3. Crypto-Agility (15%) — default 50 if compliance not yet computed
    4. Certificate Hygiene (10%) — key length, valid chain, CT logged
    5. Regulatory Compliance (10%) — default 50 if not yet computed
    6. Migration Velocity (10%) — default 0 for first scan
  - Returns: `{"quantum_risk_score": int, "risk_classification": str, "factors": [...]}`
  - Classification: Quantum Ready (0-199) / Aware (200-399) / At Risk (400-599) / Vulnerable (600-799) / Critical (800-1000)
  - Logs: each factor's score, total score, classification

- [x] Add to `test_risk_score.py`:
  - Test: Asset with RSA-2048 only, no PQC → score > 700 (Vulnerable/Critical)
  - Test: Asset with ML-KEM-768 deployed → score < 300 (Ready/Aware)
  - Test: Mixed asset (hybrid TLS 1.3 + RSA cert) → score 300-600

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_risk_score.py::test_risk_score -v
```

---

### P4.3 — Standalone: HNDL Exposure Window
- [x] Add function to `risk_engine.py`:
  - Function `compute_hndl_window(first_seen: datetime, cipher_vulnerable: bool, data_shelf_life_years: float, crqc_year: int) -> dict`
  - Returns: `{"harvest_start": date, "harvest_end": date, "decrypt_risk_end": date, "is_currently_exposed": bool, "exposure_years": float}`
  - Logs: window boundaries, exposure status

- [x] Add to `test_risk_score.py`:
  - Test: Asset first seen 2024, vulnerable cipher, shelf life 10yr, CRQC 2032 → exposed, harvest window = 2024-2032

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_risk_score.py::test_hndl -v
```

---

### P4.4 — Standalone: TNFL Risk Assessment
- [x] Add function to `risk_engine.py`:
  - Function `assess_tnfl(asset_type: str, signature_algorithm: str, auth_mechanisms: list) -> dict`
  - Rule-based evaluation from `05-ALGORITHM_RESEARCH.md` § 4.5
  - Returns: `{"tnfl_risk": bool, "tnfl_severity": str, "tnfl_contexts": [str]}`
  - Logs: asset type, signature algo, TNFL result

- [x] Add to `test_risk_score.py`:
  - Test: SWIFT endpoint + ECDSA → TNFL=True, severity=CRITICAL
  - Test: Web portal + RSA → TNFL=True, severity=MEDIUM (JWT signing)
  - Test: Web portal + ML-DSA → TNFL=False

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_risk_score.py::test_tnfl -v
```

---

### P4.5 — Combined: Full Risk Assessment for an Asset
- [x] Add function to `risk_engine.py`:
  - Function `assess_asset_risk(asset_id: str, scan_id: str, db: Session) -> dict`
  - Pulls asset data + CBOM components from DB
  - Runs: Mosca → risk score → HNDL window → TNFL
  - Saves `RiskScore` and `RiskFactor` records to DB
  - Returns full risk assessment
  - Logs: complete risk summary

- [x] Add function `assess_all_assets(scan_id: str, db: Session) -> list[dict]`:
  - Runs risk assessment for all assets in the scan
  - Uses numpy for batch Mosca computation
  - Logs: total assets, risk distribution (X critical, Y vulnerable, ...)

**✅ Standalone Test**: Run full risk assessment on assets from P2/P3 test data, verify DB records

---

**✅ Phase 4 Complete** when:
1. Mosca's inequality correctly identifies exposed/safe assets
2. Risk scores in 0–1000 range with correct classification
3. HNDL windows computed with correct date arithmetic
4. TNFL correctly flags signature-dependent assets
5. All results persisted to PostgreSQL
6. All standalone tests pass
