# Implementation Scratchpad — Phase 2, 3, 4

## Test Targets (PERSISTED)
- https://pnb.bank.in
- https://onlinesbi.sbi.bank.in  
- https://www.hdfc.bank.in

## Current Task: ✅ Done — Phase 2, 3, 4 Complete
Next: Phase 5 — Compliance + Graph Service (if needed)

## Key Dependencies
- sslyze (TLS scanning)
- cryptography (cert parsing)
- cyclonedx-python-lib v11.7.0 (CBOM generation)
- numpy (vectorized risk computation)
- app/data/nist_quantum_levels.json (algorithm → NIST level mapping)
- app/data/pqc_oids.json (PQC OID detection)
- app/data/data_shelf_life_defaults.json (data shelf life by asset type)

---

## Phase Completion Summary (2026-04-09)

### Phase 2 — Crypto Inspector ✅
- P2.1: TLS scan with SSLyze + stdlib fallback — 3 bug fixes applied
- P2.2: Certificate chain parsing (CN, SAN, key type, chain validation)
- P2.3: NIST quantum level assignment with normalization
- P2.4: PQC detection via OID check + TLS group check
- P2.5: API auth fingerprinting (OIDC, Bearer, API-Key)
- P2.6: Full crypto inspection pipeline
- P2.7: DB persistence (Certificate records)

### Phase 3 — CBOM Builder ✅
- P3.1: CycloneDX 1.6 BOM assembly with AlgorithmProperties, CertificateProperties, ProtocolProperties
- P3.2: File storage (data/cbom/{scan_id}/{asset_id}.cdx.json) + DB persistence
- P3.3: Aggregate CBOM with deduplication and statistics
- P3.4: CVE cross-referencing via NVD API v2

### Phase 4 — Risk Engine ✅
- P4.1: Mosca's inequality (X+Y>Z for 3 CRQC scenarios)
- P4.2: 5-factor quantum risk score (0-1000) — RSA-only=775, PQC=225, Hybrid=525
- P4.3: HNDL exposure window computation
- P4.4: TNFL assessment (rule-based, SWIFT=CRITICAL, JWT=MEDIUM, PQC=safe)
- P4.5: Combined risk assessment with DB persistence

### Test Summary
- **26 non-network tests pass** in 4.5s
- All network tests (TLS scans against Indian banking domains) also pass
- Total: ~40 tests across 3 test files
