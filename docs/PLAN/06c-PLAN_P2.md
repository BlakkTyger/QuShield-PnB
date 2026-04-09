# Phase 2 — Crypto Inspector

> **Goal**: Build standalone functions that take a hostname:port, perform TLS handshake analysis, enumerate cipher suites, parse certificate chains, detect PQC readiness, and output a structured cryptographic fingerprint.
> **Estimated time**: 5–6 hours
> **Dependencies**: P0 complete
> **External APIs**: None (directly connects to target servers)

---

## Checklist

### P2.1 — Standalone: TLS Handshake & Cipher Suite Enumeration (SSLyze)
- [ ] Create `backend/app/services/crypto_inspector.py` — start with a single function:
  - Function `scan_tls(hostname: str, port: int = 443) -> dict`
  - Uses SSLyze `Scanner` with `ServerScanRequest`
  - Scan commands: `TLS_1_0_CIPHER_SUITES`, `TLS_1_1_CIPHER_SUITES`, `TLS_1_2_CIPHER_SUITES`, `TLS_1_3_CIPHER_SUITES`, `CERTIFICATE_INFO`, `HTTP_HEADERS`
  - Returns dict with: `tls_versions_supported`, `cipher_suites[]`, `negotiated_cipher`, `key_exchange`, `forward_secrecy`, `certificate_chain`
  - Logs: hostname, port, scan commands used, cipher count, TLS version, duration

- [ ] Create `backend/tests/standalone/test_tls_scan.py`:
  - Test 1: `google.com:443` — expect TLS 1.3, ECDHE key exchange, forward secrecy=True
  - Test 2: `expired.badssl.com:443` — expect expired certificate detected
  - Test 3: `tls-v1-0.badssl.com:1010` — expect TLS 1.0 detected (if still available)
  - Test 4: `self-signed.badssl.com:443` — expect self-signed chain issue
  - Each test logs: full cipher list, TLS version, key exchange, timing

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_tls_scan.py -v --tb=short
# Expected: All 4 tests pass with correct TLS detection
```

**📝 Log to DEV_LOG.md**: Cipher counts per site, TLS versions detected, timing per scan

---

### P2.2 — Standalone: Certificate Chain Parsing (cryptography/PyCA)
- [ ] Add function to `crypto_inspector.py`:
  - Function `parse_certificate(cert_pem: bytes) -> dict`
  - Extracts: common_name, san_list, issuer, ca_name, key_type, key_length, signature_algorithm, signature_algorithm_oid, valid_from, valid_to, sha256_fingerprint, is_ct_logged
  - Uses `cryptography.x509.load_pem_x509_certificate()`
  - Detects key type: RSA, EC (P-256/P-384), Ed25519
  - Logs: common_name, key_type, key_length, days_until_expiry

- [ ] Add function `parse_certificate_chain(chain_pems: list[bytes]) -> list[dict]`:
  - Parses each cert in the chain
  - Identifies: leaf, intermediate(s), root
  - Validates chain order (each cert's issuer matches next cert's subject)
  - Returns list of parsed certs with `chain_position` field

- [ ] Create `backend/tests/standalone/test_cert_parse.py`:
  - Test 1: Fetch cert from `google.com`, parse it, verify CN contains "google"
  - Test 2: Fetch cert from `github.com`, verify SAN list includes "github.com"
  - Test 3: Parse the full chain from `example.com`, verify chain depth ≥ 2
  - Test 4: Verify key type detection (RSA vs EC) across multiple real certs

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_cert_parse.py -v
# Expected: All certs parsed correctly, key types detected, chain validated
```

**📝 Log to DEV_LOG.md**: Cert details for each test site (CN, key type, key size, expiry, chain depth)

---

### P2.3 — Standalone: NIST Quantum Security Level Assignment
- [ ] Add function to `crypto_inspector.py`:
  - Function `get_nist_quantum_level(algorithm: str, key_length: int = None) -> dict`
  - Returns: `{"nist_level": int, "is_quantum_vulnerable": bool, "quantum_status": str}`
  - Reads from `backend/app/data/nist_quantum_levels.json` (created in P0.7)
  - Handles: algorithm name normalization (e.g., "TLS_AES_256_GCM_SHA384" → "AES-256-GCM")
  - Logs: input algorithm, resolved level, vulnerability status

- [ ] Create `backend/tests/standalone/test_quantum_level.py`:
  - Test: `RSA-2048` → level 0, vulnerable
  - Test: `AES-256-GCM` → level 5, safe
  - Test: `ECDHE-P256` → level 0, vulnerable
  - Test: `ML-KEM-768` → level 3, PQC safe
  - Test: unknown algorithm → graceful handling (level -1 or "unknown")

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_quantum_level.py -v
```

---

### P2.4 — Standalone: PQC Detection
- [ ] Add function to `crypto_inspector.py`:
  - Function `detect_pqc(hostname: str, port: int = 443) -> dict`
  - **Layer 1 — Signature OID check**: Parse cert's `signature_algorithm_oid` against PQC OID table
  - **Layer 2 — TLS group check**: Attempt to detect if server supports PQC key exchange groups
    - Use Python `ssl` module: check `ssl.SSLContext.get_ciphers()` for any PQC-related entries
    - NOTE: Full PQC handshake detection requires OpenSSL 3.5+ with oqs-provider. For POC, do OID-based detection only + flag that full detection requires oqs-provider.
  - Returns: `{"pqc_key_exchange": bool, "pqc_signature": bool, "pqc_algorithms_found": [], "detection_method": "oid_check"}`
  - Logs: PQC status, algorithms found (if any)

- [ ] Create `backend/tests/standalone/test_pqc_detect.py`:
  - Test 1: `google.com` — likely supports X25519MLKEM768 (Google enabled PQC hybrid in 2024)
  - Test 2: `example.com` — likely classical only
  - Test 3: Verify OID table matches known PQC OIDs

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_pqc_detect.py -v
```

**📝 Log to DEV_LOG.md**: PQC detection results per test site, detection method used

---

### P2.5 — Standalone: API Auth Fingerprinting
- [ ] Add function to `crypto_inspector.py`:
  - Function `detect_api_auth(url: str) -> dict`
  - Checks: `/.well-known/openid-configuration` endpoint
  - Examines response headers for: `WWW-Authenticate`, `X-API-Key` patterns
  - If JWT detected: parse header's `alg` field
  - Returns: `{"auth_mechanisms": ["JWT-RS256", "mTLS"], "jwt_algorithm": "RS256", "oidc_endpoint": "..."}`
  - Uses `httpx` for async HTTP requests
  - Logs: URL, detected auth mechanisms, JWT algorithm

- [ ] Create `backend/tests/standalone/test_api_auth.py`:
  - Test 1: `https://accounts.google.com` — should detect OIDC
  - Test 2: A known API endpoint — check header detection
  - Test 3: A non-API website — should return empty `auth_mechanisms`

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_api_auth.py -v
```

---

### P2.6 — Combined: Full Crypto Inspection Function
- [ ] Add function to `crypto_inspector.py`:
  - Function `inspect_asset(hostname: str, port: int = 443) -> CryptoFingerprint`
  - Calls: `scan_tls()` → `parse_certificate_chain()` → `get_nist_quantum_level()` for each algorithm → `detect_pqc()` → `detect_api_auth()`
  - Returns a unified `CryptoFingerprint` dataclass/dict containing all results
  - Assigns NIST quantum level to each cipher suite and certificate
  - Logs: complete summary (TLS version, cipher count, cert CN, PQC status, quantum level)

- [ ] Add function `inspect_assets_batch(assets: list[dict], max_concurrent: int = 20) -> list[CryptoFingerprint]`:
  - Uses `asyncio` + `ThreadPoolExecutor` for concurrent scanning
  - Progress logging: `Inspecting asset 15/47: www.example.com`
  - Error handling: skip failed assets, log error, continue
  - Returns list of fingerprints (None for failed assets)

- [ ] Create `backend/tests/standalone/test_full_crypto.py`:
  - Test: inspect `google.com` → verify all fields populated
  - Test: inspect `expired.badssl.com` → verify expiry detected
  - Test: batch inspect `["google.com", "github.com", "example.com"]` → all 3 return results

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_full_crypto.py -v
```

---

### P2.7 — Persistence: Save Crypto Results to Database
- [ ] Add function to `crypto_inspector.py`:
  - Function `save_crypto_results(scan_id: str, asset_id: str, fingerprint: dict, db: Session)`
  - Creates `Certificate` records for each cert in the chain
  - Updates the `Asset` record with TLS version, key exchange info
  - Logs: records created, asset updated

- [ ] Add test to `tests/standalone/test_full_crypto.py`:
  - Inspect `example.com`, save results to DB
  - Query back certificates table, verify data integrity

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_full_crypto.py::test_save_to_db -v
```

---

**✅ Phase 2 Complete** when:
1. `scan_tls("google.com")` returns full cipher suite list with TLS 1.3
2. `parse_certificate_chain()` correctly parses real certificate chains
3. NIST quantum levels correctly assigned (RSA=0, AES-256=5)
4. PQC detection runs without errors (even if no PQC detected on classical servers)
5. All standalone tests pass
6. Crypto results persisted to PostgreSQL
7. `DEV_LOG.md` has entries for P2.1 through P2.7
