# Implementation Scratchpad

## Test Targets (PERSISTED)
- https://pnb.bank.in
- https://onlinesbi.sbi.bank.in  
- https://www.hdfc.bank.in

## Current Task: Phase 7B — Feature Expansion

---

## Phase Completion Summary

### Phase 0-6 ✅ (Completed)
### Phase 7 — REST API Layer ✅ COMPLETE
- 31 endpoints, 26/26 tests passing
- E2E validated: PNB (96 assets), SBI (87), HDFC (95)
- Enterprise Rating, Migration Plan, Vendor Readiness, Regulatory Countdown implemented

### Phase 7B — Feature Expansion 🔧 IN PROGRESS

**Tracking**: See `PROMPT.md` for detailed checkpoint list

#### Quick Scan Design Notes
- Use ONLY stdlib ssl (no SSLyze) — single connection in 1-3s
- Return: TLS version, cipher, cert details, NIST levels, risk score, compliance snapshot
- No DB persistence for anonymous users; persist for logged-in users
- `scan_tls()` with SSLyze takes 3-8s alone — that's why Quick Scan bypasses it

#### Shallow Scan Design Notes
- crt.sh API for subdomain discovery (~1-5s)
- DNS resolution in parallel (20 workers) to filter live subdomains
- TLS scan top-10 subdomains using stdlib ssl
- Skip: port scanning, SSLyze, pinning detection, auth fingerprint, CDN/WAF detection
- Total target: 30-90 seconds

#### Auth Design Notes  
- bcrypt password hashing via passlib
- JWT HS256 with secret from env (JWT_SECRET_KEY)
- Access token 30min, refresh token 7 days
- Email verification via UUID4 token, 24h expiry
- Quick Scan: public (no auth). Shallow/Deep: require auth.
- user_id FK on ScanJob (nullable for backward compat)
