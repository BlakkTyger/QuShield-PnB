# Verification & Testing Master Checklist (PROMPT3.md)

This document serves as the **Phase 9 Verification Loop** driver. Every feature mandated by the QuShield-PnB specification is listed below. We must test each granular feature, check for output accuracy, verify algorithm classifications, fix any detected bugs, and document findings to `TESTING_RESULTS.md`.

---

## Track 1: Complete Phase 8 API Additions
Before thorough testing, complete the final AI settings APIs as identified:
- [x] 1.1 `PATCH /api/v1/auth/me/ai-settings`: Updates `deployment_mode`, `ai_tier`, and JSON `cloud_api_keys`.
- [x] 1.2 `GET /api/v1/auth/ai-models`: List available models by parsing settings.
- [x] 1.3 `03-FRONTEND.md`: Add UI components for AI Chat, Reports, tier selection.
- [x] 1.4 `04-SYSTEM_ARCHITECTURE.md`: Detail AI abstraction, ChromaDB, Pandas memory isolation.
- [x] 1.5 `06g-PLAN_P9.md`: Revise with this exhaustive testing plan.

---

## Track 2: Core Platform & Application Logic (Verification)

### 2.1 — Authentication & Security Isolation
- [ ] 2.1.1 Secure JWT Generation & Verification (`/api/v1/auth/login`)
- [ ] 2.1.2 Route protection (Ensure scanning requires valid Bearer)
- [ ] 2.1.3 Tenant Isolation (User A cannot view/query User B's scan jobs, assets, or vector space)

### 2.2 — External Attack Surface Discovery
- [ ] 2.2.1 Resolving Target Hostname (`https://pnb.bank.in`)
- [ ] 2.2.2 Subdomain Enum & Rapid Concurrent IP Resolution
- [ ] 2.2.3 Third-Party / Shadow Asset flagging.

### 2.3 — Deep Cryptographic Inventory & TLS Scanning
- [ ] 2.3.1 TLS Handshake mapping (versions, forward secrecy)
- [ ] 2.3.2 Cipher Suite Extraction & Accurate NIST Algorithm Mapping
- [ ] 2.3.3 **PQC Detection Accuracy**: Verify NIST Level (0-6) mapped precisely for legacy RSA/ECC vs ML-KEM/ML-DSA.
- [ ] 2.3.4 JWT Deep Algorithm Parsing extraction
- [ ] 2.3.5 Certificate extraction (Subject, Issuer, Hash, Expiry)

### 2.4 — Quantum Risk Scoring (Mosca's Model)
- [ ] 2.4.1 Mosca's Inequality execution (Migration Time + Shelf Life > Time to CRQC)
- [ ] 2.4.2 Accurate dynamic generation of `base_score` (0-1000 scale).
- [ ] 2.4.3 Classification logic (Quantum Critical, Vulnerable, At Risk, Aware, Ready).
- [ ] 2.4.4 Cert-CRQC Expiry Race mapping calculation accuracy.

### 2.5 — Compliance & Vendor Logic
- [ ] 2.5.1 FIPS 203/204/205 Mapping Check
- [ ] 2.5.2 Regulatory bodies check (RBI, SEBI, PCI-DSS)
- [ ] 2.5.3 Crypto-Agility score calculation
- [ ] 2.5.4 Vendor PQC Readiness matching mapping

### 2.6 — CBOM & Topology
- [ ] 2.6.1 CycloneDX 1.6 valid JSON payload generation
- [ ] 2.6.2 Graph Relationship Topology builder (Neo4J layout JSON)

### 2.7 — Deep Scan Orchestration
- [ ] 2.7.1 Real-time background processing (multi-threading).
- [ ] 2.7.2 Server-Sent Events (SSE) `stream` accuracy tracking % progress.
- [ ] 2.7.3 Incremental Scans (caching and short-circuiting unchanged domains).

### 2.8 — AI Data Analytics & Reporting
- [ ] 2.8.1 `SqlAgent`: SQLite Memory Isolation on Pandas DataFrames for tabular query safety.
- [ ] 2.8.2 `VectorStore`: ChromaDB RAG chunking with strict `user_id` injection and retrieval.
- [ ] 2.8.3 `Migration Roadmap API`: PQCC standard Output generation.
- [ ] 2.8.4 `ReportGenerator`: Executive HTML embedding AI outputs + WeasyPrint PDF compile.

---

## Track 3: The End-To-End Execution & Bug Hunt
Execute a complete sequence against the exact target `https://pnb.bank.in`:
- [ ] 3.1 Create User, authenticate, extract JWT.
- [ ] 3.2 Dispatch Deep Scan payload `{"targets": ["pnb.bank.in"]}`.
- [ ] 3.3 Validate the Deep Scan completes 100% via the background loop.
- [ ] 3.4 Aggressively scrape the SQLite database and raw outputs for anomalies.
  - *Are algorithm names mapping to the PQC matrix correctly or returning N/A?*
  - *Are foreign keys linking properly?*
  - *Is the Mosca math failing or dividing by zero?*
- [ ] 3.5 Fix all discovered bugs immediately. Update backend logic to ensure perfection.
- [ ] 3.6 Re-run the scan payload post-patches.
- [ ] 3.7 Run complex AI prompts (Tabular generation and Roadmap Generation) to certify LLM accuracy.
- [ ] 3.8 Write comprehensively logged verification output to `TESTING_RESULTS.md`.