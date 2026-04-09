# Gap Analysis & Implementation Plan: Pre-Phase 5 Hardening

## Problem Statement

After completing Phases 2–4, a careful comparison of `02-OUTPUTS.md` (the expected output specification) against the actual implementation reveals **significant gaps** in the discovery and analysis depth. The current implementation scans individual bank domains but does NOT produce the breadth of outputs the specification requires.

---

## Gap Analysis: 02-OUTPUTS.md vs Current Implementation

### Module 1 — External Attack Surface Discovery Engine

| Expected Output | Status | Gap |
|---|---|---|
| **1.1 Asset Universe Map** — 100+ subdomains per bank | ❌ MISSING | Discovery Engine runs but only finds assets via the Go binary. The Python pipeline tests use single hostnames (`pnb.bank.in`), not the full subdomain enumeration. The Go binary exists but has never been tested against Indian banking domains. |
| **1.2 Third-Party & Supply Chain Crypto Exposure** — NPCI, CBS vendors, payment gateways | ❌ MISSING | No `third_party_deps` table population. No supply chain crypto mapping at all. |
| **1.3 Shadow Asset Detection** — Dev servers, test portals, legacy subdomains | ❌ MISSING | No CMDB comparison, no shadow detection logic. |
| Asset Class metadata — classify as internet_banking/upi_gateway/swift etc. | ⚠️ PARTIAL | `_infer_asset_type()` in risk_engine.py does hostname-pattern matching, but it's very basic and not saved to Asset model. |
| Hosting Entity — bank-owned DC / AWS / Akamai / NIC | ❌ MISSING | No hosting provider detection. |
| TLS Termination Point identification | ❌ MISSING | No CDN/WAF detection. |

### Module 2 — Deep Cryptographic Inventory

| Expected Output | Status | Gap |
|---|---|---|
| **2.1 Protocol-Level Inventory** per asset | ✅ DONE | scan_tls + get_nist_quantum_level covers this |
| **2.2 Certificate Lifecycle Intelligence** | ⚠️ PARTIAL | We have cert parsing and expiry. Missing: **Effective Security Remaining** (min of cert_expiry vs CRQC), **CA PQC Readiness tracking**, **Multi-SAN exposure analysis** |
| **2.3 API Crypto Fingerprinting** | ⚠️ PARTIAL | `detect_api_auth()` exists but only checks OIDC/Bearer. Missing: **JWT algorithm extraction**, **transport protocol detection (HTTP/2, QUIC)**, **sensitive data indicator detection** |
| **2.4 HSM & Key Management Inventory** | ❌ DEFERRED | Agent-based — out of scope for POC |

### Module 3 — Quantum Risk Scoring

| Expected Output | Status | Gap |
|---|---|---|
| **3.1 Mosca's Theorem** | ✅ DONE | compute_mosca() works correctly |
| **3.2 Asset Classification** | ✅ DONE | 5-tier classification implemented |
| **3.3 TNFL Risk Flags** | ✅ DONE | assess_tnfl() implemented |

### Module 4 — PQC Compliance Dashboard

| Expected Output | Status | Gap |
|---|---|---|
| **4.1 Algorithm Compliance Matrix** | ❌ NOT YET | Planned for Phase 6 |
| **4.2 Crypto-Agility Score** | ❌ NOT YET | Planned for Phase 6 |
| **4.3 Hybrid Deployment Tracker** | ❌ NOT YET | Planned for Phase 6 |

### Module 5 — Banking Threat Intelligence

| Expected Output | Status | Gap |
|---|---|---|
| **5.1 HNDL Exposure Window** | ✅ DONE | compute_hndl_window() implemented |
| **5.2 India-Specific Regulatory Compliance** | ❌ NOT YET | Planned for Phase 6 |
| **5.3 Threat Actor Attribution** | ❌ DEFERRED | Out of scope for POC |

### Module 7 — Certificate Intelligence

| Expected Output | Status | Gap |
|---|---|---|
| **Cert chain parsing** | ✅ DONE | |
| **CRQC-Adjusted Effective Expiry** | ❌ MISSING | Should be computed alongside cert parsing |
| **CA PQC Readiness tracking** | ❌ MISSING | Need a static CA readiness DB |
| **Multi-SAN Exposure (blast radius from one cert)** | ❌ MISSING | Should be in graph builder |
| **CT Log Anomaly Detection** | ❌ DEFERRED | |
| **Certificate Pinning Detection** | ❌ MISSING | HPKP/Expect-CT header check missing |

### Module 9 — Enterprise Quantum Rating

| Expected Output | Status | Gap |
|---|---|---|
| **0–1000 scoring model** | ✅ DONE | compute_risk_score() implements the 5-factor model |

## Critical Gaps to Fix NOW (Phase 5 & 6)

### Gap 1: Asset Discovery is Robust but Unorchestrated
**Status: Discovery Fixed ✅, Orchestration Missing ❌**
The Go Discovery Engine has been successfully extended and verified against Indian banking domains (discovering 100+ subdomains, live IPs, and ports using multiple independent OSINT APIs alongside deep DNS validation). However, these discoveries are NOT being fed into the Python cryptographic inspection pipeline at scale.
**Action**: Implement `backend/app/services/orchestrator.py` to pipe the resulting JSON from the Go Engine directly into `crypto_inspector.py`. Instead of iterating single hostnames, the orchestrator must rigorously compute Certificate Intelligence, CBOM graphs, and Risk Scores against ALL identified subdomains in parallel, yielding comprehensive multi-asset reporting.

### Gap 2: Missing Consolidated Summary Output format 
**Status: ❌ MISSING**
Presently, the encryption algorithms, TLS versions, Quantum Security Status, Key Lengths, Certificate Validities and Risk Statuses are only exposed deep inside isolated JSON constructs or database rows. We need a clean dashboard output summarizing the encryption status across the entire discovery map.
**Action**: As part of Phase 5 Orchestration, `scripts/smoke_test.py` must print a high-level table iterating over every subdomain, displaying its definitive crypto-posture matrix.

### Gap 3: Missing Compliance & Graph Topography (Module 4 & 6 outputs)
**Status: ❌ NOT YET**
- **Compliance Rules**: FIPS 203/204/205 validations, TLS 1.3 enforcing blocks, Forward Secrecy assessments.
- **Crypto-Agility Scores**: Measuring rotation frequencies and automated renewals.
- **Topography Graphs**: Assessing the specific blast radius if a certain certificate's underlying key becomes compromised (i.e. if it is shared across 35 different bank subdomains).
**Action**: Implement Phase 6 `backend/app/services/compliance.py` and `backend/app/services/graph_builder.py`.
