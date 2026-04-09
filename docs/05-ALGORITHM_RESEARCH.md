# 05 — Algorithm, Library & Tooling Research

> **Purpose**: For every functional substep in the scan pipeline (as defined in `04-SYSTEM_ARCHITECTURE.md`), this document identifies the best-fit algorithm, library, or external tool — with alternatives considered and rationale for the final pick. No code is written; this is a pure research deliverable.

---

## How This Document Maps to the Architecture

The scan pipeline defined in the Orchestrator's Temporal workflow has **six sequential phases**. This document follows that exact phasing:

| Phase | Service | Core Function |
|-------|---------|---------------|
| **Phase 0** | Orchestrator | Validate targets, check rate limits |
| **Phase 1** | Discovery Engine (Go) | DNS, CT logs, ASN, ports, HTTP probing |
| **Phase 2** | Crypto Inspector (Python) | TLS handshake, cipher enum, cert parsing, PQC detection |
| **Phase 3** | CBOM Service (Python) | CycloneDX BOM assembly, CVE cross-ref, NIST quantum levels |
| **Phase 4** | Risk Engine (Python) | Mosca theorem, HNDL window, TNFL, quantum risk scoring |
| **Phase 5** | Compliance + Graph (parallel) | Regulatory checks, crypto-agility, Neo4j topology, blast radius |
| **Phase 6** | Post-scan (Notifications, AI, Reports, Migration) | Alerting, RAG chatbot, PDF generation, roadmap |

---

## Phase 0 — Orchestration & Workflow Engine

### 0.1 Workflow Orchestration

| Candidate | Language | Strengths | Weaknesses |
|-----------|----------|-----------|------------|
| **Temporal** | Python SDK (`temporalio`) | Durable execution survives pod restarts; native retries with exponential backoff; multi-step workflow state; timer-based scheduling; signal/query support | Heavier infrastructure (needs Temporal server + PostgreSQL/Cassandra backend) |
| Celery + Redis | Python | Simple, widely used | No native multi-step workflows; no durable state; poor at long-running fan-out-fan-in |
| Prefect 2 | Python | Good UI, DAG-based | Higher overhead; designed for data pipelines, not request-driven scan jobs |
| Apache Airflow | Python | Mature, DAG scheduler | Overkill; designed for batch ETL, not real-time event-driven workflows |

**✅ DECISION: Temporal** via `temporalio` Python SDK.
- Workflow: Python `async def` decorated with `@workflow.defn`
- Activities: one per scan phase trigger (e.g., `trigger_discovery`, `trigger_crypto_inspect`)
- Retry policy: 3 retries, exponential backoff (2s, 4s, 8s), per-activity timeout 30 min
- The Temporal server runs as a Docker container alongside the app

### 0.2 Message Bus

| Candidate | Durability | Replay | Fan-out | Language Support |
|-----------|------------|--------|---------|-----------------|
| **Apache Kafka** | ✅ Persistent log | ✅ Consumer offset replay | ✅ Native consumer groups | Go: `segmentio/kafka-go` · Python: `confluent-kafka` |
| RabbitMQ | ✅ (optional) | ❌ | ✅ | Both |
| NATS JetStream | ✅ | ✅ | ✅ | Both, but smaller ecosystem |
| Redis Streams | ✅ | ✅ | Limited | Both |

**✅ DECISION: Apache Kafka**
- **Python client**: `confluent-kafka` — C-extension based (librdkafka), 10-50x faster than `kafka-python`
- **Go client**: `segmentio/kafka-go` — pure Go, no CGO dependency, good goroutine integration
- Message format: JSON with versioned schema envelope (not Avro initially — reduces Schema Registry dependency for MVP)
- Topic partitioning: partition by `org_id` for multi-tenant isolation

### 0.3 Scan Job State Cache

**✅ DECISION: Redis 7** for:
- Scan job status polling (low-latency GET by `scan_id`)
- Real-time pub/sub to WebSocket Hub (`scan:events:{scan_id}` channel)
- Rate-limit counters (per-org, per-user)
- Python client: `redis[hiredis]` (hiredis C parser for 3x throughput)

---

## Phase 1 — Discovery Engine (Go)

> This is the only service written in Go. Go is chosen because Phase 1 requires massively concurrent network I/O (50,000+ goroutines for DNS resolution, port scanning). Python's GIL makes this impractical.

### 1.1 Subdomain Enumeration

| Candidate | Type | Speed | Sources | Integrability |
|-----------|------|-------|---------|---------------|
| **subfinder v2** (ProjectDiscovery) | Passive OSINT | ⚡ Fast | 50+ sources (crt.sh, VirusTotal, Shodan, SecurityTrails, Chaos, Censys) | Go library import: `github.com/projectdiscovery/subfinder/v2` |
| Amass v4 (OWASP) | Active + Passive | 🐢 5-10x slower | Broadest source coverage | Go library, but very heavy memory footprint |
| gobuster | Active brute-force | ⚡ Fast | Wordlist only | CLI only, no library API |
| knock | Passive | Moderate | Limited | Python only |

**✅ DECISION: subfinder v2** as Go library
- Import directly into Discovery Engine — no subprocess calls
- Passive-only: won't trigger IDS/WAF alerts on bank infrastructure
- Configurable via Go struct: API keys for SecurityTrails, Shodan, VirusTotal, Censys
- Output: channel of discovered subdomains, consumed by goroutine

**Supplementary: dnsx** (ProjectDiscovery) for active DNS resolution
- Resolves A/AAAA/CNAME/MX for all discovered subdomains
- Concurrent: 10,000+ resolutions/sec using goroutine pool
- Import: `github.com/projectdiscovery/dnsx/libs/dnsx`

### 1.2 Certificate Transparency Log Mining

| Candidate | Method | Rate Limit | Reliability |
|-----------|--------|------------|-------------|
| **subfinder's built-in CT** | Integrated | N/A (handled internally) | High |
| crt.sh JSON API | HTTP GET `/?q=%25.{domain}&output=json` | ~5 req/min (strict) | Unstable under load |
| Google CT API (Pilot/Argon/Xenon) | Paginated merkle tree walk | Higher throughput | Complex implementation |
| Censys Search API | Authenticated REST | 250/month (free) | Reliable |

**✅ DECISION: subfinder handles CT internally** (crt.sh, Censys, Facebook CT)
- **Supplementary**: Direct crt.sh JSON API call with exponential backoff (2s, 4s, 8s) for domains where subfinder returns incomplete results
- Parse `name_value` field from JSON response, deduplicate with subfinder results

### 1.3 ASN/BGP IP Range Enumeration

| Candidate | Function | Implementation |
|-----------|----------|----------------|
| **asnmap** (ProjectDiscovery) | ASN → IP prefix mapping | Go library: `github.com/projectdiscovery/asnmap` |
| RIPE NCC RIPEstat API | ASN details, routing history | REST API (free, no key, 1000 req/day) |
| Team Cymru DNS | IP → ASN reverse lookup | DNS TXT query to `origin.asns.cymru.com` |
| **ipinfo.io API** | IP → ASN/org enrichment | REST API (50k req/month free) |

**✅ DECISION: asnmap** (Go library) + **RIPE NCC RIPEstat** (REST API)
- asnmap: Given a bank's known ASN, enumerate all IP prefixes → discover shadow infrastructure
- RIPEstat: supplementary validation + routing history
- ipinfo.io: for geolocation enrichment (org name, city, country) — used later in asset metadata
- **Geolocation DB**: MaxMind GeoLite2-City (offline `.mmdb` file) via `oschwald/geoip2-golang`

### 1.4 Port Scanning

| Candidate | Language | Speed | Root Required | Library API |
|-----------|----------|-------|---------------|-------------|
| **naabu v2** (ProjectDiscovery) | Go | ~50k ports/sec | SYN: yes, CONNECT: no | ✅ `github.com/projectdiscovery/naabu/v2/pkg/runner` |
| masscan | C | ~10M pkts/sec | Yes | ❌ CLI only (subprocess) |
| Nmap | C | Variable (tunable) | SYN: yes | ❌ CLI (or nmap Go wrapper) |
| zgrab2 | Go | Moderate | No | ✅ Library |

**✅ DECISION: naabu v2** as Go library
- SYN scan mode (requires `CAP_NET_RAW` container capability) for speed
- Fallback: CONNECT scan mode if running unprivileged
- Configurable via `runner.Options`: host list, port range (default top 1000), rate limiting, timeout
- Result callback: `OnResult func(r *result.Result)` — stream results as they arrive
- Integration: feed open ports into httpx for HTTP service detection

### 1.5 HTTP Service Probing & Technology Fingerprinting

| Candidate | Function | Integration |
|-----------|----------|-------------|
| **httpx** (ProjectDiscovery) | HTTP/HTTPS probing, tech detection, status codes, titles, CDN detection | Go library: `github.com/projectdiscovery/httpx` |
| Wappalyzer | Technology fingerprinting | Node.js library / API |
| WhatWeb | Web scanner | Ruby CLI |

**✅ DECISION: httpx** as Go library
- Probes all open HTTP/HTTPS ports from naabu results
- Detects: web server (nginx/Apache/IIS), response headers, CDN (Akamai/Cloudflare), WAF
- TLS certificate summary (quick pre-check before deep Crypto Inspector analysis)
- JSON output → feed directly into asset records

### 1.6 Deduplication & Confidence Scoring

**Algorithm**: Hash-based deduplication with composite key
- **Key**: `SHA256(normalize(hostname) + resolved_ip + port)`
- **Confidence Score**: `count(methods_that_found_this_asset) / total_methods * 100`
  - Found by 1 method → 20% confidence
  - Found by all 5 methods → 100% confidence
- Implementation: Go `sync.Map` for concurrent-safe deduplication across goroutines

### 1.7 Orchestration Within Discovery Engine

All five enumeration methods run as **parallel goroutine groups** using `errgroup.Group`:
```
errgroup.Group
├── goroutine 1: subfinder (subdomain enum)
├── goroutine 2: crt.sh direct API (CT supplement)
├── goroutine 3: asnmap + RIPEstat (ASN/BGP)
├── goroutine 4: naabu (port scan on discovered IPs)
└── goroutine 5: httpx (HTTP probing on open ports)
```
- goroutines 4 and 5 block on goroutines 1-3 (need IPs first) — use Go channels for synchronization
- All results funnel into a shared deduplication channel → bulk POST to Asset Registry

---

## Phase 2 — Crypto Inspector (Python)

### 2.1 TLS Handshake & Cipher Suite Enumeration

| Candidate | Depth | Speed | PQC Detection | Python API |
|-----------|-------|-------|---------------|------------|
| **SSLyze** | Deep (ciphers, vulns, certs, ROBOT, Heartbleed) | Moderate (built-in concurrency) | Partial (TLS 1.3 groups) | ✅ `Scanner`, `ServerScanRequest`, `ScanCommand` |
| tlsx (ProjectDiscovery) | Moderate | Fast | Yes (TLS key_share) | ❌ Go CLI (subprocess) |
| testssl.sh | Very deep | Slow (bash) | Yes | ❌ Bash script |
| `ssl` stdlib | Low-level | Fast | Manual | ✅ but requires custom implementation |

**✅ DECISION: SSLyze** (primary) + **custom `ssl` module probe** (for PQC-specific detection)

**SSLyze scan commands to use:**
1. `ScanCommand.SSL_2_0_CIPHER_SUITES` through `TLS_1_3_CIPHER_SUITES` — full cipher enumeration
2. `ScanCommand.CERTIFICATE_INFO` — full cert chain + OCSP stapling + CT log status
3. `ScanCommand.ROBOT` — detect ROBOT vulnerability (RSA padding oracle)
4. `ScanCommand.HEARTBLEED` — Heartbleed vulnerability
5. `ScanCommand.SESSION_RENEGOTIATION` — detect insecure renegotiation
6. `ScanCommand.HTTP_HEADERS` — HSTS, Expect-CT, HPKP (certificate pinning)

**Concurrency model:**
- SSLyze `Scanner` class handles its own thread pool (default 10 concurrent scans)
- Wrap in `asyncio` event loop: `loop.run_in_executor(ThreadPoolExecutor(50), scan_batch)`
- Batch assets in groups of 50 for parallel SSLyze scanning

### 2.2 Deep Certificate Parsing

**✅ DECISION: `cryptography` (PyCA)** — `pip install cryptography`

Extraction fields per certificate:
| Field | Method |
|-------|--------|
| Subject CN | `cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)` |
| SAN list | `cert.extensions.get_extension_for_class(SubjectAlternativeName)` |
| Issuer | `cert.issuer` |
| Valid From/To | `cert.not_valid_before_utc` / `cert.not_valid_after_utc` |
| Public Key Type | `isinstance(cert.public_key(), (rsa.RSAPublicKey, ec.EllipticCurvePublicKey))` |
| Key Size | `cert.public_key().key_size` |
| Signature Algorithm OID | `cert.signature_algorithm_oid` |
| SHA-256 Fingerprint | `cert.fingerprint(hashes.SHA256())` |
| CT Poison Extension | Check for OID `1.3.6.1.4.1.11129.2.4.3` |
| OCSP Endpoint | `cert.extensions.get_extension_for_class(AuthorityInformationAccess)` |

**Certificate chain reconstruction:**
- SSLyze returns the full chain (leaf → intermediates)
- Root CA: look up in `certifi` trust store or system CA bundle
- Validate chain: `cryptography.x509.verification` (Python 3.12+)

### 2.3 Post-Quantum Cryptography (PQC) Detection

This is a **differentiating capability** — no mainstream scanning tool does this comprehensively yet.

**Three-layer detection strategy:**

**Layer 1 — TLS Key Exchange Detection (runtime)**
- Use Python `ssl` module with OpenSSL 3.5+ (compiled with oqs-provider)
- Attempt TLS 1.3 handshake requesting PQC groups: `X25519MLKEM768`, `MLKEM768`
- Check `SSLSocket.shared_ciphers()` and `SSLSocket.cipher()` for PQC identifiers
- Positive detection: key_share extension contains IANA code `0x11ec` (X25519MLKEM768)

**Layer 2 — Certificate Signature Algorithm (static)**
- Parse certificate's `signature_algorithm_oid` against NIST PQC OID table:

| Algorithm | OID | NIST Level |
|-----------|-----|------------|
| ML-DSA-44 | `2.16.840.1.101.3.4.3.17` | 2 |
| ML-DSA-65 | `2.16.840.1.101.3.4.3.18` | 3 |
| ML-DSA-87 | `2.16.840.1.101.3.4.3.19` | 5 |
| SLH-DSA-SHA2-128s | `2.16.840.1.101.3.4.3.20` | 1 |
| SLH-DSA-SHA2-256f | `2.16.840.1.101.3.4.3.27` | 5 |

**Layer 3 — Handshake Size Heuristic (passive)**
- Classical TLS 1.3 ClientHello: ~250 bytes
- PQC hybrid ClientHello: ~1,500+ bytes (ML-KEM public key adds ~1,300 bytes)
- If ServerHello key_share > 1,000 bytes → likely PQC hybrid negotiation

**Libraries:**
- `liboqs-python` — for local PQC signature verification (validate ML-DSA signed certs)
- `oqs-provider` for OpenSSL 3 — enables PQC TLS handshakes from Python's `ssl` module

### 2.4 API Authentication Fingerprinting

| Detection Target | Method | Library |
|-----------------|--------|---------|
| JWT Bearer token | Check `Authorization: Bearer` header pattern | `PyJWT` (decode header without verification: `jwt.get_unverified_header()`) |
| JWT algorithm | Parse `alg` field from JWT header | `PyJWT` |
| OIDC discovery | GET `/.well-known/openid-configuration` → extract `jwks_uri` | `httpx` (async HTTP client) + `authlib` |
| mTLS | Check if server requests client certificate during handshake | `ssl.SSLSocket.getpeercert()` + check `CertificateRequest` message |
| API Key | Check for `X-API-Key`, `Authorization: ApiKey` headers in responses/docs | HTTP header inspection |
| HMAC-signed | Check for `X-Signature`, `X-Hmac` headers | HTTP header pattern matching |

**✅ DECISION: PyJWT** + **httpx** + custom header inspection logic

---

## Phase 3 — CBOM Service (Python)

### 3.1 CycloneDX CBOM Generation

**✅ DECISION: `cyclonedx-python-lib`** — official CycloneDX library
- `pip install cyclonedx-python-lib`
- Supports CycloneDX specification **1.6** (latest, includes CBOM extensions)
- Create BOM → add Components → set Properties → serialize to JSON

**Component mapping:**

| Detected Item | CycloneDX Component Type | Properties |
|---------------|--------------------------|------------|
| TLS cipher suite | `ComponentType.CRYPTOGRAPHIC_ASSET` | `nistQuantumSecurityLevel`, `algorithm`, `keyLength` |
| Certificate | `ComponentType.CRYPTOGRAPHIC_ASSET` | `keyType`, `validTo`, `issuer`, `fingerprint` |
| Crypto library (OpenSSL ver) | `ComponentType.LIBRARY` | `version`, `pqcSupport` |
| Key exchange algorithm | `ComponentType.CRYPTOGRAPHIC_ASSET` | `algorithm`, `nistQuantumSecurityLevel` |
| Signature algorithm | `ComponentType.CRYPTOGRAPHIC_ASSET` | `algorithm`, `nistQuantumSecurityLevel` |

### 3.2 NIST Quantum Security Level Assignment

Static lookup table — no computation needed:

| Algorithm Family | Specific Algorithm | NIST Level | Quantum Status |
|------------------|--------------------|------------|----------------|
| RSA | RSA-2048 | 0 | ❌ Vulnerable (Shor's) |
| RSA | RSA-4096 | 0 | ❌ Vulnerable (Shor's) |
| ECDH/ECDSA | P-256 | 0 | ❌ Vulnerable (Shor's) |
| ECDH/ECDSA | P-384 | 0 | ❌ Vulnerable (Shor's) |
| AES | AES-128-GCM | 1 | ✅ Safe (Grover halves security) |
| AES | AES-256-GCM | 5 | ✅ Safe |
| SHA | SHA-256 | 1 | ✅ Safe |
| SHA | SHA-384 | 3 | ✅ Safe |
| ML-KEM | ML-KEM-512 | 1 | ✅ PQC |
| ML-KEM | ML-KEM-768 | 3 | ✅ PQC |
| ML-KEM | ML-KEM-1024 | 5 | ✅ PQC |
| ML-DSA | ML-DSA-44 | 2 | ✅ PQC |
| ML-DSA | ML-DSA-65 | 3 | ✅ PQC |
| ML-DSA | ML-DSA-87 | 5 | ✅ PQC |
| SLH-DSA | SLH-DSA-128s | 1 | ✅ PQC |
| SLH-DSA | SLH-DSA-256f | 5 | ✅ PQC |
| Hybrid | X25519+ML-KEM-768 | 3 | ⚡ Hybrid |
| ChaCha20 | ChaCha20-Poly1305 | N/A (symmetric) | ✅ Safe |
| 3DES | 3DES-CBC | 0 | ❌ Deprecated (weak key length) |

### 3.3 CVE Cross-Referencing

| Source | API | Rate Limit | Coverage |
|--------|-----|------------|----------|
| **NVD API v2** (NIST) | `https://services.nvd.nist.gov/rest/json/cves/2.0` | 5 req/30s (no key), 50 req/30s (with key) | Comprehensive, authoritative |
| **OSV.dev** | `https://api.osv.dev/v1/query` | Generous | Open-source ecosystems (PyPI, npm, Go) |
| VulnCheck | Commercial API | N/A | Enhanced NVD with exploit data |

**✅ DECISION: NVD API v2** (primary) + **OSV.dev** (supplementary for libraries)
- Map detected library versions to CPE identifiers → query NVD
- Example: `OpenSSL 1.1.1w` → `cpe:2.3:a:openssl:openssl:1.1.1w:*:*:*:*:*:*:*`
- Cache CVE results in PostgreSQL (CVEs don't change once published)

---

## Phase 4 — Risk Engine (Python)

### 4.1 Mosca's Inequality — Core Risk Model

**The equation**: `X + Y > Z` → asset is at quantum risk

| Variable | Meaning | Source | Default Values |
|----------|---------|--------|----------------|
| **X** (Migration Time) | Estimated time to migrate this asset to PQC | Computed from: `playbook_effort_hours / team_capacity + vendor_dependency_delay` | 6-36 months depending on asset type |
| **Y** (Data Shelf Life) | How long data must remain confidential | Asset type lookup table (configurable per org) | See table below |
| **Z** (CRQC Arrival) | Time until quantum computers can break PKC | Probability distribution from GRI survey | 3 scenarios |

**Data shelf life defaults:**

| Asset Type | Default Y (years) | Rationale |
|------------|-------------------|-----------|
| SWIFT endpoint | 10 | Financial messages, regulatory retention |
| Core Banking API | 20 | Account data, lifelong confidentiality |
| Internet Banking Portal | 5 | Session data, relatively short-lived |
| UPI Gateway | 3 | Transaction data, moderate shelf life |
| OTP/2FA endpoint | 0.01 (~4 days) | Ephemeral authentication tokens |
| Mobile Banking Backend | 7 | Mix of session + PII data |

**CRQC arrival scenarios (from Global Risk Institute 2024 survey):**

| Scenario | Year | Basis |
|----------|------|-------|
| Pessimistic | 2029 | Gidney's 2025 improvements, aggressive estimates |
| Median | 2032 | GRI median expert consensus |
| Optimistic | 2035 | Conservative estimate, slow hardware progress |

**✅ Implementation: `numpy`** — vectorized computation across all assets
- All assets processed in a single numpy array operation (no Python loops)
- Mosca check: `exposed = (X + Y) > Z` where Z is tested against all three scenarios

### 4.2 Monte Carlo CRQC Probability Simulation

For the advanced probabilistic risk view (Risk Intelligence page sliders):

**Algorithm:**
1. Model CRQC arrival as a **log-normal distribution** fitted to GRI expert survey data
   - Parameters: μ = ln(2032), σ = 0.15 (captures 2029-2035 range at 95% CI)
2. Draw N=10,000 samples from this distribution
3. For each sample Z_i: compute `exposed_i = (X + Y) > Z_i`
4. P(exposed) = `sum(exposed) / N` — continuous probability per asset

**Libraries:**
- `numpy.random.lognormal()` — sampling
- `scipy.stats.lognorm` — PDF/CDF for the slider visualization

**Performance**: 10,000 samples × 1,000 assets = 10M operations → <100ms on numpy

### 4.3 Quantum Risk Score (0–1000)

**Five-factor weighted scoring model:**

| Factor | Weight | Input Source | Scoring Method |
|--------|--------|-------------|----------------|
| PQC Algorithm Deployment | 30% | CBOM components | `(pqc_components / total_components) × 300` |
| HNDL Exposure Reduction | 25% | Cipher analysis | `(1 - P(exposed_to_hndl)) × 250` |
| Crypto-Agility Readiness | 15% | Compliance agility score | `(agility_score / 100) × 150` |
| Certificate Hygiene | 10% | Cert chain analysis | Weighted check: key length ≥ 2048 (25%), valid chain (25%), CT logged (25%), not expiring soon (25%) → scale to 100 |
| Regulatory Compliance | 10% | Compliance Service | `(compliance_checks_passed / total_checks) × 100` |
| Migration Velocity | 10% | Migration Service | `(assets_migrated_last_90d / total_critical_assets) × 100` |

**Final score**: `sum(factor_score × weight)` → 0–1000 integer

**Classification thresholds:**

| Score | Classification |
|-------|---------------|
| 0–199 | Quantum Ready 🟢 |
| 200–399 | Quantum Aware 🔵 |
| 400–599 | Quantum at Risk 🟡 |
| 600–799 | Quantum Vulnerable 🟠 |
| 800–1000 | Quantum Critical 🔴 |

### 4.4 HNDL Exposure Window Computation

**Algorithm** (per asset):
```
earliest_vulnerable_scan = min(scan_dates where cipher was quantum_vulnerable)
crqc_arrival = Z (selected scenario)
data_shelf_life = Y

hndl_window = {
  "harvest_start": earliest_vulnerable_scan,
  "harvest_end": crqc_arrival,
  "decrypt_risk_start": crqc_arrival,
  "decrypt_risk_end": crqc_arrival + data_shelf_life,
  "is_currently_exposed": today < crqc_arrival AND cipher_is_quantum_vulnerable
}
```
- Implementation: Python `datetime` arithmetic, numpy for batch processing
- Stored in ClickHouse for time-series visualization

### 4.5 TNFL (Trust Now, Forge Later) Risk Assessment

**Algorithm**: Rule-based boolean evaluation per asset

| Check | Condition | Severity |
|-------|-----------|----------|
| SWIFT signing | Asset type = "SWIFT Endpoint" AND signature_algo ∈ {RSA, ECDSA} | CRITICAL |
| UPI authorization | Asset type = "UPI Gateway" AND signature_algo ∈ {RSA, ECDSA} | CRITICAL |
| Code/firmware signing | Asset serves software/firmware updates | HIGH |
| Certificate issuance | Asset is a CA or issues certs | HIGH |
| JWT signing | JWT algo ∈ {RS256, RS384, RS512, ES256, ES384} | MEDIUM |
| mTLS auth | Asset uses client certificate verification | MEDIUM |

Output: `tnfl_risk: bool`, `tnfl_severity: str`, `tnfl_contexts: list[str]`

---

## Phase 5 — Compliance Service + Graph Service (Parallel)

### 5.1 Compliance Rule Engine

Pure **rule-based evaluation** — no ML, no probabilistic computation.

**FIPS Compliance Checks:**

| Check | Logic | Data Source |
|-------|-------|-------------|
| FIPS 203 (ML-KEM) deployed | `any(component.algorithm == "ML-KEM-*" for component in cbom)` | CBOM Service |
| FIPS 204 (ML-DSA) deployed | `any(component.algorithm == "ML-DSA-*" for component in cbom)` | CBOM Service |
| FIPS 205 (SLH-DSA) available | `any(component.algorithm == "SLH-DSA-*" for component in cbom)` | CBOM Service |
| TLS 1.3 enforced | `asset.tls_version == "TLSv1.3" AND NOT supports_tls_1_2_downgrade` | Crypto Inspector |
| Forward Secrecy | `asset.key_exchange ∈ {"ECDHE", "DHE", "ML-KEM"}` | Crypto Inspector |
| Hybrid mode active | `asset.key_exchange contains "X25519MLKEM768"` | Crypto Inspector |
| Classical deprecated | `NOT any(component.algorithm ∈ {"RSA", "ECDHE", "ECDSA"} for component in cbom)` | CBOM Service |

**Crypto-Agility Score (0–100):**

| Factor | Weight | Detection Method |
|--------|--------|-----------------|
| Dynamic cipher negotiation | 20 | TLS: check if server preference vs client preference in SSLyze output |
| Automated cert renewal | 20 | Detect ACME (Let's Encrypt), check cert age < 90 days pattern |
| Automated key rotation | 20 | Compare cert `notBefore` across historical scans, detect rotation frequency |
| Cryptographic abstraction layer | 20 | Detect HSM usage (from manual input), detect crypto library version diversity |
| Documented owner + SLA | 20 | Manual input field (org provides per-asset ownership data) |

### 5.2 Graph Service — Neo4j Topology & Blast Radius

**✅ DECISION: Neo4j 5** + **APOC plugin** + **neo4j Python driver**

**Graph construction algorithm** (per scan):
1. Pull all assets, certs, IPs from Asset Registry + CBOM Service (internal REST)
2. For each asset: `MERGE (d:Domain {id: asset_id})` — upsert node
3. For each IP: `MERGE (ip:IP {address: ip_addr})` — upsert node
4. For each cert: `MERGE (c:Certificate {fingerprint: sha256_fp})` — upsert node
5. Create edges: `(d)-[:RESOLVES_TO]->(ip)`, `(d)-[:USES_CERTIFICATE]->(c)`, `(c)-[:ISSUED_BY]->(ca)`
6. Compute blast radius per certificate:

**Blast Radius Algorithm:**
```cypher
// For each certificate, count all domains that would be affected
MATCH (c:Certificate {fingerprint: $fp})
OPTIONAL MATCH (c)<-[:USES_CERTIFICATE]-(d:Domain)
OPTIONAL MATCH (c)-[:CHAINS_TO*0..5]->(parent:Certificate)<-[:USES_CERTIFICATE]-(d2:Domain)
WITH c, collect(DISTINCT d) + collect(DISTINCT d2) AS affected
SET c.blast_radius = size(affected)
RETURN c.fingerprint, c.blast_radius
```

- Uses APOC `apoc.path.subgraphNodes()` for complex multi-hop traversals
- Blast radius is stored as a property on the Certificate node
- Frontend queries `GET /graph/topology` → receives JSON: `{nodes: [...], edges: [...]}`
- D3.js renders: node size ∝ blast_radius, node color ∝ PQC readiness

---

## Phase 6 — Post-Scan Services

### 6.1 AI Service — RAG Chatbot & Report Generation

#### LLM Selection

| Model | Strengths | Weaknesses | License |
|-------|-----------|------------|---------|
| **Qwen 2.5 7B** ✅ | Best at structured JSON, code, data extraction; disciplined output formatting | Slightly weaker at creative prose | Apache 2.0 |
| LLaMA 3.1 8B | Best all-rounder, natural prose, broad reasoning | Occasionally needs stricter JSON prompting | Meta Community |
| Mistral 7B v0.3 | Efficient, good for fine-tuning | Weakest at structured output among the three | Apache 2.0 |

**✅ DECISION: Qwen 2.5 7B** (primary) via Ollama
- `ollama pull qwen2.5:7b`
- Use **Ollama `format: "json"` mode** for guaranteed valid JSON output
- For executive summaries (prose-heavy): optionally switch to LLaMA 3.1 8B
- Hardware: single A100 40GB or 2× RTX 4090 (24GB each) sufficient

#### Embedding Model

| Model | Dimensions | Context | MTEB Score | Size |
|-------|------------|---------|------------|------|
| **nomic-embed-text v1.5** ✅ | 768 | 8192 tokens | Strong (top-10 for size class) | ~275MB |
| bge-m3 | 1024 | 8192 tokens | Higher | ~1.2GB |
| all-MiniLM-L6-v2 | 384 | 512 tokens | Moderate | ~80MB |

**✅ DECISION: nomic-embed-text v1.5** via Ollama
- Best balance: strong retrieval quality at modest size
- 8192 token context window — enough for CBOM summaries and playbook chunks
- `ollama pull nomic-embed-text`

#### Vector Database

| Candidate | Language | Filtering | Self-Hosted | Production-Grade |
|-----------|----------|-----------|-------------|-----------------|
| ChromaDB | Python | Basic | ✅ | ⚠️ Degrades at scale |
| **Qdrant** ✅ | Rust | Excellent (native) | ✅ Docker | ✅ Proven at millions of vectors |
| Weaviate | Go | Excellent (hybrid) | ✅ Docker | ✅ But heavier |

**✅ DECISION: Qdrant** for production, ChromaDB for MVP/prototyping
- Qdrant: `docker run -p 6333:6333 qdrant/qdrant`
- Python client: `pip install qdrant-client`
- Superior payload (metadata) filtering: filter by `org_id`, `asset_type`, `risk_level` while searching
- Scales to millions of vectors with consistent latency

#### RAG Framework

| Framework | Purpose | Fit |
|-----------|---------|-----|
| **LlamaIndex** ✅ | Purpose-built for RAG (retrieval + structured Q&A) | ✅ Excellent |
| LangChain | General-purpose agent framework | ⚠️ Overkill for pure RAG |

**✅ DECISION: LlamaIndex**
- `pip install llama-index llama-index-llms-ollama llama-index-vector-stores-qdrant`
- Better document chunking, query engine, response synthesis
- Native Ollama + Qdrant integrations
- Structured output mode for JSON report generation

### 6.2 Reporting Service — PDF Generation

| Candidate | Engine | Chart Support | Complexity | Quality |
|-----------|--------|---------------|------------|---------|
| **WeasyPrint** ✅ (simple) | Cairo | SVG/PNG embeds | Low | Good for text-heavy |
| **Playwright** ✅ (complex) | Chromium | Full JS/CSS3 | Medium | Perfect fidelity |
| ReportLab | Custom | Manual drawing | High | Full control |
| wkhtmltopdf | WebKit | Basic | Low | ⚠️ Deprecated/unmaintained |

**✅ DECISION: Dual approach**
- **WeasyPrint** for text-heavy regulatory reports (fast, lightweight)
- **Playwright** for chart-heavy dashboards and executive reports (Chromium rendering)
- Chart generation: **matplotlib** → SVG → embed in Jinja2 HTML template
- Template engine: **Jinja2** for both paths

### 6.3 Migration Service — Roadmap & Gantt Generation

**Algorithm for prioritized migration roadmap:**

```
for each asset:
  priority_score = quantum_risk_score × (1 / crypto_agility_score)
  est_duration = sum(playbook.effort_hours for playbook in applicable_playbooks)
  est_start = today + (priority_rank × parallel_capacity_factor)
  est_complete = est_start + est_duration
  
  if est_complete > crqc_arrival_pessimistic:
    flag = "CRITICAL — completion after CRQC"
```

- Priority sorted by: Quantum Critical first, then by TNFL risk, then by HNDL exposure
- Gantt data: JSON array of `{asset_id, est_start, est_complete, phase, risk_level}`
- Playbook matching: rule-based join on `asset.tech_stack` → `playbook.stack_category`

### 6.4 Notification Service

| Component | Tool | Notes |
|-----------|------|-------|
| Email delivery | `aiosmtplib` (async) or SendGrid SDK | Async SMTP for on-premise; SendGrid for cloud |
| Webhook delivery | `httpx` (async HTTP client) | Retry with exponential backoff (3 attempts) |
| Rule engine | Custom Python if-then rules | Evaluate scan results against alert_rules table |
| Real-time push | Redis pub/sub → WebSocket Hub | Channel: `scan:events:{scan_id}` |

---

## Infrastructure — Supporting Technology Decisions

### Full-Text Search: Elasticsearch 8

**✅ Confirmed** — best for complex aggregation queries across assets
- Python client: `elasticsearch[async]` (async support)
- Index mapping: mirrors `assets` table + enriched fields (risk, TLS, cipher)
- Use for: global search bar (algorithm name, CVE, cert fingerprint, IP, domain)
- Sync strategy: SQLAlchemy `after_insert`/`after_update` event listener → async ES index

### Time-Series Database: ClickHouse

**✅ Confirmed** — best for high-volume analytical queries on risk score trends
- Python client: `clickhouse-driver` (native TCP protocol, fastest)
- Async alternative: `asynch` (async ClickHouse client)
- Table engine: `MergeTree()` partitioned by `toYYYYMM(computed_at)`
- Compression: 10-100x for repetitive risk score data
- Query pattern: "Show risk score trend for asset X over last 12 months"

### Graph Database: Neo4j 5

**✅ Confirmed** — Cypher query language is ideal for topology traversal
- Python driver: `neo4j` (official, Bolt protocol, async support)
- APOC plugin: `apoc.path.subgraphNodes()`, `apoc.path.spanningTree()`
- GDS library: for large-scale graph analytics if >100k nodes
- Indexing: `CREATE INDEX FOR (c:Certificate) ON (c.fingerprint)` for fast lookups

### Object Storage: MinIO

**✅ Confirmed** — S3-compatible self-hosted storage
- Python client: `boto3` with MinIO endpoint
- Pre-signed URLs for secure, time-limited report downloads
- Bucket structure: `cbom/{org_id}/{scan_id}/`, `reports/{org_id}/`

---

## Summary: Complete Tool & Library Manifest

### Go Services (Discovery Engine)

| Function | Library | Import Path |
|----------|---------|-------------|
| Subdomain enumeration | subfinder v2 | `github.com/projectdiscovery/subfinder/v2` |
| DNS resolution | dnsx | `github.com/projectdiscovery/dnsx` |
| Port scanning | naabu v2 | `github.com/projectdiscovery/naabu/v2` |
| HTTP probing | httpx | `github.com/projectdiscovery/httpx` |
| ASN mapping | asnmap | `github.com/projectdiscovery/asnmap` |
| Geolocation | geoip2-golang | `github.com/oschwald/geoip2-golang` |
| Kafka client | kafka-go | `github.com/segmentio/kafka-go` |
| HTTP framework | Gin | `github.com/gin-gonic/gin` |
| DNS library | miekg/dns | `github.com/miekg/dns` |

### Python Services (All Others)

| Function | Library | pip Package |
|----------|---------|-------------|
| TLS scanning | SSLyze | `sslyze` |
| Certificate parsing | cryptography (PyCA) | `cryptography` |
| PQC detection | liboqs-python + oqs-provider | `liboqs-python` |
| CBOM generation | CycloneDX Python lib | `cyclonedx-python-lib` |
| Risk computation | NumPy + SciPy | `numpy`, `scipy` |
| Graph database | Neo4j driver | `neo4j` |
| Elasticsearch | Elasticsearch client | `elasticsearch[async]` |
| ClickHouse | ClickHouse driver | `clickhouse-driver` |
| Kafka client | Confluent Kafka | `confluent-kafka` |
| Vector database | Qdrant client | `qdrant-client` |
| RAG framework | LlamaIndex | `llama-index` |
| LLM interface | Ollama | `ollama` (via LlamaIndex adapter) |
| JWT parsing | PyJWT | `pyjwt` |
| PDF generation | WeasyPrint + Playwright | `weasyprint`, `playwright` |
| HTML templates | Jinja2 | `jinja2` |
| HTTP client | httpx | `httpx` |
| Async email | aiosmtplib | `aiosmtplib` |
| Redis client | redis + hiredis | `redis[hiredis]` |
| Scheduling | APScheduler | `apscheduler` |
| Workflow | Temporal SDK | `temporalio` |
| Geolocation | geoip2 | `geoip2` |
| API framework | FastAPI | `fastapi`, `uvicorn[standard]` |
| ORM | SQLAlchemy 2.0 | `sqlalchemy[asyncio]` |
| Migrations | Alembic | `alembic` |
| Validation | Pydantic v2 | `pydantic` |
| S3/MinIO | boto3 | `boto3` |

### External Services (Self-Hosted)

| Service | Image | Purpose |
|---------|-------|---------|
| PostgreSQL 16 | `postgres:16` | Primary relational data store |
| Redis 7 | `redis:7-alpine` | Cache + pub/sub |
| Apache Kafka | `confluentinc/cp-kafka` | Event streaming |
| Temporal | `temporalio/server` | Workflow orchestration |
| Neo4j 5 | `neo4j:5` | Graph database |
| ClickHouse | `clickhouse/clickhouse-server` | Time-series analytics |
| Elasticsearch 8 | `elasticsearch:8` | Full-text search |
| MinIO | `minio/minio` | Object storage |
| Ollama | `ollama/ollama` | Local LLM inference |
| Qdrant | `qdrant/qdrant` | Vector database |
| Kong OSS | `kong:3` | API gateway |
| Prometheus | `prom/prometheus` | Metrics |
| Grafana | `grafana/grafana` | Dashboards |
| Loki | `grafana/loki` | Log aggregation |
| Jaeger | `jaegertracing/all-in-one` | Distributed tracing |

---

*This document should be treated as the definitive algorithm and tooling reference for implementation. All code written for QuShield-PnB should use the libraries and approaches specified here unless a technical blocker is discovered during implementation, in which case this document should be updated with the filed ADR.*
