# SCRATCHPAD — Algorithm & Library Research Intermediate Notes

## PHASE 1: Discovery Engine (Go)

### 1A. DNS Subdomain Enumeration
- **Winner: subfinder v2** (projectdiscovery) — Go library, importable as package `github.com/projectdiscovery/subfinder/v2`
- Alternatives considered: amass (OWASP), gobuster, dnsx
- subfinder is faster, leaner, passive-only (no brute-force noise), uses 50+ data sources (VirusTotal, Shodan, SecurityTrails, Chaos)
- Amass is more comprehensive but 5-10x slower and heavier memory footprint
- **For active DNS resolution**: use `dnsx` (projectdiscovery) — concurrent DNS resolver in Go, resolves A/AAAA/CNAME/MX
- Go DNS library: `miekg/dns` — low-level, used internally by subfinder/dnsx

### 1B. Certificate Transparency Log Mining
- **Primary: subfinder already integrates CT logs** (crt.sh, Censys, etc.)
- **Dedicated CT: crt.sh JSON API** — `https://crt.sh/?q=%25.{domain}&output=json`
  - Rate limit: ~5 req/min (strict), needs backoff
- **Alternative: Google CT API** (Pilot, Argon, Xenon logs) — higher throughput but more complex
- **certstream** (real-time CT stream) — useful for monitoring, not batch discovery
- Decision: subfinder handles CT internally; supplement with direct crt.sh calls with retry/backoff for completeness

### 1C. ASN/BGP Sweep
- **Winner: asnmap** (projectdiscovery) — Go library, maps ASN→IP ranges
  - `github.com/projectdiscovery/asnmap`
- **Data sources**: RIPE NCC RIPEstat API (free, no key), ARIN Whois, BGP.tools
- **Alternative**: Team Cymru ASN lookup (DNS-based, fast)
- For IP→ASN reverse lookup: `ipinfo.io` API (richer org data, requires API key)

### 1D. Passive DNS
- **SecurityTrails API** — historical DNS records, subdomains
- **Shodan API** — host+port+banner data
- Both configurable; subfinder already integrates both as data sources
- For extra depth: `chaos` (projectdiscovery) — their own passive DNS dataset

### 1E. Port Scanning
- **Winner: naabu v2** (projectdiscovery) — Go library, SYN+CONNECT scan
  - `github.com/projectdiscovery/naabu/v2/pkg/runner`
  - SYN scan: ~50k ports/sec, requires root/CAP_NET_RAW
  - CONNECT scan: no root needed, slower
- **Alternative: masscan** — fastest raw scanner (10M+ packets/sec) but C binary, harder to integrate
- **Nmap**: most accurate service detection, but slow for pure port discovery
- **Strategy**: naabu for fast port discovery → httpx for HTTP probing on open ports

### 1F. HTTP Probing & Fingerprinting
- **httpx** (projectdiscovery) — Go library, probes HTTP/HTTPS on discovered ports
  - Detects: web server, tech stack, status codes, content length, title, CDN
  - `github.com/projectdiscovery/httpx`

### 1G. Geolocation
- **geoip2** (MaxMind GeoLite2-City) — offline DB lookups, fast
- **ipinfo.io** — API for richer ASN/org data
- From ROUGH_RESEARCH.md item #10 — confirmed good choice

### 1H. Deduplication
- In-memory Go map with composite key: `(hostname, ip, port)` tuple
- Merge results from all 5 methods, assign confidence score based on how many methods found the asset

---

## PHASE 2: Crypto Inspector (Python)

### 2A. TLS Handshake & Cipher Suite Enumeration
- **Winner: SSLyze** — Python library, industry standard
  - `pip install sslyze`
  - Scan commands: `ScanCommand.SSL_2_0_CIPHER_SUITES` thru `TLS_1_3_CIPHER_SUITES`
  - Also: `CERTIFICATE_INFO`, `ROBOT`, `HEARTBLEED`, `SESSION_RENEGOTIATION`
  - Async-capable, JSON output, per-server concurrent scanning
- **Alternative: tlsx** (projectdiscovery) — Go binary, faster but less deep
- SSLyze gives us cipher negotiation, certificate chain, protocol support, vulnerability checks all in one

### 2B. Certificate Chain Parsing
- **Winner: cryptography (PyCA)** — `pip install cryptography`
  - `x509.load_pem_x509_certificate()` or `load_der_x509_certificate()`
  - Extract: Subject, SAN, Issuer, Valid dates, Public Key (type + size), Signature Algorithm OID, Extensions
  - Supports RSA, ECDSA, Ed25519 key parsing
  - From ROUGH_RESEARCH.md item #4 — confirmed
- **pyOpenSSL**: higher-level but less maintained; use `cryptography` directly
- For PQC detection: check Signature Algorithm OID against NIST PQC OIDs (ML-KEM, ML-DSA, SLH-DSA)

### 2C. Post-Quantum Cryptography Detection
- **oqs-provider** (OpenQuantumSafe) — OpenSSL 3 provider for PQC algorithms
  - Detects: X25519MLKEM768 (IANA 4588/0x11ec), ML-KEM-768, ML-DSA-65
  - Can attempt PQC handshakes with target servers
- **liboqs-python** — wrapper for liboqs C library
  - Not for TLS scanning; for verifying/generating PQC signatures locally
- **Detection strategy**: 
  1. SSLyze enumerates supported cipher suites (classical)
  2. Custom `ssl` module handshake with oqs-provider loaded → attempt PQC groups
  3. Check ClientHello key_share size (ML-KEM adds ~1300 bytes)
  4. Parse certificate Signature Algorithm OIDs for PQC algorithms
- NIST PQC OIDs reference table needed (ML-KEM: 2.16.840.1.101.3.4.4.x, ML-DSA: 2.16.840.1.101.3.4.3.x)

### 2D. JWT/API Auth Detection
- **PyJWT** — extract header without verification to detect algorithm (RS256, ES256, HS256)
- **authlib** — OIDC discovery endpoint parsing (`/.well-known/openid-configuration`)
- HTTP header inspection: check for `Authorization: Bearer`, `X-API-Key`, client cert in mTLS
- OIDC well-known → extract `jwks_uri` → parse key types → detect PQC readiness

### 2E. Concurrency Model
- `asyncio.gather()` + `concurrent.futures.ThreadPoolExecutor`
- TLS handshakes are CPU-bound (RSA operations) — need real OS threads
- Optimal: ThreadPoolExecutor(max_workers=50) for TLS, async for I/O coordination
- SSLyze has its own concurrency — uses `Scanner` class with built-in parallelism

---

## PHASE 3: CBOM Service (Python)

### 3A. CycloneDX CBOM Generation
- **Winner: cyclonedx-python-lib** — official CycloneDX Python library
  - `pip install cyclonedx-python-lib`
  - Creates CycloneDX 1.6 BOMs with components, vulnerabilities, dependencies
  - Supports custom properties including `nistQuantumSecurityLevel` (0-6)
  - Generates JSON and XML output
- **Component types**: `ComponentType.LIBRARY`, `ComponentType.CRYPTOGRAPHIC_ASSET`
- Each algorithm, cert, key → separate CycloneDX component with quantum security level property

### 3B. CVE Cross-Referencing
- **NVD API v2** (NIST) — lookup CVEs by CPE for detected library versions
- **OSV.dev API** — open-source vulnerability database, fast JSON API
- Strategy: map detected `OpenSSL 1.1.1w` → CPE → query NVD → attach as `vulnerabilities[]`

### 3C. NIST Quantum Security Level Assignment
- Static mapping table: algorithm → NIST level
  - RSA-2048 → Level 0 (quantum-vulnerable)
  - AES-128-GCM → Level 1 (symmetric, safe with Grover's doubling)
  - AES-256-GCM → Level 5
  - ML-KEM-768 → Level 3
  - ML-KEM-1024 → Level 5
  - ML-DSA-65 → Level 3
  - SLH-DSA → Level 1-5 (parameter dependent)
  - ECDHE P-256 → Level 0 (quantum-vulnerable)
  - ECDHE P-384 → Level 0 (quantum-vulnerable)

---

## PHASE 4: Risk Engine (Python)

### 4A. Mosca's Theorem Computation
- **Mosca Inequality**: if X + Y > Z → data is at risk
  - X = migration time (estimated from crypto-agility score + playbook effort)
  - Y = data shelf life (asset type defaults: SWIFT=10yr, OTP=0yr, accounts=20yr)
  - Z = CRQC arrival estimate (probability distribution)
- **Implementation**: numpy vectorized computation across all assets
- CRQC arrival modeled as probability distribution (Global Risk Institute 2024 survey):
  - Pessimistic: ~2029, Median: ~2032, Optimistic: ~2035
  - Use scipy.stats for weighted probability (log-normal or beta distribution)

### 4B. Quantum Risk Score (0-1000)
- Five-factor weighted model:
  1. PQC Algorithm Deployment (30%) — from CBOM data
  2. HNDL Exposure Reduction (25%) — cipher vulnerability analysis
  3. Crypto-Agility Readiness (15%) — from compliance agility score
  4. Certificate Hygiene (10%) — key lengths, CT compliance, chain validity
  5. Regulatory Compliance (10%) — FIPS/RBI/SEBI gap
  6. Migration Velocity (10%) — rate of PQC adoption over 90 days
- **numpy** for vectorized scoring across asset portfolio
- **ClickHouse** for time-series storage of risk score history

### 4C. HNDL Exposure Window
- Start: earliest_scan_date (first time asset was seen with quantum-vulnerable cipher)
- Active harvest window: today → CRQC arrival estimate
- Risk horizon: CRQC arrival → CRQC arrival + data_shelf_life
- Simple date arithmetic with Python `datetime` + numpy for batch processing

### 4D. TNFL Risk Assessment
- Boolean flags per asset checking for signature-dependent use cases:
  - SWIFT message signing, UPI authorization, firmware signing, cert issuance
- If asset uses ECDSA/RSA for digital signatures → TNFL flag = True
- Severity multiplier based on signature context (payment = critical, internal = medium)

### 4E. Monte Carlo Simulation (optional advanced)
- For probabilistic CRQC arrival: run N=10,000 samples from CRQC distribution
- For each sample: compute Mosca inequality → probability that asset is exposed
- `numpy.random` for sampling, vectorized across all assets
- Output: P(exposed) per asset as continuous 0-1 value

---

## PHASE 5: Compliance & Graph (parallel)

### 5A. Compliance Engine
- Pure rule-based evaluation — no ML needed
- FIPS checks: OID comparison against NIST FIPS 203/204/205 algorithm identifiers
- TLS 1.3 check: protocol version from SSLyze output
- Forward secrecy: check if negotiated cipher uses DHE/ECDHE
- Crypto-agility score: 5-factor model
  1. Dynamic cipher negotiation (TLS → check if server prefers vs client)
  2. ACME/SCEP auto-renewal (check for Let's Encrypt, ACME headers)
  3. Key rotation automation (detect key age from cert valid_from)
  4. Abstraction layer (detect HSM API, crypto library version)
  5. Documented owner + SLA (manual input field)

### 5B. Graph Service — Neo4j
- **neo4j Python driver** — official, Bolt protocol, async support
  - `pip install neo4j`
- **APOC plugin** — for advanced graph algorithms (blast radius, BFS, path analysis)
  - `apoc.path.subgraphNodes()` — find all nodes reachable from a certificate
  - Variable-length path queries: `MATCH (c:Certificate)-[:DEPENDS_ON*1..10]->(d)`
- **Blast radius algorithm**: 
  - BFS from certificate node → count all reachable Domain/Service nodes
  - Cypher: `MATCH (c:Certificate {fingerprint: $fp})<-[:USES_CERTIFICATE]-(d:Domain) RETURN count(d)`
  - Extended: follow SHARES_CERT_WITH, CHAINS_TO edges
- **Neo4j GDS** (Graph Data Science) — for large-scale graph analytics if needed
- **Frontend export**: Cypher → JSON with nodes[] + edges[] → D3.js force-directed graph

---

## PHASE 6: Post-Scan Services

### 6A. Reporting Service
- **PDF Generation: Playwright** (upgraded from WeasyPrint)
  - WeasyPrint struggles with complex SVG charts and modern CSS
  - Playwright uses Chromium engine → perfect rendering of charts, tables, modern layouts
  - `pip install playwright` + `playwright install chromium`
  - Workflow: Jinja2 HTML template → Playwright `page.pdf()`
  - Alternative: keep WeasyPrint for simple text-heavy reports; Playwright for chart-heavy reports
- **Chart rendering in PDFs**: 
  - Generate charts as SVG/PNG using matplotlib → embed in Jinja2 template
  - Or: generate with Plotly → static image export → embed
- **Scheduling**: APScheduler with PostgreSQL job store (persistent across restarts)
- **MinIO**: S3-compatible, `boto3` client for upload/download/pre-signed URLs

### 6B. AI Service
- **LLM: Qwen 2.5 7B** (primary) + LLaMA 3.1 8B (fallback via Ollama)
  - Qwen 2.5 excels at structured JSON output, code/data tasks — critical for CBOM analysis
  - LLaMA 3.1 better for prose-heavy executive summaries
  - Both run via Ollama: `ollama pull qwen2.5:7b`
  - Apache 2.0 license (Qwen) vs Meta Community License (LLaMA)
  - Single A100 GPU or 2x RTX 4090 sufficient for 7-8B models
- **Vector DB: Qdrant** (upgraded from ChromaDB)
  - ChromaDB: great for prototyping but performance degrades at scale
  - Qdrant: Rust-based, superior filtering, production-grade self-hosted
  - Native Go/Python clients, Docker deployment
  - Hybrid search: vector + metadata filtering (org_id, asset_type)
  - Alternative: stick with ChromaDB for MVP, migrate to Qdrant for production
- **Embedding Model: nomic-embed-text v1.5** (via Ollama confirmed)
  - 768-dim, 8192 context window, runs locally
  - Good MTEB scores for retrieval tasks
  - Alternative: bge-m3 (multi-lingual, slightly better but larger)
- **RAG Framework: LlamaIndex** (over LangChain)
  - LlamaIndex is purpose-built for RAG (retrieval + structured responses)
  - LangChain is more general-purpose agent framework — overkill for this use case
  - LlamaIndex: better document parsing, chunk management, query engine
  - `pip install llama-index llama-index-llms-ollama llama-index-vector-stores-qdrant`
- **SSE Streaming**: FastAPI native `StreamingResponse` + Ollama streaming API

### 6C. Notification Service
- **Email: python-email + aiosmtplib** (async SMTP) or SendGrid SDK
- **Webhooks: httpx** (async HTTP client for webhook delivery)
- **Rule engine**: simple Python rule evaluation (if-then conditions on scan results)
- **Redis pub/sub**: for real-time in-app notifications via WebSocket Hub

---

## INFRASTRUCTURE DECISIONS

### Workflow Orchestration: Temporal
- **temporalio Python SDK** — `pip install temporalio`
- Workflows are Python async functions decorated with `@workflow.defn`
- Activities are individual units of work (e.g., "trigger discovery", "compute risk")
- Durable execution: workflow state survives pod restarts
- Better than Celery: native multi-step workflows, timeouts, retries, state persistence
- Better than Prefect: lower overhead, designed for exactly this use case

### Message Bus: Apache Kafka
- **confluent-kafka** Python client — C-based, fastest Python Kafka library
- **kafka-go** (segmentio) — Go client for Discovery Engine
- Schema: JSON with versioned envelope (not Avro initially, to reduce complexity)
- Alternative: NATS JetStream — simpler but less ecosystem tooling
- Kafka chosen for: durability, replayability, fan-out to multiple consumers

### Search: Elasticsearch 8
- **elasticsearch-py** — official Python client
- Good for: cross-asset search by algorithm, CVE, cert fingerprint, IP
- Alternative: Meilisearch (simpler, faster for small datasets) — but lacks aggregation depth
- Elasticsearch chosen for: aggregation queries, complex filtering, mature ecosystem

### Time-Series: ClickHouse
- **clickhouse-driver** — native Python client (TCP protocol, fast)
- Good for: risk score trends, certificate expiry timelines, scan telemetry
- Alternative: TimescaleDB (PostgreSQL extension) — simpler ops but slower for analytics
- ClickHouse chosen for: columnar compression (10-100x), batch insert performance
