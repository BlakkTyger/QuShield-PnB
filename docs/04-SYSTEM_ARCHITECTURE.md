This requires thinking through communication patterns, data ownership, scan pipeline topology, and API contracts before touching repo structure. Let me work through it systematically.Now the full system design document:

---

## Tech Stack Decision Table

| Concern | Technology | Rationale |
|---|---|---|
| Core service language | **Python 3.12** | Best ecosystem for crypto libs (pyOpenSSL, cryptography), ML, and scanning tooling |
| High-perf network scanning | **Go 1.22** | Discovery Engine only — goroutines for massively concurrent DNS/port scanning |
| Service framework (Python) | **FastAPI** | Async-native, auto-OpenAPI docs, Pydantic schema validation, WebSocket support |
| Service framework (Go) | **Gin** | Lightweight, fast routing, good middleware ecosystem |
| API Gateway | **Kong OSS** | Plugin ecosystem (rate-limit, auth, request transform), upstream load balancing |
| WebSocket / SSE hub | **FastAPI + `asyncio`** | Native async streaming; no third-party WS server needed |
| Async message bus | **Apache Kafka** | Durable, replayable scan event streams; fan-out to multiple consumers |
| Workflow orchestration | **Temporal** | Stateful long-running scan workflows with automatic retry and timeout handling |
| Primary relational DB | **PostgreSQL 16** | Assets, certs, users, compliance records, scan jobs — owned per-service via schema |
| Caching + pub/sub | **Redis 7** | Rate-limit counters, scan job state cache, real-time event pub/sub to WebSocket hub |
| Graph database | **Neo4j 5** | Asset relationship graph, topology, blast radius — Cypher queries |
| Time-series / telemetry | **ClickHouse** | High-ingest scan telemetry, historical risk score trends, certificate expiry timelines |
| Full-text search | **Elasticsearch 8** | Cross-asset search by algorithm name, CVE, cert fingerprint, IP, domain |
| Object storage | **MinIO** | S3-compatible on-premise storage for PDF reports, CBOM JSON files, raw scan artifacts |
| Local LLM inference | **Ollama** | On-premise LLM — no data leaves the bank's network |
| LLM model | **Mistral-7B / LLaMA 3.1-8B** | Runs on a single A100 GPU; good instruction following for report generation |
| Vector database (RAG) | **ChromaDB** | Lightweight, embeds alongside AI service, stores CBOM/scan summaries as embeddings |
| Embedding model | **nomic-embed-text** (via Ollama) | 768-dim embeddings, runs locally, no external API calls |
| Task scheduling | **APScheduler** (inside Reporting Service) | Cron-style scheduled report generation |
| PDF generation | **WeasyPrint** | HTML→PDF with CSS, good table/chart rendering |
| Container runtime | **Docker + Docker Compose** (dev), **Kubernetes** (prod) | Standard container orchestration |
| Service discovery | **Kubernetes DNS** (prod) / **Docker network** (dev) | Services address each other by service name |
| Observability | **Prometheus + Grafana + Loki** | Metrics, dashboards, log aggregation |
| Distributed tracing | **OpenTelemetry + Jaeger** | Trace a scan job across 6 services |
| Secret management | **HashiCorp Vault** | API keys, DB credentials, LLM tokens — no secrets in env files in prod |
| CI/CD | **GitHub Actions** | Per-service pipelines; image push to container registry |
| API documentation | **Auto-generated OpenAPI/Swagger** | Each FastAPI service exposes `/docs` automatically |

---

## Repository Structure

Monorepo with clearly delineated service directories. Every service is a fully self-contained deployable unit — its own `Dockerfile`, `requirements.txt` / `go.mod`, `tests/`, and database migrations. Shared code lives in `packages/` and is imported as a local Python package or Go module.

```
qushield-pnb/
│
├── services/
│   ├── gateway/                     # Kong config + custom plugins
│   ├── websocket-hub/               # Python FastAPI – real-time streaming
│   ├── auth-service/                # Python FastAPI – JWT, RBAC, user mgmt
│   ├── orchestrator/                # Python FastAPI + Temporal – scan job lifecycle
│   ├── discovery-engine/            # Go + Gin – DNS, CT logs, ASN, ports
│   ├── crypto-inspector/            # Python FastAPI – TLS handshake, ciphers, certs
│   ├── cbom-service/                # Python FastAPI – CBOM build + CycloneDX export
│   ├── risk-engine/                 # Python FastAPI – Mosca, HNDL, TNFL scoring
│   ├── asset-registry/              # Python FastAPI – asset CRUD, Elasticsearch sync
│   ├── compliance-service/          # Python FastAPI – FIPS matrix, RBI, agility score
│   ├── graph-service/               # Python FastAPI – Neo4j topology, blast radius
│   ├── migration-service/           # Python FastAPI – roadmap, playbooks, vendors
│   ├── reporting-service/           # Python FastAPI – PDF, CBOM pkg, scheduling
│   ├── ai-service/                  # Python FastAPI – Ollama, ChromaDB, RAG chatbot
│   └── notification-service/        # Python FastAPI – alerts, email, webhooks
│
├── packages/                        # Shared internal libraries (installed via pip -e)
│   ├── qs-models/                   # Pydantic models shared across all Python services
│   │   ├── qs_models/
│   │   │   ├── asset.py
│   │   │   ├── scan.py
│   │   │   ├── cbom.py
│   │   │   ├── risk.py
│   │   │   ├── certificate.py
│   │   │   └── compliance.py
│   │   └── pyproject.toml
│   │
│   ├── qs-kafka/                    # Kafka producer/consumer abstractions
│   │   ├── qs_kafka/
│   │   │   ├── topics.py            # Topic name constants
│   │   │   ├── producer.py
│   │   │   ├── consumer.py
│   │   │   └── schemas/             # Avro/JSON schemas per topic
│   │   └── pyproject.toml
│   │
│   ├── qs-db/                       # SQLAlchemy base models + Alembic migration base
│   │   ├── qs_db/
│   │   │   ├── base.py
│   │   │   ├── session.py
│   │   │   └── mixins.py
│   │   └── pyproject.toml
│   │
│   └── qs-go-shared/                # Go shared utilities (models, Kafka wrapper)
│       ├── models/
│       ├── kafka/
│       └── go.mod
│
├── infrastructure/
│   ├── docker/
│   │   ├── docker-compose.yml           # Full local dev stack
│   │   ├── docker-compose.override.yml  # Developer overrides
│   │   └── docker-compose.prod.yml      # Production reference
│   │
│   ├── kafka/
│   │   ├── topics.yml               # Topic definitions + partition counts
│   │   └── schema-registry/         # Avro schemas for each topic
│   │
│   ├── kong/
│   │   ├── kong.yml                 # Declarative Kong config
│   │   └── plugins/
│   │
│   ├── kubernetes/
│   │   ├── base/                    # Kustomize base manifests per service
│   │   ├── overlays/
│   │   │   ├── dev/
│   │   │   └── prod/
│   │   └── secrets/                 # External Secrets Operator refs (Vault)
│   │
│   ├── monitoring/
│   │   ├── prometheus/
│   │   │   └── prometheus.yml
│   │   ├── grafana/
│   │   │   └── dashboards/
│   │   └── loki/
│   │
│   ├── vault/
│   │   └── policies/
│   │
│   └── temporal/
│       └── workflows/               # Temporal namespace + task queue config
│
├── frontend/                        # Next.js frontend (separate deploy)
│   └── ...
│
├── docs/
│   ├── adr/                         # Architecture Decision Records
│   ├── api/                         # API contracts per service
│   ├── runbooks/                    # Operational runbooks
│   └── data-flow/                   # Sequence diagrams
│
├── scripts/
│   ├── seed-db.py                   # Dev database seeding
│   ├── create-topics.sh             # Kafka topic creation script
│   └── generate-test-cbom.py
│
├── .github/
│   └── workflows/
│       ├── ci-gateway.yml
│       ├── ci-orchestrator.yml
│       ├── ci-discovery.yml         # Go service — different pipeline
│       └── ...                      # One workflow per service
│
├── Makefile                         # Developer convenience commands
└── README.md
```

Each service directory follows this internal structure:

```
services/[service-name]/
├── app/
│   ├── main.py                  # FastAPI app factory + lifespan hooks
│   ├── api/
│   │   ├── v1/
│   │   │   ├── router.py        # Mounts all route groups
│   │   │   └── endpoints/       # One file per resource group
│   │   └── deps.py              # FastAPI dependency injection (DB session, auth)
│   ├── core/
│   │   ├── config.py            # Pydantic Settings (reads from env/Vault)
│   │   ├── events.py            # Startup/shutdown event handlers
│   │   └── security.py          # JWT verification
│   ├── domain/
│   │   ├── models.py            # SQLAlchemy ORM models (service-owned tables)
│   │   ├── schemas.py           # Pydantic request/response schemas
│   │   ├── repository.py        # DB access layer
│   │   └── service.py           # Business logic (pure Python, no FastAPI)
│   ├── kafka/
│   │   ├── producer.py          # Publishes events to topics
│   │   └── consumer.py          # Subscribes to upstream topics
│   └── workers/                 # Background tasks (APScheduler, Temporal workers)
├── migrations/
│   ├── env.py                   # Alembic config
│   └── versions/
├── tests/
│   ├── unit/
│   ├── integration/
│   └── conftest.py
├── Dockerfile
├── requirements.txt
└── pyproject.toml
```

---

## Service-by-Service Deep Dive

### 1 — API Gateway (`services/gateway/`)

**Technology:** Kong OSS with declarative `kong.yml` configuration. No custom code initially — configured entirely through Kong's plugin system.

**Responsibilities:**
- Single entry point for all HTTP traffic from the frontend
- JWT verification via the Kong JWT plugin (tokens issued by Auth Service)
- Per-user and per-organisation rate limiting (Kong Rate Limiting Advanced)
- Request routing to upstream services by path prefix
- Payload size validation (reject oversized scan requests)
- CORS configuration for the frontend origin
- Request/response logging to Loki via the Kong HTTP Logger plugin

**Routing table:**

| Path Prefix | Upstream Service | Auth Required |
|---|---|---|
| `/api/v1/auth/` | `auth-service:8130` | No |
| `/api/v1/scans/` | `orchestrator:8010` | Yes |
| `/api/v1/assets/` | `asset-registry:8120` | Yes |
| `/api/v1/cbom/` | `cbom-service:8040` | Yes |
| `/api/v1/risk/` | `risk-engine:8050` | Yes |
| `/api/v1/compliance/` | `compliance-service:8060` | Yes |
| `/api/v1/topology/` | `graph-service:8070` | Yes |
| `/api/v1/migration/` | `migration-service:8080` | Yes |
| `/api/v1/reports/` | `reporting-service:8090` | Yes |
| `/api/v1/ai/` | `ai-service:8100` | Yes |
| `/api/v1/notifications/` | `notification-service:8110` | Yes |

**WebSocket traffic** routes directly to `websocket-hub:8001` via Kong's WebSocket support (`ws://`). This is kept on a separate port so it bypasses the standard HTTP rate limiting.

**Triggered by:** Every frontend HTTP call. Also ingests CI/CD webhook calls on `/api/v1/scans/trigger`.

---

### 2 — WebSocket Hub (`services/websocket-hub/`)

**Technology:** Python 3.12, FastAPI, `asyncio`, Redis pub/sub.

**Responsibilities:**
- Maintains persistent WebSocket connections with authenticated frontend clients
- Subscribes to Redis `scan:events:{scan_id}` channels
- Forwards scan progress events, phase completions, new asset discoveries, and critical alerts to the connected client in real time
- Multiplexes multiple scan streams to one client (a user may have multiple scans running)
- Sends heartbeat pings every 30 seconds; closes stale connections after 90 seconds of inactivity

**Key data structures:**
```python
# In-memory connection registry (per hub instance)
connections: dict[str, dict[str, WebSocket]] = {
    "user_id": {
        "scan_id_1": websocket_connection,
        "scan_id_2": websocket_connection,
    }
}
```

**Event payload structure (pushed to frontend):**
```json
{
  "event": "scan.phase.complete",
  "scan_id": "sc_abc123",
  "phase": 2,
  "phase_name": "Certificate Intelligence",
  "assets_found": 847,
  "timestamp": "2026-04-09T10:22:44Z"
}
```

**Triggered by:**
- Frontend establishes WebSocket connection on page load with a valid JWT
- Redis pub/sub messages from Orchestrator, Discovery Engine, and Notification Service

---

### 3 — Auth Service (`services/auth-service/`)

**Technology:** Python 3.12, FastAPI, PostgreSQL, `python-jose` (JWT), `passlib` (bcrypt).

**Responsibilities:**
- User registration, login, password management
- JWT issuance (access token 15 min, refresh token 7 days)
- RBAC: roles of `admin`, `analyst`, `developer`, `viewer`
- Organisation management (multi-tenancy — each bank is an org)
- API key management for CI/CD webhook integrations
- Optional: SAML/OIDC SSO integration point for enterprise banks

**Database schema (owns `auth` PostgreSQL schema):**

```
users           (id, email, hashed_password, role, org_id, is_active, created_at)
organisations   (id, name, domain, plan, created_at)
api_keys        (id, user_id, key_hash, label, last_used, expires_at)
refresh_tokens  (id, user_id, token_hash, expires_at, revoked)
```

**Endpoints:**
- `POST /auth/login` → returns access + refresh JWT
- `POST /auth/refresh` → rotates refresh token
- `POST /auth/logout` → revokes refresh token
- `GET /auth/me` → returns user profile
- `POST /auth/api-keys` → creates a CI/CD API key

**Consumed by:** API Gateway (JWT verification via Kong plugin calling `/auth/validate`). Every service also independently verifies JWT signature using the shared public key (pulled from Vault at startup).

**Triggered by:** Frontend login form, CI/CD webhook auth header validation.

---

### 4 — Scan Orchestrator (`services/orchestrator/`)

**Technology:** Python 3.12, FastAPI, Temporal (workflow engine), PostgreSQL, Kafka producer, Redis.

**This is the most architecturally complex service.** It does not perform any scanning itself — it manages the lifecycle of every scan job and coordinates all downstream pipeline services through Temporal workflows.

**Responsibilities:**
- Accepts scan requests from the frontend (via API Gateway)
- Creates a `ScanJob` record in PostgreSQL with status `queued`
- Initiates a Temporal workflow for each scan — the workflow handles phase sequencing, retries, timeouts, and failure recovery
- Publishes phase-trigger events to Kafka topics
- Maintains scan job state in Redis (for low-latency status polling)
- Publishes scan progress events to Redis pub/sub (consumed by WebSocket Hub)
- Handles scan pause, cancel, and re-run requests
- Manages scheduled scans (cron-based recurring scans per org)

**Database schema (owns `orchestrator` PostgreSQL schema):**

```
scan_jobs          (id, org_id, user_id, targets[], config, status, phase, 
                    created_at, started_at, completed_at, error_message)
scan_schedules     (id, org_id, cron_expression, targets[], config, last_run, next_run)
scan_phases        (id, scan_id, phase_number, phase_name, status, 
                    started_at, completed_at, assets_processed)
```

**Temporal Workflow — `ScanWorkflow`:**

```
ScanWorkflow
  ├── Phase 0: Validate targets, check rate limits
  ├── Phase 1: Signal → Discovery Engine (Kafka: scan.discovery.start)
  │            Await: Kafka scan.discovery.complete
  ├── Phase 2: Signal → Crypto Inspector (Kafka: scan.crypto.start)
  │            Await: Kafka scan.crypto.complete
  ├── Phase 3: Signal → CBOM Service (Kafka: scan.cbom.start)
  │            Await: Kafka scan.cbom.complete
  ├── Phase 4: Signal → Risk Engine (Kafka: scan.risk.start)
  │            Await: Kafka scan.risk.complete
  ├── Phase 5: Signal → Compliance Service (Kafka: scan.compliance.start)
  │            Signal → Graph Service (Kafka: scan.graph.start)  [parallel]
  │            Await both completions
  └── Phase 6: Signal → Notification Service (Kafka: scan.complete)
               Update ScanJob status → 'completed'
               Publish Redis pub/sub: scan:events:{scan_id}
```

Temporal ensures that if any phase fails, it is retried up to 3 times with exponential backoff before the workflow is marked failed and the CISO is notified. Long pauses (e.g., waiting for Phase 2 to complete) persist durably in Temporal's history — a pod restart does not lose the workflow state.

**Kafka topics produced:**

| Topic | Consumed by |
|---|---|
| `scan.discovery.start` | Discovery Engine |
| `scan.crypto.start` | Crypto Inspector |
| `scan.cbom.start` | CBOM Service |
| `scan.risk.start` | Risk Engine |
| `scan.compliance.start` | Compliance Service |
| `scan.graph.start` | Graph Service |
| `scan.complete` | Notification Service, Asset Registry |

**API Endpoints:**
- `POST /scans/` → create and start a new scan
- `GET /scans/{scan_id}` → poll scan status + phase progress
- `DELETE /scans/{scan_id}` → cancel a running scan
- `GET /scans/` → list all scans for the org (paginated)
- `POST /scans/schedule` → create a recurring scan schedule

**Triggered by:** Frontend "Start Discovery" button, scheduled cron jobs, CI/CD webhook `POST /api/v1/scans/trigger`.

---

### 5 — Discovery Engine (`services/discovery-engine/`)

**Technology:** **Go 1.22**, Gin, Kafka consumer/producer, PostgreSQL (writes to Asset Registry's DB via internal API call, not direct DB access).

Go is chosen specifically for this service because Phase 1 involves massively concurrent network I/O — enumerating thousands of subdomains, hitting CT log APIs, and sweeping IP ranges. Go's goroutine scheduler handles 50,000+ concurrent connections efficiently. Python's GIL makes this impractical at scale.

**Responsibilities:**
- Consumes `scan.discovery.start` Kafka message
- Runs five enumeration methods in parallel goroutines:
  1. DNS brute-force subdomain enumeration (wordlist-driven, including financial institutions dictionaries)
  2. Certificate Transparency & External API log mining (crt.sh API, CertSpotter API, HackerTarget API)
  3. Active DNS Verification (Go `net.LookupIP` to aggressively filter out non-resolving domains)
  4. ASN/BGP sweep (RIPE NCC API, ARIN Whois)
  5. Port scanning (via Go `net.DialTimeout` on discovered live IPs) & HTTP probing extracting status codes, server headers, and titles
- Deduplicates discovered assets across all five methods
- Creates preliminary `Asset` records by calling Asset Registry's internal API (`POST /internal/assets/bulk`)
- Streams progress events to Kafka `scan.discovery.progress` (consumed by WebSocket Hub via Orchestrator)
- Produces `scan.discovery.complete` with the full list of discovered asset IDs when done

**Produced Kafka topics:**

| Topic | Content |
|---|---|
| `scan.discovery.progress` | Phase 1 progress (asset count, method status) |
| `scan.discovery.complete` | List of discovered asset IDs for Phase 2 |
| `asset.discovered` | Individual asset events (consumed by Asset Registry) |

**No direct DB access.** The Discovery Engine is stateless — all data is persisted through Kafka events consumed by the Asset Registry. This makes the Go service lean and testable.

**Triggered by:** Kafka message on `scan.discovery.start`.

---

### 6 — Crypto Inspector (`services/crypto-inspector/`)

**Technology:** Python 3.12, FastAPI, `cryptography` (pyca), `pyOpenSSL`, `ssl`, `certifi`, Kafka.

**Responsibilities:**
- Consumes `scan.discovery.complete` to get the list of asset IDs to inspect
- Fetches each asset's TLS endpoint via the Asset Registry internal API
- For each asset, performs a controlled TLS handshake that:
  - Enumerates all supported cipher suites (by attempting negotiation with each)
  - Records the negotiated cipher suite, key exchange algorithm, and TLS version
  - Downloads the full certificate chain (leaf + all intermediates)
  - Parses certificate: Subject, SAN list, Issuer, Valid From/To, Public Key type and length, SHA fingerprint, CT log status
  - Detects whether the endpoint enforces forward secrecy
  - Detects certificate pinning headers (HPKP, Expect-CT)
  - Flags mismatches between the negotiated cipher and the certificate key type
- For API endpoints: detects the auth mechanism (JWT header, mTLS client cert, API key header) and extracts JWT algorithm from well-known OIDC discovery endpoints
- Publishes rich cryptographic records to Kafka `scan.crypto.asset.complete` per asset
- Publishes `scan.crypto.complete` when all assets are processed

**Uses `asyncio` + `ThreadPoolExecutor`** for concurrent TLS handshakes (TLS handshake is CPU-bound due to RSA operations, so true threads are needed, not coroutines).

**Produced Kafka topics:**

| Topic | Content |
|---|---|
| `scan.crypto.asset.complete` | Full cryptographic fingerprint per asset (consumed by CBOM Service) |
| `scan.crypto.complete` | Signal to Orchestrator that Phase 2 is done |

**Triggered by:** Kafka message on `scan.crypto.start` (which includes the asset ID list from Phase 1).

---

### 7 — CBOM Service (`services/cbom-service/`)

**Technology:** Python 3.12, FastAPI, `cyclonedx-python-lib`, MinIO, PostgreSQL, Kafka.

**Responsibilities:**
- Consumes `scan.crypto.asset.complete` events (one per asset) and accumulates them
- When `scan.crypto.complete` arrives, assembles the full CBOM for the scan
- Generates a CycloneDX 1.6 BOM document per asset, including:
  - `components[]` — each crypto algorithm, cert, key, and library as a CycloneDX component
  - `nistQuantumSecurityLevel` property (0–6 per component)
  - `vulnerabilities[]` — cross-referenced CVEs for detected library versions
  - `dependencies[]` — which algorithm components depend on which key components
- Generates an org-wide aggregate CBOM from all per-asset CBOMs
- Stores CBOM JSON files in MinIO at `cbom/{org_id}/{scan_id}/{asset_id}.cdx.json`
- Stores CBOM metadata (not raw JSON) in PostgreSQL for fast query
- Publishes `scan.cbom.complete` with MinIO paths

**Database schema (owns `cbom` PostgreSQL schema):**

```
cbom_records    (id, scan_id, asset_id, org_id, cyclonedx_version,
                 component_count, vulnerable_component_count, 
                 minio_path, generated_at)
cbom_components (id, cbom_id, component_type, algorithm_name, 
                 key_length, nist_quantum_level, is_quantum_vulnerable,
                 usage_context, pqc_replacement)
cbom_certs      (id, cbom_id, common_name, san_list, issuer, ca_name,
                 key_type, key_length, valid_from, valid_to, 
                 sha256_fingerprint, ct_logged)
```

**API Endpoints (for CBOM Explorer page):**
- `GET /cbom/assets/{asset_id}` → latest CBOM for an asset
- `GET /cbom/assets/{asset_id}/history` → historical CBOMs (diff over time)
- `GET /cbom/scans/{scan_id}/aggregate` → org-wide CBOM
- `GET /cbom/export/{cbom_id}?format=json|pdf|csv` → triggers download from MinIO
- `GET /cbom/algorithms/distribution` → org-wide algorithm usage stats
- `GET /cbom/certificates/expiry-timeline` → certs grouped by expiry bucket

**Triggered by:** Kafka messages from Crypto Inspector. API calls from frontend CBOM Explorer page.

---

### 8 — Risk Engine (`services/risk-engine/`)

**Technology:** Python 3.12, FastAPI, `numpy` (Mosca computation), ClickHouse (risk score history), PostgreSQL, Kafka.

**Responsibilities:**
- Consumes `scan.cbom.complete` to trigger risk computation
- For each asset, pulls its CBOM components from the CBOM Service (internal API call)
- Computes the Quantum Risk Score (0–1000) via the five-factor model
- Computes the Mosca triple (X migration time, Y data shelf life, Z CRQC arrival) per asset, using asset type defaults configurable per org
- Classifies each asset: Quantum Critical / Vulnerable / At Risk / Aware / Ready
- Computes HNDL Exposure Window: start date (earliest known scan), active harvest period, retroactive decryption risk horizon
- Evaluates TNFL (Trust Now Forge Later) risk for assets with digital signature usage
- Writes risk scores to PostgreSQL and historical trend data to ClickHouse
- Produces `scan.risk.complete`

**Database schema (owns `risk` PostgreSQL schema):**

```
risk_scores      (id, asset_id, scan_id, org_id, quantum_risk_score,
                  risk_classification, mosca_x, mosca_y, mosca_z_pessimistic,
                  mosca_z_median, mosca_z_optimistic, hndl_exposed,
                  tnfl_risk, computed_at)
risk_factors     (id, risk_score_id, factor_name, factor_score, 
                  factor_weight, rationale)
```

**ClickHouse table (time-series risk history):**
```sql
CREATE TABLE risk_history (
  org_id String,
  asset_id String,
  scan_id String,
  quantum_risk_score UInt16,
  risk_classification LowCardinality(String),
  computed_at DateTime
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(computed_at)
ORDER BY (org_id, asset_id, computed_at);
```

**API Endpoints (for Risk Intelligence page):**
- `GET /risk/portfolio/heatmap` → Mosca X/Y coordinates for all assets (for the 2D heatmap)
- `GET /risk/assets/{asset_id}` → full risk breakdown for one asset
- `GET /risk/portfolio/summary` → Critical/Vulnerable/At-Risk/Ready counts
- `GET /risk/assets/{asset_id}/hndl-window` → HNDL timeline data for the asset
- `POST /risk/assets/{asset_id}/mosca/simulate` → recalculate Mosca with custom X/Y/Z inputs (for interactive sliders)

**Triggered by:** Kafka message on `scan.risk.start`. Frontend slider interactions call the simulate endpoint directly via API Gateway.

---

### 9 — Asset Registry (`services/asset-registry/`)

**Technology:** Python 3.12, FastAPI, PostgreSQL, Elasticsearch (sync), Redis (cache).

**Responsibilities:**
- The authoritative single source of truth for all discovered assets
- Accepts bulk asset creation from Discovery Engine (via internal `/internal/assets/bulk` endpoint)
- Updates asset records when Crypto Inspector and Risk Engine enrich them
- Maintains asset type classification, owner assignment, and tag management
- Syncs every asset write to Elasticsearch for full-text search
- Exposes the paginated, filtered, sortable asset inventory table used by the Discovery page
- Detects shadow assets: compares discovered assets against the bank's CMDB (uploaded as CSV or synced via API)
- Caches frequently-accessed asset lists in Redis (TTL 60 seconds) to reduce DB load during large inventory page renders

**Database schema (owns `assets` PostgreSQL schema):**

```
assets           (id, org_id, name, url, ip_v4, ip_v6, asset_type,
                  discovery_method, is_shadow, cmdb_registered,
                  owner_team, tags[], hosting_provider,
                  first_seen_at, last_seen_at, last_scan_id)
asset_ports      (id, asset_id, port, protocol, service_name, banner)
asset_metadata   (id, asset_id, key, value)          -- flexible key-value store
third_party_deps (id, asset_id, vendor_name, product, product_version,
                  endpoint_url, dep_type)
```

**Elasticsearch index (`assets`):** Mirrors all fields from the `assets` table plus enriched fields (risk_classification, tls_version, key_exchange_algorithm, cert_expiry). Updated on every asset write via a SQLAlchemy event listener.

**API Endpoints (for Discovery & Inventory page):**
- `GET /assets/` → paginated, filterable, sortable asset list
- `GET /assets/{asset_id}` → full asset detail (slide-out panel)
- `GET /assets/shadow` → assets not in CMDB
- `GET /assets/third-party` → third-party vendor endpoints
- `POST /assets/cmdb/upload` → upload CMDB CSV for shadow asset detection
- `GET /assets/search?q=...` → Elasticsearch-backed full-text search
- `POST /internal/assets/bulk` → internal endpoint (not exposed via Gateway)

**Triggered by:** Kafka events from Discovery Engine (`asset.discovered`), enrichment calls from Crypto Inspector and Risk Engine. Frontend Discovery page calls.

---

### 10 — Compliance Service (`services/compliance-service/`)

**Technology:** Python 3.12, FastAPI, PostgreSQL, Kafka.

**Responsibilities:**
- Consumes `scan.compliance.start` with scan_id
- Pulls CBOM data from CBOM Service and risk scores from Risk Engine (internal API calls)
- Evaluates each asset against:
  - FIPS 203/204/205 deployment status (is ML-KEM/ML-DSA/SLH-DSA in use?)
  - TLS 1.3 enforcement
  - Forward secrecy
  - Certificate hygiene (key length ≥ 2048, valid chain, CT logged)
  - RBI IT Framework cryptographic requirements
  - SEBI CSCRF software supply chain crypto inventory
  - PCI DSS 4.0 TLS minimum version
  - NPCI UPI mTLS requirement
- Computes the Crypto-Agility Score (0–100) for each asset by checking five agility factors
- Maintains regulatory deadline records per org
- Produces `scan.compliance.complete`

**Database schema (owns `compliance` PostgreSQL schema):**

```
compliance_results    (id, asset_id, scan_id, org_id,
                       fips_203_deployed, fips_204_deployed, fips_205_deployed,
                       tls_13_enforced, forward_secrecy,
                       rbi_compliant, sebi_compliant, pci_compliant, npci_compliant,
                       crypto_agility_score, computed_at)
agility_factors       (id, compliance_result_id, factor_name, score, passed)
regulatory_deadlines  (id, org_id, regulation_name, jurisdiction, deadline_date,
                       compliance_pct, last_updated)
```

**API Endpoints (for PQC Compliance page):**
- `GET /compliance/portfolio/fips-matrix` → asset × FIPS standard grid data
- `GET /compliance/assets/{asset_id}` → full compliance breakdown
- `GET /compliance/portfolio/agility-distribution` → agility score histogram
- `GET /compliance/regulatory/deadlines` → org's regulatory deadline countdown data
- `GET /compliance/portfolio/india-tracker` → India-specific regulation status
- `GET /compliance/portfolio/hybrid-tracker` → hybrid deployment progression over time

**Triggered by:** Kafka message on `scan.compliance.start`.

---

### 11 — Graph Service (`services/graph-service/`)

**Technology:** Python 3.12, FastAPI, Neo4j (via `neo4j` Python driver), Kafka.

**Responsibilities:**
- Consumes `scan.graph.start` (runs in parallel with compliance, not after it)
- Pulls all discovered assets, certs, IPs, services, and their relationships from Asset Registry and CBOM Service
- Upserts nodes and edges into Neo4j:
  - Nodes: Domain, IP, Certificate, Service, CA, HSM, Organisation
  - Edges: `RESOLVES_TO`, `USES_CERTIFICATE`, `RUNS_SERVICE`, `ISSUED_BY`, `SHARES_CERT_WITH`, `DEPENDS_ON`
- Computes blast radius for each certificate node (how many assets would be compromised if this cert's key is broken)
- Labels each node with its PQC readiness status
- Produces `scan.graph.complete`

**Neo4j schema (Cypher):**
```cypher
// Node labels
(:Domain {id, name, org_id, risk_class, pqc_ready})
(:IP {address, version, asn, geo_country, geo_city})
(:Certificate {fingerprint, common_name, key_type, key_length, 
               nist_level, valid_to, ca_name, is_quantum_vulnerable})
(:Service {name, version, port, banner})
(:CA {name, pqc_roadmap_published, pqc_target_version})

// Relationships
(:Domain)-[:RESOLVES_TO]->(:IP)
(:Domain)-[:USES_CERTIFICATE {negotiated_at}]->(:Certificate)
(:IP)-[:RUNS_SERVICE {port}]->(:Service)
(:Certificate)-[:ISSUED_BY]->(:CA)
(:Certificate)-[:CHAINS_TO]->(:Certificate)
```

**API Endpoints (for Topology Map page):**
- `GET /graph/topology` → full graph export (nodes + edges) for D3.js rendering
- `GET /graph/assets/{asset_id}/neighbors` → first-degree connections of an asset
- `GET /graph/certificates/{fingerprint}/blast-radius` → blast radius computation
- `GET /graph/trust-chain/{domain}` → certificate trust chain as a tree
- `GET /graph/topology/filter?type=...&risk=...` → filtered graph view

**Triggered by:** Kafka message on `scan.graph.start`. Frontend Topology Map page real-time filter changes call the filter endpoint directly.

---

### 12 — Migration Service (`services/migration-service/`)

**Technology:** Python 3.12, FastAPI, PostgreSQL.

**Responsibilities:**
- Stores and serves the migration playbook library (seeded from a static YAML library at startup, customizable per org)
- Generates per-asset migration recommendations by joining asset data (from Asset Registry) with CBOM data (from CBOM Service) and risk scores (from Risk Engine)
- Computes the prioritized migration roadmap: for each asset, calculates estimated start date, estimated completion date based on crypto-agility score and playbook effort estimates
- Generates the Gantt timeline data for the Migration Planner page
- Manages the third-party vendor readiness tracker (CRUD for vendor records + manual PQC roadmap status updates)
- Tracks migration velocity: how many assets have moved from Classical → Hybrid → Full PQC over time

**Database schema (owns `migration` PostgreSQL schema):**

```
playbooks          (id, title, stack_category, difficulty, effort_hours,
                    applicable_asset_types[], content_markdown, version)
asset_migration    (id, asset_id, org_id, current_phase, target_phase,
                    assigned_playbook_ids[], est_start, est_complete,
                    actual_complete, blocked_reason, owner)
vendors            (id, org_id, vendor_name, product_name, current_version,
                    pqc_roadmap_published, pqc_target_version, 
                    est_availability, risk_if_delayed)
migration_progress (id, org_id, scan_id, classical_count, hybrid_count,
                    full_pqc_count, blocked_count, recorded_at)
```

**API Endpoints (for Migration Planner page):**
- `GET /migration/roadmap` → Gantt timeline data for all org assets
- `GET /migration/playbooks/` → playbook library (filterable by stack/difficulty)
- `GET /migration/playbooks/{id}` → full playbook content
- `GET /migration/assets/{asset_id}/plan` → specific migration plan for an asset
- `GET /migration/vendors/` → vendor readiness tracker table
- `PATCH /migration/vendors/{id}` → update vendor PQC roadmap status
- `GET /migration/progress/history` → migration velocity over time (for progress chart)

**Triggered by:** Frontend Migration Planner page loads. Also re-computed after each scan completes (Orchestrator publishes `scan.complete` consumed here to refresh roadmap estimates).

---

### 13 — Reporting Service (`services/reporting-service/`)

**Technology:** Python 3.12, FastAPI, `WeasyPrint` (HTML→PDF), `APScheduler`, MinIO, PostgreSQL, Kafka.

**Responsibilities:**
- Generates on-demand reports by aggregating data from Asset Registry, CBOM Service, Risk Engine, Compliance Service, and Migration Service (all via internal API calls)
- Renders reports as PDF using Jinja2 HTML templates + WeasyPrint
- Stores generated PDFs in MinIO at `reports/{org_id}/{report_id}.pdf`
- Manages scheduled reports: APScheduler persists cron jobs in PostgreSQL and triggers report generation at the scheduled time
- Sends generated reports via email (SMTP) or a secure download link
- Generates the CycloneDX CBOM audit package by bundling all per-asset CBOM files from MinIO into a ZIP

**Database schema (owns `reporting` PostgreSQL schema):**

```
report_jobs        (id, org_id, user_id, report_type, config_json,
                    status, minio_path, generated_at, file_size_bytes)
report_schedules   (id, org_id, report_type, cron_expression, config_json,
                    last_run, next_run, delivery_config_json)
```

**API Endpoints (for Reports page):**
- `POST /reports/generate` → trigger on-demand report (async, returns job ID)
- `GET /reports/jobs/{job_id}` → poll report generation status
- `GET /reports/jobs/{job_id}/download` → returns pre-signed MinIO URL (valid 1 hour)
- `GET /reports/` → list all generated reports for the org
- `POST /reports/schedules` → create scheduled report
- `GET /reports/schedules/` → list scheduled reports

**Triggered by:** Frontend Reports page form submission. APScheduler cron triggers. `scan.complete` Kafka event can optionally auto-trigger a report if the org has a post-scan report enabled.

---

### 14 — AI Service (`services/ai-service/`)

**Technology:** Python 3.12, FastAPI, Ollama (local LLM), ChromaDB (vector store), `langchain` or `llama-index`, `sentence-transformers`.

**Responsibilities:**
- Receives natural language queries from the frontend AI chatbot
- Retrieves relevant context from ChromaDB using semantic similarity search
- ChromaDB is populated with embeddings of:
  - All asset CBOM summaries (refreshed after each scan via `scan.complete` Kafka event)
  - Risk score narratives
  - Migration playbook content
  - Regulatory deadline records
  - All historical report summaries
- Constructs a RAG prompt: `[system context] + [retrieved chunks] + [user query]`
- Sends the prompt to Ollama (`mistral:7b` or `llama3.1:8b`) running on a GPU node
- Streams the LLM response back to the frontend via Server-Sent Events (SSE)
- For AI report generation: uses a structured prompt template that instructs the LLM to produce a JSON report outline, then fills it with real data from the other services
- All LLM inference happens on-premise — zero external API calls

**ChromaDB collection design:**

```python
collections = {
    "cbom_summaries":       # One document per (org_id, asset_id) CBOM summary
    "risk_narratives":      # Risk score explanations per asset
    "playbooks":            # Migration playbook content chunks
    "regulatory_docs":      # RBI/SEBI/PCI requirement text
    "scan_findings":        # Key findings from each scan
}
```

**API Endpoints (for AI Assistant page):**
- `POST /ai/chat` → accepts a user message, returns a streaming SSE response
- `POST /ai/report` → accepts a report brief (audience, tone, focus), returns structured report draft
- `POST /ai/embed/refresh` → re-embeds all CBOM summaries for an org (triggered by `scan.complete` Kafka event)
- `GET /ai/chat/history` → returns the conversation thread for the session

**Triggered by:** Frontend AI Assistant page user messages. `scan.complete` Kafka event triggers ChromaDB refresh.

---

### 15 — Notification Service (`services/notification-service/`)

**Technology:** Python 3.12, FastAPI, `SendGrid` / SMTP, PostgreSQL, Kafka, Redis pub/sub.

**Responsibilities:**
- Consumes `scan.complete` Kafka events and evaluates alert rules for the org
- Alert rules: new shadow asset detected, certificate expiring in <30 days, new Quantum Critical asset found, new CVE against a detected library version
- For each triggered alert: stores it in PostgreSQL, publishes to Redis pub/sub `scan:events:{scan_id}` (picked up by WebSocket Hub for in-app real-time delivery)
- Sends email notifications for critical alerts (configurable per-org and per-user)
- Sends webhook payloads to configured org endpoints (for SIEM integration)
- Manages the notification center read/unread state per user

**Database schema (owns `notifications` PostgreSQL schema):**

```
alerts             (id, org_id, asset_id, scan_id, alert_type, severity,
                    title, description, is_read, created_at)
alert_rules        (id, org_id, rule_type, severity_threshold, enabled)
notification_prefs (id, user_id, alert_type, email_enabled, in_app_enabled)
webhook_endpoints  (id, org_id, url, secret, events[])
```

**Triggered by:** `scan.complete` Kafka event. Also triggered externally by other services that detect time-sensitive conditions (e.g., Certificate Expiry daemon that runs on a daily cron inside this service).

---

## Kafka Topic Map

```
Topics consumed by each service:

scan.discovery.start       → Discovery Engine
scan.discovery.progress    → Orchestrator (for WebSocket Hub relay)
scan.discovery.complete    → Orchestrator (Temporal signal), Asset Registry
asset.discovered           → Asset Registry
scan.crypto.start          → Crypto Inspector
scan.crypto.asset.complete → CBOM Service
scan.crypto.complete       → Orchestrator (Temporal signal)
scan.cbom.start            → CBOM Service
scan.cbom.complete         → Orchestrator (Temporal signal), Risk Engine trigger
scan.risk.start            → Risk Engine
scan.risk.complete         → Orchestrator (Temporal signal)
scan.compliance.start      → Compliance Service
scan.compliance.complete   → Orchestrator (Temporal signal)
scan.graph.start           → Graph Service
scan.graph.complete        → Orchestrator (Temporal signal)
scan.complete              → Notification Service, AI Service (embed refresh),
                             Migration Service (roadmap refresh),
                             Reporting Service (if auto-report enabled)
```

All topics use JSON encoding with a versioned schema envelope:
```json
{
  "schema_version": "1.0",
  "event_type": "scan.discovery.complete",
  "scan_id": "sc_abc123",
  "org_id": "org_pnb",
  "timestamp": "2026-04-09T10:22:44Z",
  "payload": { ... }
}
```

---

## Inter-Service Communication Rules

The architecture follows three strict rules that make it maintainable as it grows:

**Rule 1 — No direct database cross-access.** Every service owns exactly one PostgreSQL schema. No service ever connects to another service's schema. Data is exchanged only through Kafka events or internal REST API calls.

**Rule 2 — Internal API vs external API.** Every service has an `/internal/` router that is not registered with Kong (only reachable inside the Docker/Kubernetes network). External-facing endpoints go through Kong with JWT auth enforced. This prevents inter-service calls from bypassing auth while still allowing them to communicate efficiently.

**Rule 3 — Kafka for pipeline, REST for queries.** Scan pipeline data flows through Kafka (fire-and-forget, durable, replayable). Frontend-triggered data reads always go through REST (synchronous, paginated, filterable). This keeps the scan pipeline decoupled from the UI and makes it independently scalable.

---

## Addendum: Phase 7B Architecture Additions (2026-04-10)

### Scan Tier Architecture

The system supports three scan tiers with progressively deeper analysis:

| Tier | Latency Target | Scope | Pipeline |
|---|---|---|---|
| **Quick Scan** | 3–8 seconds | Root domain only | 1 TLS handshake → cert parse → NIST quantum levels → risk score → compliance snapshot |
| **Shallow Scan** | 30–90 seconds | Root + subdomains (DNS/CT only) | DNS enumeration + crt.sh → top-N subdomain TLS scans → CBOM → risk → compliance |
| **Deep Scan** | 5–10 minutes | Full infrastructure | Go Discovery Engine (DNS+CT+ASN+ports) → full crypto inspection on all assets → CBOM → risk → compliance → topology |

**Quick Scan** runs synchronously in the API request handler (no background thread). **Shallow** and **Deep** scans run as background tasks. The `ScanJob` model includes a `scan_type` enum field (`quick`, `shallow`, `deep`) that determines which pipeline to execute.

**Scan Tier Escalation**: If a user requests a Quick Scan for a domain that already has a Shallow or Deep scan cached, the system returns the richer cached result instantly. Tier hierarchy: `deep > shallow > quick`.

### Authentication Service

| Component | Technology |
|---|---|
| Password hashing | `bcrypt` via `passlib` |
| Token format | JWT (HS256), access + refresh tokens |
| Access token TTL | 30 minutes |
| Refresh token TTL | 7 days |
| Email verification | Token-based (UUID4, 24h expiry) |
| Data isolation | `user_id` FK on `ScanJob`; query filters enforce ownership |

**Models**: `User` (id, email, password_hash, email_verified, created_at) + `EmailVerification` (token, user_id, expires_at).

**Scan Cache**: `ScanCache` (domain, scan_type, scan_id, user_id, cached_at, expires_at). TTLs: quick=1h, shallow=6h, deep=24h.

### GeoIP Location Service

Uses MaxMind GeoLite2 databases (already configured in `.env` as `MAXMIND_DB_PATH`) to resolve IP addresses to geographic coordinates and ISP/organization metadata.

**Model**: `GeoLocation` (asset_id, ip_address, latitude, longitude, city, state, country, organization, isp, asn).

**API Output**: GeoJSON format for map rendering. Each asset's IPs plotted with hostname, risk status, asset type, and quantum vulnerability as hover data.

### Crypto Algorithm Improvements

1. **Hybrid PQC Detection**: Extended `detect_pqc()` and `scan_tls()` to detect TLS 1.3 hybrid named groups (X25519MLKEM768 `0x4588`, SecP256r1MLKEM768 `0x4589`, SecP384r1MLKEM1024 `0x4590`).
2. **Cipher Suite Decomposition**: CBOM components decomposed from monolithic cipher names into structured `{key_exchange, authentication, symmetric, mac}`.
3. **HNDL Sensitivity Multiplier**: Per-asset-type weighting (swift_endpoint: 5.0x, internet_banking: 3.0x, upi_gateway: 3.0x, etc.) applied to HNDL exposure calculation.
4. **Dynamic Migration Complexity**: Mosca's X parameter computed dynamically from scan data (agility score, third-party dependency, pinning, forward secrecy) rather than static defaults.