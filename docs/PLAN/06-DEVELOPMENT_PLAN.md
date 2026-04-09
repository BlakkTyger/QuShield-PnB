# 06 — POC Development Master Plan

> **Guiding Principles:**
> 1. **Test-first**: Every function is written standalone, tested against real websites, then integrated.
> 2. **Log-everything**: Structured JSON logging from day 1; every function call logs inputs, outputs, timing.
> 3. **Minimal infrastructure**: PostgreSQL is the ONLY required external service. No Kafka, no Redis, no Temporal, no Elasticsearch, no ClickHouse, no MinIO, no Kong — all deferred or replaced with in-process alternatives.
> 4. **Monolith-first**: Build as a single Python application (+ one Go binary). Microservice split happens later.
> 5. **No Docker for dev**: Run everything locally. Docker comes after the POC works end-to-end.

---

## POC Simplifications vs Production Architecture

| Production (04-SYSTEM_ARCHITECTURE.md) | POC Replacement | Rationale |
|----------------------------------------|-----------------|-----------|
| Apache Kafka (message bus) | **Python `asyncio.Queue`** + direct function calls | Zero infrastructure; scan pipeline is a single process |
| Temporal (workflow orchestration) | **Simple Python orchestrator class** with try/except retry | No need for durable workflows in POC |
| Redis (cache + pub/sub) | **In-memory Python dict** + `asyncio.Event` for signaling | POC has one user, no cache pressure |
| Kong OSS (API gateway) | **FastAPI single app with router prefixes** | One process, one port |
| Elasticsearch (full-text search) | **PostgreSQL `ILIKE` + `pg_trgm` extension** | PostgreSQL full-text search is adequate for POC |
| ClickHouse (time-series) | **PostgreSQL table** for risk history | Avoid another database |
| Neo4j (graph) | **NetworkX in-memory graph** serialized to JSON | Avoids Neo4j server; NetworkX does BFS/blast-radius fine for <10k nodes |
| MinIO (object storage) | **Local filesystem** (`data/cbom/`, `data/reports/`) | Files are just files |
| Qdrant (vector DB) | **ChromaDB in-process** | Zero infrastructure; good enough for POC |
| Prometheus/Grafana/Loki | **Python `logging` module** with JSON formatter + log files | File-based structured logs |
| OpenTelemetry/Jaeger | **Custom timing decorators** logging to JSON | Simple `@timed` decorator |
| HashiCorp Vault | **`.env` file** via `python-dotenv` | Dev-only secrets |
| Docker Compose | **Run locally** with `python` and `go run` | Zero containerization overhead for dev |
| Multiple microservices | **One FastAPI app** with modular routers | Monolith-first, split later |

### External Services — What You Actually Need

| Service | Required? | How to Set Up |
|---------|-----------|---------------|
| **PostgreSQL 16** | ✅ YES | `sudo apt install postgresql` or `docker run -d --name qushield-pg -p 5432:5432 -e POSTGRES_PASSWORD=qushield postgres:16` |
| **Go 1.22+** | ✅ YES (for Discovery Engine) | `sudo apt install golang-go` or download from golang.org |
| **Python 3.12+** | ✅ YES | System Python or `pyenv install 3.12` |
| **Ollama** (Phase 5 only) | ⏳ LATER | `curl -fsSL https://ollama.com/install.sh \| sh` |
| **MaxMind GeoLite2 DB** | ⏳ OPTIONAL | Download `.mmdb` file from MaxMind website |

---

## Development Phases Overview

| Phase | Name | Description | Depends On |
|-------|------|-------------|------------|
| **P0** | Foundation | Repo structure, DB schema, logging framework, shared models, config | Nothing |
| **P1** | Discovery Engine | Go binary for subdomain/port/service enumeration | P0 |
| **P2** | Crypto Inspector | TLS scanning, cipher enumeration, certificate parsing, PQC detection | P0 |
| **P3** | CBOM Builder | CycloneDX CBOM assembly from crypto inspection results | P2 |
| **P4** | Risk Engine | Mosca theorem, quantum risk scoring, HNDL/TNFL assessment | P3 |
| **P5** | Scan Orchestrator | End-to-end pipeline: Discovery → Crypto → CBOM → Risk | P1 + P4 |
| **P6** | Compliance & Graph | Regulatory compliance checks, topology graph, blast radius | P3 + P4 |
| **P7** | API Layer | FastAPI REST API exposing all data to the frontend | P5 + P6 |
| **P8** | Frontend MVP | Next.js frontend: Quick Scan, Dashboard, CBOM Explorer | P7 |
| **P9** | AI & Reports | RAG chatbot, PDF report generation | P7 |

Each phase has its own detailed plan document: `06a-PLAN_P0.md` through `06i-PLAN_P9.md`.

---

## Cross-Cutting: Logging & Testing Strategy

### Logging Framework (Implemented in P0, Used Everywhere)

Every function in the codebase uses structured JSON logging:

```
# Log format (written to logs/{service}/{date}.jsonl):
{
  "timestamp": "2026-04-09T10:22:44.123Z",
  "level": "INFO",
  "service": "crypto_inspector",
  "function": "scan_tls_endpoint",
  "input": {"host": "example.com", "port": 443},
  "output_summary": {"cipher": "TLS_AES_256_GCM_SHA384", "tls_version": "TLSv1.3"},
  "duration_ms": 1247,
  "scan_id": "sc_abc123"
}
```

**Log levels:**
- `DEBUG` — function entry/exit with full input/output
- `INFO` — scan phase completions, asset counts, scores computed
- `WARNING` — rate limits hit, retries triggered, degraded results
- `ERROR` — scan failures, network timeouts, parsing errors

**Log viewer script** (`scripts/log_viewer.py`):
- Reads JSONL files, filters by level/service/function/scan_id
- Outputs colored, formatted table to terminal
- Usage: `python scripts/log_viewer.py --level ERROR --service crypto_inspector --last 50`

### Testing Strategy

**Three levels of testing:**

1. **Standalone Tests** (`tests/standalone/`):
   - Each function is tested independently against **real websites** (not mocks)
   - Test targets: `scanme.nmap.org`, `example.com`, `google.com`, `expired.badssl.com`, `self-signed.badssl.com`
   - Output: JSON results file + pass/fail assertions + timing
   - Run: `python -m pytest tests/standalone/ -v --tb=short`

2. **Integration Tests** (`tests/integration/`):
   - Test the full pipeline: domain input → discovery → crypto → CBOM → risk → output
   - Uses a real domain (e.g., `example.com`)
   - Validates that each stage's output is valid input for the next stage
   - Run: `python -m pytest tests/integration/ -v`

3. **Pipeline Smoke Test** (`scripts/smoke_test.py`):
   - End-to-end script that runs the full system against one domain
   - Prints a structured summary of all outputs
   - Validates data integrity across all stages
   - Run: `python scripts/smoke_test.py example.com`

**Testing rule**: No function is integrated into the main codebase until its standalone test passes and its outputs are verified by the developer.

---

## File Structure (POC — Simplified)

```
qushield-pnb/
├── .env.example                    # Template for environment variables
├── .env                            # Your local config (git-ignored)
├── docs/                           # All planning & research documents
│
├── backend/
│   ├── pyproject.toml              # Python project config (deps, metadata)
│   ├── requirements.txt            # Pinned dependencies
│   │
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                 # FastAPI app entry point
│   │   ├── config.py               # Pydantic Settings (reads .env)
│   │   │
│   │   ├── core/
│   │   │   ├── logging.py          # Structured JSON logger setup
│   │   │   ├── database.py         # SQLAlchemy engine + session factory
│   │   │   ├── timing.py           # @timed decorator for performance logging
│   │   │   └── exceptions.py       # Custom exception classes
│   │   │
│   │   ├── models/                 # SQLAlchemy ORM models (all tables)
│   │   │   ├── __init__.py
│   │   │   ├── asset.py
│   │   │   ├── scan.py
│   │   │   ├── certificate.py
│   │   │   ├── cbom.py
│   │   │   ├── risk.py
│   │   │   └── compliance.py
│   │   │
│   │   ├── schemas/                # Pydantic schemas (request/response)
│   │   │   ├── __init__.py
│   │   │   ├── asset.py
│   │   │   ├── scan.py
│   │   │   ├── cbom.py
│   │   │   ├── risk.py
│   │   │   └── compliance.py
│   │   │
│   │   ├── services/               # Business logic (one file per domain)
│   │   │   ├── __init__.py
│   │   │   ├── orchestrator.py     # Scan pipeline coordinator
│   │   │   ├── crypto_inspector.py # TLS scanning, cert parsing
│   │   │   ├── cbom_builder.py     # CycloneDX CBOM generation
│   │   │   ├── risk_engine.py      # Mosca, HNDL, risk scoring
│   │   │   ├── compliance.py       # FIPS, RBI, agility checks
│   │   │   ├── graph_builder.py    # NetworkX topology + blast radius
│   │   │   ├── asset_manager.py    # Asset CRUD + shadow detection
│   │   │   └── report_generator.py # PDF generation
│   │   │
│   │   ├── api/                    # FastAPI routers
│   │   │   ├── __init__.py
│   │   │   ├── v1/
│   │   │   │   ├── scans.py
│   │   │   │   ├── assets.py
│   │   │   │   ├── cbom.py
│   │   │   │   ├── risk.py
│   │   │   │   ├── compliance.py
│   │   │   │   ├── topology.py
│   │   │   │   └── reports.py
│   │   │   └── router.py          # Mounts all v1 routers
│   │   │
│   │   └── data/                   # Static data files
│   │       ├── nist_quantum_levels.json
│   │       ├── pqc_oids.json
│   │       ├── data_shelf_life_defaults.json
│   │       └── regulatory_deadlines.json
│   │
│   ├── migrations/                 # Alembic migrations
│   │   ├── env.py
│   │   ├── alembic.ini
│   │   └── versions/
│   │
│   └── tests/
│       ├── standalone/             # Individual function tests (real websites)
│       │   ├── test_tls_scan.py
│       │   ├── test_cert_parse.py
│       │   ├── test_pqc_detect.py
│       │   ├── test_cbom_build.py
│       │   ├── test_risk_score.py
│       │   └── test_compliance.py
│       ├── integration/            # Multi-stage pipeline tests
│       │   └── test_full_pipeline.py
│       └── conftest.py
│
├── discovery/                      # Go binary (Discovery Engine)
│   ├── go.mod
│   ├── go.sum
│   ├── main.go                     # CLI entry point
│   ├── cmd/
│   │   └── scan.go                 # Scan command handler
│   ├── pkg/
│   │   ├── subdomain/              # subfinder wrapper
│   │   ├── portscan/               # naabu wrapper
│   │   ├── httpprobe/              # httpx wrapper
│   │   ├── asnlookup/             # asnmap wrapper
│   │   └── dedup/                  # Deduplication logic
│   ├── internal/
│   │   ├── config/                 # Config from env
│   │   └── logger/                 # Structured JSON logger
│   └── tests/
│       ├── subdomain_test.go
│       ├── portscan_test.go
│       └── integration_test.go
│
├── scripts/
│   ├── log_viewer.py               # Structured log viewer
│   ├── smoke_test.py               # Full pipeline end-to-end test
│   ├── test_discovery.sh           # Test Go discovery binary standalone
│   └── db_setup.py                 # Create database + run migrations
│
├── logs/                           # Runtime log output (git-ignored)
│   ├── crypto_inspector/
│   ├── orchestrator/
│   ├── risk_engine/
│   └── discovery/
│
└── data/                           # Runtime data output (git-ignored)
    ├── cbom/                       # Generated CBOM JSON files
    ├── reports/                    # Generated PDF reports
    ├── geolite/                    # MaxMind GeoIP database
    └── graphs/                     # NetworkX graph exports
```

---

## Detailed Phase Plans

Each phase has its own document with:
- Granular numbered checklist items
- Explicit standalone test steps
- Logging implementation steps
- Integration verification steps

| Document | Phase | Focus |
|----------|-------|-------|
| [06a-PLAN_P0.md](./06a-PLAN_P0.md) | P0 — Foundation | Repo, DB, logging, models, config |
| [06b-PLAN_P1.md](./06b-PLAN_P1.md) | P1 — Discovery Engine | Go binary: subdomains, ports, HTTP |
| [06c-PLAN_P2.md](./06c-PLAN_P2.md) | P2 — Crypto Inspector | TLS, ciphers, certs, PQC detection |
| [06d-PLAN_P3.md](./06d-PLAN_P3.md) | P3 — CBOM Builder | CycloneDX CBOM generation |
| [06e-PLAN_P4.md](./06e-PLAN_P4.md) | P4 — Risk Engine | Mosca, risk scoring, HNDL/TNFL |
| [06f-PLAN_P5.md](./06f-PLAN_P5.md) | P5 — Scan Orchestrator | Full pipeline coordination |
| [06g-PLAN_P6.md](./06g-PLAN_P6.md) | P6 — Compliance & Graph | Regulations, topology, blast radius |
| [06h-PLAN_P7_P8.md](./06h-PLAN_P7_P8.md) | P7/P8 — API & Frontend | REST API + Next.js frontend |
| [06i-PLAN_P9.md](./06i-PLAN_P9.md) | P9 — AI & Reports | RAG chatbot, PDF reports |

---

## Developer Workflow

When a coding agent picks up a phase:

1. **Read** the phase plan document (e.g., `06a-PLAN_P0.md`)
2. **Implement** each checklist item sequentially
3. **Run** the standalone test specified after each item
4. **Log** the test result in `docs/DEV_LOG.md` with timestamp, item ID, pass/fail, output summary
5. **Run** the integration test at the end of each phase
6. **Update** the checklist: mark items `[x]` as complete

**DEV_LOG.md format:**
```markdown
## 2026-04-09

### P0.3 — Logging Framework
- **Status**: ✅ PASS
- **Test**: `python -c "from app.core.logging import get_logger; ..."`
- **Output**: JSON logs written to `logs/test/2026-04-09.jsonl` — 3 test entries verified
- **Duration**: 12 minutes
- **Notes**: Used `python-json-logger` for formatting

### P0.4 — Database Connection
- **Status**: ✅ PASS
- **Test**: `python scripts/db_setup.py`
- **Output**: Connected to PostgreSQL, created 6 tables, verified with `\dt`
- **Duration**: 8 minutes
- **Notes**: Required `psycopg2-binary` instead of `psycopg2` on Ubuntu
```

This log provides full traceability of every implementation step.
