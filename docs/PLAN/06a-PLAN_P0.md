# Phase 0 — Foundation

> **Goal**: Set up the repository structure, database, configuration, logging framework, and shared models. Everything else builds on this.
> **Estimated time**: 3–4 hours
> **External dependencies**: PostgreSQL only

---

## Checklist

### P0.1 — Repository Skeleton
- [x] Create the directory structure exactly as in `06-DEVELOPMENT_PLAN.md → File Structure`
- [x] Create `backend/pyproject.toml` with project metadata
- [x] Create `backend/requirements.txt` with these pinned dependencies:
  ```
  fastapi>=0.111.0
  uvicorn[standard]>=0.30.0
  sqlalchemy[asyncio]>=2.0.30
  alembic>=1.13.0
  psycopg2-binary>=2.9.9
  pydantic>=2.7.0
  pydantic-settings>=2.3.0
  python-dotenv>=1.0.1
  python-json-logger>=2.0.7
  httpx>=0.27.0
  sslyze>=6.0.0
  cryptography>=42.0.0
  cyclonedx-python-lib>=7.0.0
  numpy>=1.26.0
  scipy>=1.13.0
  networkx>=3.3
  pyjwt>=2.8.0
  geoip2>=4.8.0
  jinja2>=3.1.4
  weasyprint>=62.0
  pytest>=8.2.0
  pytest-asyncio>=0.23.0
  rich>=13.7.0
  ```
- [x] Create `.gitignore` with entries for: `.env`, `logs/`, `data/`, `__pycache__/`, `*.pyc`, `.venv/`, `node_modules/`
- [x] Copy `.env.example` to `.env` and fill in `POSTGRES_PASSWORD`
- [x] Create Python virtual environment: `python -m venv .venv && source .venv/bin/activate && pip install -r backend/requirements.txt`

**✅ Verify**: `python -c "import fastapi, sqlalchemy, sslyze, cryptography; print('All imports OK')"` → prints "All imports OK"

---

### P0.2 — Configuration System
- [x] Create `backend/app/config.py`:
  - Use `pydantic_settings.BaseSettings` to load from `.env`
  - Fields: `POSTGRES_HOST`, `POSTGRES_PORT`, `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`, `LOG_LEVEL`, `LOG_DIR`, `DATA_DIR`, `APP_ENV`
  - Computed property: `database_url` → `postgresql+psycopg2://{user}:{pass}@{host}:{port}/{db}`
  - Computed property: `async_database_url` → `postgresql+asyncpg://{user}:{pass}@{host}:{port}/{db}`

**✅ Verify**: `python -c "from app.config import settings; print(settings.database_url)"` → prints valid PostgreSQL URL

---

### P0.3 — Structured Logging Framework
- [x] Create `backend/app/core/logging.py`:
  - Function `get_logger(service_name: str) -> logging.Logger`
  - Uses `python_json_logger.JsonFormatter` for structured JSON output
  - Writes to both **console** (colored, human-readable via `rich`) and **file** (`logs/{service_name}/{date}.jsonl`)
  - Every log entry includes: `timestamp`, `level`, `service`, `function`, `message`
  - Creates log directories automatically if they don't exist

- [x] Create `backend/app/core/timing.py`:
  - Decorator `@timed` that logs function name, arguments (truncated), return value summary, and execution time in milliseconds
  - Works with both sync and async functions
  - Logs at `DEBUG` level

**✅ Verify**: Create a test script:
```python
from app.core.logging import get_logger
from app.core.timing import timed

logger = get_logger("test")
logger.info("Test message", extra={"custom_field": "value"})

@timed
def slow_function(x):
    import time; time.sleep(0.1)
    return x * 2

result = slow_function(21)
# Check: logs/test/{today}.jsonl has 2 entries (INFO + DEBUG)
```

---

### P0.4 — Database Setup
- [x] Create `backend/app/core/database.py`:
  - `engine` = SQLAlchemy engine from `settings.database_url`
  - `SessionLocal` = sessionmaker
  - `Base` = declarative_base()
  - Function `get_db()` → dependency injection for FastAPI
  - Function `init_db()` → creates all tables (dev only)

- [x] Create `scripts/db_setup.py`:
  - Connects to PostgreSQL
  - Creates the `qushield` database if it doesn't exist
  - Runs `Base.metadata.create_all(engine)` to create all tables
  - Prints summary: which tables were created

**✅ Verify**: `python scripts/db_setup.py` → prints "Created N tables: assets, scan_jobs, certificates, ..."

---

### P0.5 — Database Models (SQLAlchemy ORM)
- [x] Create `backend/app/models/scan.py`:
  ```
  scan_jobs: id (UUID), targets (JSON list), config (JSON), status (enum: queued/running/completed/failed),
             current_phase (int), created_at, started_at, completed_at, error_message
  ```

- [x] Create `backend/app/models/asset.py`:
  ```
  assets: id (UUID), scan_id (FK), hostname, url, ip_v4, ip_v6, asset_type (enum),
          discovery_method, is_shadow (bool), hosting_provider,
          first_seen_at, last_seen_at, confidence_score (float)
  asset_ports: id, asset_id (FK), port (int), protocol, service_name, banner
  ```

- [x] Create `backend/app/models/certificate.py`:
  ```
  certificates: id (UUID), asset_id (FK), scan_id (FK),
                common_name, san_list (JSON), issuer, ca_name,
                key_type (enum: RSA/EC/ML-DSA/...), key_length (int),
                signature_algorithm, signature_algorithm_oid,
                valid_from, valid_to, sha256_fingerprint,
                is_ct_logged (bool), nist_quantum_level (int 0-6),
                is_quantum_vulnerable (bool), chain_depth (int)
  ```

- [x] Create `backend/app/models/cbom.py`:
  ```
  cbom_records: id (UUID), scan_id (FK), asset_id (FK),
                component_count (int), vulnerable_count (int),
                file_path (str), generated_at
  cbom_components: id, cbom_id (FK), component_type (enum), algorithm_name,
                   key_length (int), nist_quantum_level (int),
                   is_quantum_vulnerable (bool), usage_context, pqc_replacement
  ```

- [x] Create `backend/app/models/risk.py`:
  ```
  risk_scores: id (UUID), asset_id (FK), scan_id (FK),
               quantum_risk_score (int 0-1000), risk_classification (enum),
               mosca_x (float), mosca_y (float),
               mosca_z_pessimistic (float), mosca_z_median (float), mosca_z_optimistic (float),
               hndl_exposed (bool), tnfl_risk (bool), tnfl_severity,
               computed_at
  risk_factors: id, risk_score_id (FK), factor_name, factor_score (float),
                factor_weight (float), rationale (text)
  ```

- [x] Create `backend/app/models/compliance.py`:
  ```
  compliance_results: id (UUID), asset_id (FK), scan_id (FK),
                      fips_203_deployed (bool), fips_204_deployed (bool), fips_205_deployed (bool),
                      tls_13_enforced (bool), forward_secrecy (bool),
                      crypto_agility_score (int 0-100),
                      computed_at
  ```

- [x] Create `backend/app/models/__init__.py` that imports all models and exports `Base`

**✅ Verify**: `python scripts/db_setup.py` → creates all tables. Then verify with:
```bash
psql -U qushield -d qushield -c "\dt"
# Should list: scan_jobs, assets, asset_ports, certificates, cbom_records, cbom_components, risk_scores, risk_factors, compliance_results
```

---

### P0.6 — Pydantic Schemas
- [x] Create `backend/app/schemas/scan.py`: `ScanRequest`, `ScanResponse`, `ScanStatus`
- [x] Create `backend/app/schemas/asset.py`: `AssetCreate`, `AssetResponse`, `AssetList`
- [x] Create `backend/app/schemas/cbom.py`: `CBOMResponse`, `CBOMComponentResponse`
- [x] Create `backend/app/schemas/risk.py`: `RiskScoreResponse`, `MoscaInput`, `MoscaResult`
- [x] Create `backend/app/schemas/compliance.py`: `ComplianceResponse`

**✅ Verify**: `python -c "from app.schemas.scan import ScanRequest; print(ScanRequest.model_json_schema())"` → prints valid JSON schema

---

### P0.7 — Static Data Files
- [x] Create `backend/app/data/nist_quantum_levels.json` — the full algorithm→level mapping table from `05-ALGORITHM_RESEARCH.md` § 3.2
- [x] Create `backend/app/data/pqc_oids.json` — PQC signature algorithm OIDs from § 2.3
- [x] Create `backend/app/data/data_shelf_life_defaults.json` — asset-type→years mapping from § 4.1
- [x] Create `backend/app/data/regulatory_deadlines.json` — Indian regulatory deadlines with dates

**✅ Verify**: `python -c "import json; d = json.load(open('backend/app/data/nist_quantum_levels.json')); print(f'{len(d)} algorithms mapped')"` → prints count

---

### P0.8 — Log Viewer Script
- [x] Create `scripts/log_viewer.py`:
  - Reads `.jsonl` files from `logs/` directory
  - Command-line args: `--level`, `--service`, `--function`, `--scan-id`, `--last N`, `--since DATETIME`
  - Uses `rich` library for colored table output
  - Supports `--follow` mode (like `tail -f`) for real-time log watching

**✅ Verify**: Generate some test logs (from P0.3 verify step), then run:
```bash
python scripts/log_viewer.py --service test --last 5
# Should display formatted table with the test log entries
```

---

### P0.9 — Smoke Test Script Shell
- [x] Create `scripts/smoke_test.py`:
  - Takes a domain as argument
  - Currently just validates: config loads OK, DB connects OK, logging works
  - Future phases will add pipeline stages to this script
  - Print a colored summary at the end: `[✅ Config] [✅ Database] [✅ Logging]`

**✅ Verify**: `python scripts/smoke_test.py example.com` → prints green checkmarks for config, DB, logging

---

### P0.10 — Dev Log Initialization
- [x] Create `docs/DEV_LOG.md` with header and format example (as shown in `06-DEVELOPMENT_PLAN.md`)

**✅ Phase 0 Complete** when: All verify steps pass, `scripts/smoke_test.py` shows all green, and `DEV_LOG.md` has entries for each P0 item.
