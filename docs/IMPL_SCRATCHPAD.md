# Implementation Scratchpad — Phase 7

## Test Targets (PERSISTED)
- https://pnb.bank.in
- https://onlinesbi.sbi.bank.in  
- https://www.hdfc.bank.in

## Current Task: � Phase 7 — REST API Layer

---

## Pre-Phase 7 Gap Analysis

### Critical Gaps Found in Orchestrator Phase 5/6
1. **Compliance not using real data**: `orchestrator.py:192` calls `evaluate_compliance(str(asset.id), {}, {})` with EMPTY dicts. Must pass actual CBOM + crypto data.
2. **Compliance results NOT persisted to DB**: The orchestrator runs compliance but never creates `ComplianceResult` rows.
3. **Compliance model missing fields**: No `rbi_compliant`, `sebi_compliant`, `pci_compliant`, `npci_compliant` from 04-SYSTEM_ARCHITECTURE.md.
4. **Graph builder doesn't compute blast radius per cert**: Only builds topology; blast_radius is separate function not called during scan.
5. **ScanJob.total_assets/total_certificates/total_vulnerable never updated**: Orchestrator completes but doesn't write summary stats back.

### Fixes Required Before Phase 7
- Fix orchestrator to pass real cbom_data and crypto_data to compliance
- Add compliance DB persistence in orchestrator 
- Update ScanJob summary stats on completion
- Add India-specific regulatory checks (RBI, SEBI, PCI, NPCI) to compliance model + service

### Phase 7 Implementation Plan (from 06f-PLAN_P7_P8.md)
1. **P7.1**: FastAPI main.py — lifespan, CORS, exception handlers, health check, Swagger
2. **P7.2**: Scan API — POST/GET/list/summary
3. **P7.3**: Assets API — paginated, filterable, searchable, shadow
4. **P7.4**: CBOM API — per-asset, aggregate, export, algorithm distribution
5. **P7.5**: Risk API — heatmap, breakdown, HNDL window, Mosca simulate
6. **P7.6**: Compliance API — FIPS matrix, agility distribution, regulatory deadlines
7. **P7.6b**: Topology API — graph JSON, blast radius
8. **P7.7**: Integration tests — E2E against banking domains

### Architecture Decisions
- Monolith FastAPI app (POC, not microservices)
- Background scan via `threading.Thread` (no Temporal/Celery)
- Sync SQLAlchemy sessions (psycopg2-binary, not asyncpg)
- Swagger auto-generated at `/docs`, Redoc at `/redoc`
- All endpoints under `/api/v1/`

---

## Phase Completion Summary

### Phase 0-4 ✅ (Completed previously)
### Phase 5 — Orchestrator ✅ (Needs compliance fix)
### Phase 6 — Compliance & Graph ✅ (Needs DB persistence fix)
### Phase 7 — API Layer 🔧 (IN PROGRESS)
