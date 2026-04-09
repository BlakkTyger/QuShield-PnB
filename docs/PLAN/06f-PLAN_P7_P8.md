# Phase 7 & 8 — REST API + Frontend MVP

> **Goal**: Expose all backend data via FastAPI REST endpoints, then build a Next.js frontend with Quick Scan, Dashboard, and CBOM Explorer pages.
> **Estimated time**: 8–10 hours (4h backend API, 4-6h frontend)
> **Dependencies**: P6 complete (all pipeline data available)

---

## Phase 7 — REST API Layer

### P7.1 — FastAPI App Foundation
- [ ] Create `backend/app/main.py`:
  - FastAPI app with lifespan handler (init DB on startup)
  - CORS middleware (allow `http://localhost:3000` for Next.js dev)
  - Exception handlers (return structured JSON errors)
  - Health check endpoint: `GET /health` → `{"status": "ok", "db": "connected"}`
  - Mount all routers under `/api/v1/`
  - Auto-generated docs at `/docs` (Swagger) and `/redoc`

**✅ Verify**: `cd backend && uvicorn app.main:app --reload` → visit `http://localhost:8000/docs`

---

### P7.2 — Scan API Router
- [ ] Create `backend/app/api/v1/scans.py`:
  - `POST /api/v1/scans/` → start a new scan (accepts `{"targets": ["example.com"]}`)
    - Creates scan job, starts scan in background thread
    - Returns: `{"scan_id": "...", "status": "queued"}`
  - `GET /api/v1/scans/{scan_id}` → get scan status + phase progress
  - `GET /api/v1/scans/` → list all scans (paginated, sorted by created_at desc)
  - `GET /api/v1/scans/{scan_id}/summary` → full scan results summary

**✅ Test**: `curl -X POST http://localhost:8000/api/v1/scans/ -H "Content-Type: application/json" -d '{"targets":["example.com"]}'`

---

### P7.3 — Assets API Router
- [ ] Create `backend/app/api/v1/assets.py`:
  - `GET /api/v1/assets/` → paginated asset list (filter by: scan_id, risk_class, asset_type)
  - `GET /api/v1/assets/{asset_id}` → full asset detail (ports, TLS info, cert, risk)
  - `GET /api/v1/assets/search?q=...` → PostgreSQL `ILIKE` search (hostname, IP, algorithm name)
  - `GET /api/v1/assets/shadow` → assets marked as shadow (not in CMDB)

---

### P7.4 — CBOM API Router
- [ ] Create `backend/app/api/v1/cbom.py`:
  - `GET /api/v1/cbom/assets/{asset_id}` → latest CBOM for asset
  - `GET /api/v1/cbom/scans/{scan_id}/aggregate` → org-wide CBOM summary
  - `GET /api/v1/cbom/export/{asset_id}` → Download raw CycloneDX JSON file
  - `GET /api/v1/cbom/algorithms/distribution` → algorithm usage stats across all assets

---

### P7.5 — Risk API Router
- [ ] Create `backend/app/api/v1/risk.py`:
  - `GET /api/v1/risk/portfolio/heatmap` → Mosca X/Y coordinates per asset (for 2D scatter)
  - `GET /api/v1/risk/assets/{asset_id}` → full risk breakdown
  - `GET /api/v1/risk/portfolio/summary` → count per classification (Critical/Vulnerable/Ready)
  - `GET /api/v1/risk/assets/{asset_id}/hndl-window` → HNDL timeline data
  - `POST /api/v1/risk/assets/{asset_id}/mosca/simulate` → recalculate with custom X/Y/Z inputs

---

### P7.6 — Compliance & Graph API Routers
- [ ] Create `backend/app/api/v1/compliance.py`:
  - `GET /api/v1/compliance/portfolio/fips-matrix` → asset × FIPS standard grid
  - `GET /api/v1/compliance/assets/{asset_id}` → full compliance breakdown
  - `GET /api/v1/compliance/portfolio/agility-distribution` → agility score histogram data

- [ ] Create `backend/app/api/v1/topology.py`:
  - `GET /api/v1/topology/graph` → full graph JSON (nodes+edges for D3.js)
  - `GET /api/v1/topology/certificates/{fingerprint}/blast-radius` → blast radius data

---

### P7.7 — API Integration Test
- [ ] Create `backend/tests/integration/test_api.py`:
  - Start FastAPI test client
  - POST a scan → poll until complete → verify all GET endpoints return valid data
  - Assert: all endpoints return 200 with correct schema
  - Assert: pagination works (limit/offset)
  - Assert: filters work (risk_class, asset_type)

**✅ Integration Test**:
```bash
cd backend && python -m pytest tests/integration/test_api.py -v
```

---

## Phase 8 — Frontend MVP (Next.js)

### P8.1 — Next.js Project Setup
- [ ] Create Next.js app: `cd frontend && npx -y create-next-app@latest ./ --typescript --tailwind --eslint --app --src-dir --no-import-alias`
  - NOTE: Using TailwindCSS here because Next.js ecosystem is built around it
- [ ] Install additional deps: `npm install recharts @tanstack/react-query axios d3 date-fns`
- [ ] Configure API proxy in `next.config.js`: proxy `/api/*` to `http://localhost:8000`

**✅ Verify**: `cd frontend && npm run dev` → opens at `http://localhost:3000`

---

### P8.2 — Design System & Layout
- [ ] Create shared layout: dark theme, sidebar navigation, header with org name
- [ ] Sidebar nav items: Quick Scan, Dashboard, Assets, CBOM Explorer, Risk, Compliance, Topology
- [ ] Color palette: dark background (#0a0a0f), glassmorphism cards, neon accent (quantum teal #00e5ff)
- [ ] Typography: Inter font from Google Fonts
- [ ] Component library: Card, Badge, ProgressBar, DataTable, ScoreGauge, StatusPill

---

### P8.3 — Page: Quick Scan
- [ ] Centered domain input field with "Scan Now" button
- [ ] Example domain tags that auto-populate on click
- [ ] On scan: show real-time progress stepper (Phase 1-4)
  - Poll `GET /api/v1/scans/{scan_id}` every 2 seconds
- [ ] On complete: show scorecard:
  - Large circular gauge (0-1000) — Quantum Risk Score
  - 4 metric cards: TLS Version, Key Exchange, Cert Expiry, NIST Level
  - Key findings cards with severity pills
- [ ] "Run Full Audit →" button links to Assets page

---

### P8.4 — Page: Dashboard
- [ ] 4 headline metric cards (full width)
- [ ] Charts using Recharts:
  - Asset Risk Distribution (horizontal stacked bar)
  - Algorithm Exposure (donut chart)
  - Certificate Expiry Timeline (bar chart)
- [ ] Regulatory Deadline countdown list
- [ ] Critical Alerts feed
- [ ] PQC Adoption progress bar
- [ ] Bottom tabs: Top 10 Risk Assets / Expiring Certs / Recent Discoveries

---

### P8.5 — Page: Assets (Discovery & Inventory)
- [ ] Sortable, filterable data table (`@tanstack/react-table`)
- [ ] Columns: Hostname, IP, TLS Version, Key Exchange, Risk Score, Risk Class, Cert Expiry
- [ ] Filters: Risk classification, asset type, discovery method
- [ ] Search bar (full-text via API)
- [ ] Click row → slide-out panel with full asset detail
- [ ] Export CSV button

---

### P8.6 — Page: CBOM Explorer
- [ ] Tree view of CBOM components per asset
- [ ] Each component shows: algorithm, key length, NIST level, quantum status badge
- [ ] Color coding: green=safe, yellow=at risk, red=vulnerable
- [ ] Download CycloneDX JSON button
- [ ] Aggregate view: algorithm distribution chart across all assets

---

### P8.7 — Page: Topology Map
- [ ] D3.js force-directed graph visualization
- [ ] Nodes: colored by type (Domain=blue, IP=gray, Certificate=yellow, Service=purple)
- [ ] Node size: proportional to blast radius
- [ ] Click node → sidebar shows node details
- [ ] Filter controls: by risk level, node type
- [ ] Zoom/pan controls

---

### P8.8 — Frontend Integration Test
- [ ] Run backend: `cd backend && uvicorn app.main:app`
- [ ] Run frontend: `cd frontend && npm run dev`
- [ ] Browser test (via browser subagent):
  - Navigate to Quick Scan page
  - Enter "example.com" → Start scan → Wait for completion
  - Verify scorecard appears
  - Navigate to Dashboard → verify charts render
  - Navigate to Assets → verify table populates
  - Navigate to CBOM → verify components display
  - Navigate to Topology → verify graph renders

---

**✅ Phase 7+8 Complete** when:
1. All API endpoints return valid data from a completed scan
2. Frontend Quick Scan → end-to-end scan completes → scorecard displayed
3. Dashboard shows real data from the scan
4. Assets table shows all discovered assets with correct risk classifications
5. CBOM Explorer shows algorithm components with NIST levels
6. Topology graph renders with correct node/edge structure
