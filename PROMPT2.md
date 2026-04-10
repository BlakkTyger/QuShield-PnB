# Phase 8 — Feature Expansion Plan (Deep Scan UX, AI, PQC Detection, Risk Models)

> **Generated**: 2026-04-10
> **Status**: 🔧 PLANNING
> **Predecessor**: Phase 7B (Feature Expansion — ✅ COMPLETE)

---

## Overview

Phase 8 introduces 8 major feature categories:
1. **Deep Scan Streaming** — Background process + SSE progress + live data streaming
2. **AI Features** — RAG chatbot, migration roadmap generation, report generation, tiered inference
3. **HQC Detection** — Pre-populate NIST level mapping for backup KEM
4. **FN-DSA (FALCON) Detection** — Pre-populate OIDs for forthcoming FIPS 206
5. **Monte Carlo CRQC Simulation** — Probability-weighted risk distribution
6. **Certificate Expiry vs CRQC Race** — Migration planning comparison endpoint
7. **Vendor PQC Readiness (Dynamic)** — Expanded vendor tracking with comprehensive data
8. **JWT Algorithm Deep Parsing** — Reliable `alg` header extraction from JWT tokens

---

## Execution Plan

### Track A — Deep Scan Streaming & Background Process (Feature a)

- [x] **A.1** — Backend SSE (Server-Sent Events) infrastructure ✅
  - [x] A.1.1 — Create class `ScanEventManager` ✅
  - [x] A.1.2 — Dict storing async queues or generators mapped by `scan_id` ✅
  - [x] A.1.3 — Event payload schema: `{event_type, scan_id, phase, progress_pct, message, data, timestamp}` ✅
  - [x] A.1.4 — Standalone test: publish 5 events → subscriber receives all 5 ✅

- [x] **A.2** — Orchestrator integration: emit events during scan pipeline ✅
  - [x] A.2.1 — Emit `phase_start` at each phase entry (1-6)
  - [x] A.2.2 — Emit `phase_progress` with % complete during Phase 2 (crypto inspection): `{processed: N, total: M, pct: X}`
  - [x] A.2.3 — Emit `asset_discovered` with hostname + IP as assets are found in Phase 1
  - [x] A.2.4 — Emit `crypto_result` with per-asset TLS version, cipher, risk level as Phase 2 completes each asset
  - [x] A.2.5 — Emit `phase_complete` with summary stats at end of each phase
  - [x] A.2.6 — Emit estimated time remaining based on avg per-asset processing time
  - [x] A.2.7 — Integration test: run mini-scan, verify events emitted

- [x] **A.3** — SSE API endpoint ✅
  - [x] A.3.1 — `GET /api/v1/scans/{scan_id}/stream` — SSE endpoint that streams scan events
  - [x] A.3.2 — Support reconnection via `Last-Event-ID` header
  - [x] A.3.3 — Auto-close stream when scan completes
  - [x] A.3.4 — Integration test: start scan → subscribe to SSE → verify events received

- [x] **A.4** — Frontend documentation updates ✅
  - [x] A.4.1 — Update `03-FRONTEND.md`: Add SSE connection spec, progress UI components, live data feed
  - [x] A.4.2 — Document reconnection strategy, error handling, event parsing

---

### Track B — HQC Detection (Feature c)

- [x] **B.1** — Add HQC to NIST quantum level mapping ✅
  - [x] B.1.1 — Add to `nist_quantum_levels.json`: HQC-128 (Level 1), HQC-192 (Level 3), HQC-256 (Level 5) ✅
  - [x] B.1.2 — Add placeholder OIDs to `pqc_oids.json` with `"draft": true` flag (no official OIDs yet — NIST IR 8545 selected HQC Mar 2025, FIPS draft ~2027) ✅
  - [x] B.1.3 — Add HQC cipher name patterns to `detect_pqc()` for future detection ✅
  - [x] B.1.4 — Standalone test: verify HQC-128→L1, HQC-192→L3, HQC-256→L5 lookup works ✅
  - [x] B.1.5 — DEV_LOG entry ✅

---

### Track C — FN-DSA (FALCON) Detection (Feature d)

- [x] **C.1** — Add FN-DSA to detection tables ✅
  - [x] C.1.1 — Add to `nist_quantum_levels.json`: FN-DSA-512 (Level 1), FN-DSA-1024 (Level 5) ✅
  - [x] C.1.2 — Add draft OIDs to `pqc_oids.json` (FIPS 206 pending, expected H2 2026) ✅
  - [x] C.1.3 — Add FALCON/FN-DSA signature patterns to `detect_pqc()` OID check ✅
  - [x] C.1.4 — Add hybrid signature detection: FALCON + ECDSA combinations ✅
  - [x] C.1.5 — Standalone test: verify FN-DSA-512→L1, FN-DSA-1024→L5 ✅
  - [x] C.1.6 — DEV_LOG entry ✅

---

### Track D — Monte Carlo CRQC Arrival Simulation (Feature e)

- [x] **D.1** — Monte Carlo simulation service
  - [x] D.1.1 — Create `backend/app/services/monte_carlo.py`
  - [x] D.1.2 — Function `simulate_crqc_arrival(n_simulations=10000, mode_year=2032, sigma=3)`:
    - Sample CRQC arrival year from log-normal distribution
    - Return: probability distribution by year, expected arrival year, confidence intervals (5%/25%/50%/75%/95%)
  - [x] D.1.3 — Function `simulate_asset_exposure(asset_mosca_x, asset_mosca_y, n_simulations=10000)`:
    - For each simulation: compute if X+Y > Z for that CRQC sample
    - Return: probability of exposure, expected year of first exposure, exposure probability curve
  - [x] D.1.4 — Function `simulate_portfolio(assets: list, n_simulations=10000)`:
    - Run simulation for all assets against same CRQC samples
    - Return: per-asset exposure probability + portfolio-level stats
  - [x] D.1.5 — Standalone test: verify distribution shape, probability bounds, deterministic with seed

- [x] **D.2** — Monte Carlo API endpoint
  - [x] D.2.1 — `POST /api/v1/risk/monte-carlo/simulate` — custom parameters
  - [x] D.2.2 — `GET /api/v1/risk/scan/{id}/monte-carlo` — full portfolio simulation from scan data
  - [x] D.2.3 — Response includes: probability curve data (year → probability), per-asset exposure probability, portfolio summary
  - [x] D.2.4 — Integration test + DEV_LOG entry

- [x] **D.3** — Frontend documentation
  - [x] D.3.1 — Update `03-FRONTEND.md`: probability curve chart spec, Monte Carlo results display

---

### Track E — Certificate Expiry vs CRQC Race (Feature f)

- [x] **E.1** — Certificate race analysis service ✅
  - [x] E.1.1 — Add function to `risk_engine.py`: `compute_cert_crqc_race(scan_id, db)` ✅
  - [x] E.1.2 — For each certificate: compute `cert_expiry_date` vs `estimated_pqc_migration_completion_date` ✅
  - [x] E.1.3 — Flag categories: ✅
    - `natural_rotation`: cert expires BEFORE migration completes → good (natural swap opportunity)
    - `at_risk`: cert will NOT expire before CRQC arrival → bad (classical cert compromised while valid)
    - `safe`: cert already PQC or expires before CRQC
  - [x] E.1.4 — Compute migration completion estimate from migration complexity scores ✅
  - [x] E.1.5 — Standalone test: mock certs with various expiry dates → verify classification ✅

- [x] **E.2** — Certificate race API endpoint ✅
  - [x] E.2.1 — `GET /api/v1/risk/scan/{id}/cert-race` — returns per-certificate race analysis ✅
  - [x] E.2.2 — Response includes: cert details, expiry date, CRQC arrival estimate, migration estimate, race_status, recommendation ✅
  - [x] E.2.3 — Summary: count of natural_rotation / at_risk / safe certs ✅
  - [x] E.2.4 — Integration test + DEV_LOG entry ✅

---

### Track F — Vendor PQC Readiness Expansion (Feature g)

- [x] **F.1** — Expand vendor readiness data ✅
  - [x] F.1.1 — Update `vendor_readiness.json` with comprehensive data for 15+ vendors ✅ (19 vendors)
  - [x] F.1.2 — For each vendor: pqc_status, supported_algorithms, target_version, expected_date, risk_if_delayed, last_updated ✅
  - [x] F.1.3 — Verify existing `GET /api/v1/compliance/vendor-readiness` returns expanded data ✅
  - [x] F.1.4 — DEV_LOG entry ✅

---

### Track G — JWT Algorithm Deep Parsing (Feature h)

- [x] **G.1** — Enhanced JWT parsing in crypto inspector ✅
  - [x] G.1.1 — Add function `parse_jwt_algorithm(token: str) -> dict` to `crypto_inspector.py` ✅
  - [x] G.1.2 — JWT algorithm quantum mapping: 30 algorithms mapped (HS/RS/PS/ES/EdDSA/ML-DSA/FN-DSA/none) ✅
  - [x] G.1.3 — Integrate into `detect_api_auth()`: when JWT found, always attempt deep parsing ✅
  - [x] G.1.4 — Handle edge cases: truncated JWTs, non-standard encoding, missing `alg` field ✅
  - [x] G.1.5 — Standalone test: craft mock JWTs with various alg headers → verify correct extraction ✅ (13 tests)
  - [x] G.1.6 — Integration test + DEV_LOG entry ✅

---

### Track H — AI Features (Feature b) — PLANNING REQUIRED

> This is the most complex track. Full planning phase before implementation.

#### H.1 — AI Architecture Planning ✅
- [x] **H.1.1** — Research and document AI architecture in `IMPL_SCRATCHPAD.md`: ✅
  - **Secure (Local)** mode: Ollama (generation) + nomic-embed-text (embeddings) + ChromaDB (vector store)
  - **Cloud** mode: OpenAI-compatible APIs for all tasks (generation + embeddings)
  - Provider abstraction layer supporting both modes
- [x] **H.1.2** — Define tier model (2 deployment modes × 3 tiers each): ✅

  **🔒 Secure (Local) Mode** — All data stays on-premise, models run locally:
  | Tier | Generation Model | Embedding Model | Limits |
  |---|---|---|---|
  | Free | Qwen 2.5 3B (~3GB VRAM) | nomic-embed-text (Ollama) | 10 queries/day |
  | Professional | Qwen 2.5 7B or Mistral 7B (~8GB VRAM) | nomic-embed-text (Ollama) | Unlimited |
  | Enterprise | Llama 3.1 70B or Mixtral 8x7B (~40GB VRAM) | nomic-embed-text (Ollama) | Unlimited + priority |

  **☁️ Cloud Mode** — Data sent to cloud APIs, higher accuracy, faster inference:
  | Tier | Generation Model | Embedding Model | Limits |
  |---|---|---|---|
  | Free | Groq (Llama 3.3 70B / Gemma 2 9B) | Groq embeddings | Rate-limited by Groq free tier |
  | Professional | OpenAI GPT-4o / Anthropic Claude 3.5 / Gemini 1.5 Pro | OpenAI text-embedding-3-small | Unlimited (user's API key) |
  | Enterprise | OpenAI GPT-4o / Anthropic Claude Opus / Gemini 1.5 Pro | OpenAI text-embedding-3-large | Unlimited + dedicated |

- [x] **H.1.3** — Document model selection rationale per tier in `IMPL_SCRATCHPAD.md` ✅
- [x] **H.1.4** — Document embedding model selection: ✅
  - Local (all tiers): nomic-embed-text (768-dim, via Ollama) — fast, private
  - Cloud Free: Groq-compatible embeddings
  - Cloud Pro/Enterprise: OpenAI text-embedding-3-small/large or Gemini embeddings

#### H.2 — AI Service Core (Backend) ✅
- [x] **H.2.1** — Create `backend/app/services/ai_service.py`: ✅
  - LLM provider abstraction: `LocalProvider(Ollama)`, `GroqProvider`, `OpenAIProvider`, `AnthropicProvider`, `GeminiProvider`
  - Provider selection based on user's `deployment_mode` (secure/cloud) + `ai_tier` (free/professional/enterprise)
  - Unified `generate(prompt, model=None, stream=False)` interface
  - Model auto-selection based on tier
- [x] **H.2.2** — Create `backend/app/services/embedding_service.py`: ✅
  - Embedding provider abstraction: `LocalEmbedder(Ollama)`, `GroqEmbedder`, `OpenAIEmbedder`
  - Unified `embed(texts: list[str])` interface
  - Provider selection based on deployment mode + tier
- [x] **H.2.3** — Create `backend/app/services/vector_store.py`: ✅
  - ChromaDB integration for local vector storage
  - Collections: cbom_summaries, risk_narratives, scan_findings, regulatory_docs, playbooks
  - **CRITICAL**: Strict tenant isolation. Queries and documents must be filtered by `user_id` metadata. No data leakage between users.
  - `embed_scan_data(scan_id)` — chunk + embed all scan data with `user_id` isolation
  - `search_context(query, user_id, n_results=5)` — semantic search
- [x] **H.2.4** — Standalone tests: embedding, vector search, generation ✅

#### H.3 — RAG Chatbot (Module 10.1) ✅
- [x] **H.3.1** — Implement RAG pipeline in `ai_service.py`: ✅
  - Query → Embed → Search ChromaDB → Build context → Generate response
  - System prompt: banking PQC expert, answer from context only
  - Support streaming via SSE
- [x] **H.3.2** — API endpoints: ✅
  - `POST /api/v1/ai/chat` — send message, get response (or SSE stream)
  - `POST /api/v1/ai/embed/refresh` — re-embed scan data
  - `GET /api/v1/ai/status` — check AI readiness (models available, vector store status)
- [x] **H.3.3** — SQL Tabular Data Agent: ✅
  - Create `backend/app/services/sql_agent.py` to allow the LLM to write and execute read-only SQLite/Postgres queries for tabular data (assets, certificates, compliance) because embeddings are poor at tabular lookups.
  - Ensure strict tenant isolation: queries MUST only execute against rows matching `user_id`.
- [x] **H.3.4** — Integration test + DEV_LOG entry ✅

#### H.4 — AI Migration Roadmap Generation (Module 10.2) ✅
- [x] **H.4.1** — Research PQCC migration roadmap (https://pqcc.org): ✅
  - 4-phase migration: Inventory → Prioritize → Migrate → Verify
  - NIST SP 1800-38 recommendations
  - India-specific: C-DOT national roadmap (Feb 2026)
- [x] **H.4.2** — Implement `generate_migration_roadmap(scan_id, db)`: ✅
  - Pull scan data + risk scores + compliance data
  - Build structured prompt with asset inventory and risk analysis
  - Generate per-asset and portfolio-level migration recommendations
  - Include specific library versions, config changes, timelines
- [x] **H.4.3** — Store roadmap data as structured JSON in DB ✅
- [x] **H.4.4** — API: `POST /api/v1/ai/migration-roadmap/{scan_id}` — generate AI roadmap ✅
- [x] **H.4.5** — DEV_LOG entry ✅

#### H.5 — AI Report Generation (Module 10.3, 11.2) ✅
- [x] **H.5.1** — Create `backend/app/services/report_generator.py`: ✅
  - Uses basic UI charts for generation.
- [x] **H.5.2** — AI executive summary generation: ✅
  - Build structured prompt from scan summary data
  - Generate board-level narrative: risk position, key findings, recommendations
- [x] **H.5.3** — Jinja2 HTML templates for reports: ✅
  - `executive.html` — summary + charts + AI narrative
- [x] **H.5.4** — PDF generation via WeasyPrint ✅
- [x] **H.5.5** — API endpoints: ✅
  - `POST /api/v1/reports/generate/{id}` — start report generation
- [x] **H.5.6** — DEV_LOG entry ✅

#### H.6 — AI Tier & Deployment Mode Management ✅
- [x] **H.6.1** — Add fields to User model: ✅
  - `deployment_mode`: `secure` | `cloud` (default: `secure`)
  - `ai_tier`: `free` | `professional` | `enterprise` (default: `free`)
  - `cloud_api_keys`: JSON field for user's API keys (encrypted): `{openai_key, anthropic_key, gemini_key, groq_key}`
  - No payment integration yet (POC phase — tier is self-selected)
- [x] **H.6.2** — Tier enforcement middleware: ✅
  - Secure Free: 10 chat queries/day, basic reports only
  - Secure Pro: unlimited chat + reports, larger local model
  - Secure Enterprise: unlimited, largest local model, priority inference
  - Cloud Free: rate-limited by Groq free tier
  - Cloud Pro: unlimited (user's API key), best models from OpenAI/Anthropic/Gemini
  - Cloud Enterprise: unlimited, dedicated config, full model selection
- [x] **H.6.3** — API: `GET /api/v1/ai/status` — list available tiers with features per deployment mode ✅
- [ ] **H.6.4** — API: `PATCH /api/v1/users/me/ai-settings` — update deployment_mode, ai_tier, api_keys
- [ ] **H.6.5** — API: `GET /api/v1/ai/models` — list available models for current deployment_mode + tier
- [ ] **H.6.6** — DEV_LOG entry

#### H.7 — Documentation Updates
- [ ] **H.7.1** — Update `03-FRONTEND.md`: AI chat page, report builder page, tier selection UI
- [ ] **H.7.2** — Update `04-SYSTEM_ARCHITECTURE.md`: AI service architecture, provider abstraction, vector store design
- [ ] **H.7.3** — Update `06-DEVELOPMENT_PLAN.md`: Phase 8 AI milestones
- [ ] **H.7.4** — Update `06g-PLAN_P9.md`: revise with concrete AI plan (replaces old Phase 9)

---

## Execution Order

**Priority**: Low-effort high-impact first → Complex AI features last (planning before implementation)

| Step | Checkpoint | Depends On | Effort |
|---|---|---|---|
| 1 | B.1 (HQC Detection) | — | Low |
| 2 | C.1 (FN-DSA Detection) | — | Low |
| 3 | G.1 (JWT Deep Parsing) | — | Low |
| 4 | F.1 (Vendor Readiness Expansion) | — | Low |
| 5 | E.1–E.2 (Cert Expiry vs CRQC Race) | — | Low-Medium |
| 6 | D.1–D.3 (Monte Carlo Simulation) | — | Medium |
| 7 | A.1–A.4 (Deep Scan Streaming) | — | Medium |
| 8 | H.1 (AI Architecture Planning) | — | Research |
| 9 | H.2 (AI Service Core) | H.1 | Medium |
| 10 | H.3 (RAG Chatbot) | H.2 | Medium |
| 11 | H.4 (AI Migration Roadmap) | H.3 | Medium-High |
| 12 | H.5 (AI Report Generation) | H.2 | Medium-High |
| 13 | H.6 (AI Tier Management) | H.2 | Low |
| 14 | H.7 (Doc Updates) | All above | Low |

---

## Rules

- Test each feature independently before integrating
- Do not break existing Deep Scan pipeline
- Log every feature addition and test result to `DEV_LOG.md`
- Use `IMPL_SCRATCHPAD.md` for reasoning and research
- Do not start frontend — only update `03-FRONTEND.md` for documentation
- Keep `07-PQC_IMPROVEMENTS.md` and `OUTPUT_diffs.md` current
- After every feature is implemented, return to this document and update checkboxes