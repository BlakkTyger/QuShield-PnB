# Phase 9 — AI Service & Reports (Optional — Deprioritized)

> **Goal**: Add RAG chatbot and PDF report generation. These are value-add features — the core POC is complete at Phase 8.
> **Estimated time**: 5–6 hours
> **Dependencies**: P7 complete (API serving data), Ollama installed
> **External requirement**: Ollama + Qwen 2.5 7B model + nomic-embed-text

---

## Pre-requisites (Developer Action Required)

```bash
# Install Ollama (one-time)
curl -fsSL https://ollama.com/install.sh | sh

# Pull models (one-time, ~5GB total)
ollama pull qwen2.5:7b
ollama pull nomic-embed-text

# Verify Ollama is running
curl http://localhost:11434/api/tags
```

> [!IMPORTANT]
> This phase requires a GPU with ≥8GB VRAM for reasonable inference speed. If no GPU is available, use `qwen2.5:3b` (smaller model, lower quality) or skip this phase entirely — the POC works without AI features.

---

## Checklist

### P9.1 — Standalone: Ollama Connectivity Test
- [ ] Create `backend/app/services/ai_service.py`:
  - Function `test_ollama_connection() -> bool`
  - Pings `http://localhost:11434/api/tags`
  - Lists available models
  - Returns True if Qwen 2.5 and nomic-embed-text are available
  - Logs: Ollama version, available models

- [ ] Create `backend/tests/standalone/test_ai_service.py`:
  - Test: Ollama reachable, models available
  - Test: Simple generation: `"What is TLS 1.3?"` → returns non-empty response

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_ai_service.py::test_ollama_connection -v
```

---

### P9.2 — Standalone: Embedding & Vector Search (ChromaDB)
- [ ] Add to `ai_service.py`:
  - Function `initialize_vector_store() -> ChromaDB collection`
  - Function `embed_scan_data(scan_id: str, db: Session)`
    - Pulls: CBOM summaries, risk narratives, compliance results
    - Chunks text into ~512 token segments
    - Embeds via Ollama's nomic-embed-text
    - Stores in ChromaDB with metadata (scan_id, asset_id, doc_type)
  - Function `search_context(query: str, n_results: int = 5) -> list[str]`
    - Semantic search in ChromaDB
    - Returns top relevant chunks
  - Logs: documents embedded, search results count, search latency

- [ ] Add to `test_ai_service.py`:
  - Test: Embed 3 mock documents → search "which assets use RSA" → returns relevant doc

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_ai_service.py::test_vector_search -v
```

---

### P9.3 — Standalone: RAG Chat Function
- [ ] Add to `ai_service.py`:
  - Function `chat(query: str, scan_id: str = None) -> str`
  - Flow:
    1. Search ChromaDB for relevant context chunks
    2. Build prompt: `[system prompt] + [retrieved chunks] + [user query]`
    3. Call Ollama API: `POST /api/generate` with model `qwen2.5:7b`
    4. Return response text
  - System prompt: `"You are a quantum cryptography expert analyzing a bank's security posture. Answer based ONLY on the provided context data. If you don't know, say so."`
  - Logs: query, chunks retrieved, prompt length, response length, inference time

- [ ] Add to `test_ai_service.py`:
  - Test: Embed scan data from previous pipeline run → ask "What is the highest risk asset?" → verify response references actual asset data

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_ai_service.py::test_chat -v
```

**📝 Log to DEV_LOG.md**: Response quality, inference time, context relevance

---

### P9.4 — AI API Endpoints
- [ ] Create `backend/app/api/v1/ai.py`:
  - `POST /api/v1/ai/chat` → `{"message": "...", "scan_id": "..."}` → `{"response": "..."}`
  - `POST /api/v1/ai/embed/refresh` → re-embed data for a scan → `{"status": "ok", "documents": N}`

---

### P9.5 — Standalone: PDF Report Generation
- [ ] Create `backend/app/services/report_generator.py`:
  - Function `generate_report(scan_id: str, report_type: str, db: Session) -> str`
  - Report types: `"executive"`, `"technical"`, `"cbom_audit"`
  - Flow:
    1. Pull all data from DB for the scan
    2. Build data context dict
    3. Render Jinja2 HTML template with data
    4. Convert HTML → PDF via WeasyPrint
    5. Save PDF to `data/reports/{scan_id}/{report_type}.pdf`
    6. Return file path
  - Logs: report type, page count, file size, generation time

- [ ] Create Jinja2 templates in `backend/app/templates/reports/`:
  - `executive.html` — high-level summary, risk score gauge, top findings
  - `technical.html` — full cipher suites, cert details, per-asset breakdown
  - `cbom_audit.html` — CycloneDX compliance format

- [ ] Create `backend/tests/standalone/test_report_generator.py`:
  - Test: Generate executive report from pipeline data → verify PDF file created, > 0 bytes

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_report_generator.py -v
# Verify: data/reports/{scan_id}/executive.pdf exists and opens correctly
```

---

### P9.6 — Reports API Endpoints
- [ ] Create `backend/app/api/v1/reports.py`:
  - `POST /api/v1/reports/generate` → `{"scan_id": "...", "report_type": "executive"}` → `{"job_id": "...", "status": "generating"}`
  - `GET /api/v1/reports/{job_id}/download` → Returns PDF file
  - `GET /api/v1/reports/` → List generated reports

---

### P9.7 — Frontend: AI Chat + Reports Pages
- [ ] Create AI Assistant page:
  - Chat interface (message input + scrollable message list)
  - Messages alternate: user (right-aligned) / AI (left-aligned with avatar)
  - Loading animation while AI generates response
  - Suggested questions: "What are our most vulnerable assets?", "Summarize the HNDL exposure"

- [ ] Create Reports page:
  - Report type selector (Executive / Technical / CBOM Audit)
  - "Generate Report" button → shows progress → download button when ready
  - Report history table: type, generated_at, file_size, download link

---

**✅ Phase 9 Complete** when:
1. RAG chatbot answers questions about scan data using real context
2. PDF reports generate with correct data from the pipeline
3. Frontend chat interface works end-to-end
4. Reports page generates and downloads PDFs
5. All standalone tests pass

---

## Post-POC — Production Preparation (Future, NOT in this iteration)

The following are explicitly deferred and will be addressed in a separate planning cycle:

- [ ] Replace in-memory queue with Apache Kafka
- [ ] Replace simple retry with Temporal workflows
- [ ] Replace in-memory cache with Redis
- [ ] Replace PostgreSQL full-text search with Elasticsearch
- [ ] Replace PostgreSQL risk history with ClickHouse
- [ ] Replace NetworkX with Neo4j
- [ ] Replace local filesystem with MinIO
- [ ] Replace ChromaDB with Qdrant
- [ ] Add Kong API Gateway
- [ ] Add Prometheus + Grafana monitoring
- [ ] Add OpenTelemetry + Jaeger tracing
- [ ] Add HashiCorp Vault for secrets
- [ ] Dockerize all services
- [ ] Kubernetes deployment manifests
- [ ] CI/CD pipelines (GitHub Actions)
- [ ] Authentication (JWT, RBAC)
- [ ] Multi-tenancy (org isolation)
