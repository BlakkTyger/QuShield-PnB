# Implementation Scratchpad

## Test Targets (PERSISTED)
- https://pnb.bank.in
- https://onlinesbi.sbi.bank.in  
- https://www.hdfc.bank.in

## Current Task: Phase 7B — Feature Expansion

---

## Phase Completion Summary

### Phase 0-6 ✅ (Completed)
### Phase 7 — REST API Layer ✅ COMPLETE
- 31 endpoints, 26/26 tests passing
- E2E validated: PNB (96 assets), SBI (87), HDFC (95)
- Enterprise Rating, Migration Plan, Vendor Readiness, Regulatory Countdown implemented

### Phase 7B — Feature Expansion ✅ COMPLETE
- All scan tiers (Quick/Shallow/Deep), JWT Auth, Endpoint Isolation, Incremental DB updates, and smart scan caching are completed.

### Phase 8 — Advanced PQC Features 🔧 IN PROGRESS

**Wave 1 (Config & Data)** ✅ Complete
- HQC and FN-DSA detection logic and NIST level mapping
- Comprehensive JWT edge-case detection and algorithm mapping
- Vendor readiness DB expanded to 19+ entries

**Wave 2 (Risk Simulations)** ✅ Complete
- `monte_carlo.py` providing log-normal distribution probability curves (replacing static 3-scenario estimates).
- Certificate Expiry vs CRQC Race categorization.

**Wave 3 (Deep Scan Streaming) Notes**:
- Need `ScanEventManager` (SSE).
- Can use Python `asyncio.Queue` mapped by `scan_id`.
- FastApi `StreamingResponse` requires async generators.
- Orchestrator `run_deep_scan` is async but calls synchronous background workers using `concurrent.futures`. Events emitted from within thread pools must safely send to the async queues via `asyncio.run_coroutine_threadsafe(queue.put(...), loop)` or we just emit from the async orchestrator when jobs complete. Emitting at phase boundaries from the main `orchestrator.py` async context is safest.

**Wave 4 (AI Features) - Architecture Research**:
- **Dual-Mode Deployment**: The core requirement is that banks can choose between 100% on-premise execution (Secure Mode) and Cloud API execution (Cloud Mode).
- **Core AI Abstraction (`app/services/ai_service.py`)**: We need a generic `Provider` interface with `generate_text()`, `generate_embeddings()`, and `chat()`.
- **Vector DB**: ChromaDB runs entirely local, in-memory or persisted to disk. Perfect for the Secure Mode requirement.

**Tier Model Definition & Selection**:

*🔒 Secure (Local) Mode* — All data stays on-premise, uses Ollama.
- **Free**: Generation: Qwen 2.5 3B (~3GB VRAM, highly capable for its size). Embeddings: `nomic-embed-text` (768-dim). Limits: 10 queries/day.
- **Professional**: Generation: Mistral 7B or Llama 3 8B. Embeddings: `nomic-embed-text`. Limits: Unlimited.
- **Enterprise**: Generation: Llama 3.1 70B (Requires ~40GB VRAM, multi-GPU). Embeddings: `nomic-embed-text`. Limits: Unlimited + priority queues.

*☁️ Cloud Mode* — Relies on Cloud Provider APIs (User provides API keys or we bill via subscription).
- **Free**: Generation: Groq (Llama 3 8B / Gemma 2 9B), fast and generous free limits. Embeddings: Groq/HuggingFace embeddings. Limits: Groq's rate limit.
- **Professional**: Generation: OpenAI GPT-4o-mini / Anthropic Claude 3.5 Haiku / Google Gemini 1.5 Flash. Embeddings: `text-embedding-3-small`. Limits: Subject to user's API balance.
- **Enterprise**: Generation: OpenAI GPT-4o / Anthropic Claude 3.5 Sonnet / Google Gemini 1.5 Pro. Embeddings: `text-embedding-3-large`. Limits: Unlimited.

**RAG Pipeline Strategy**:
When a scan completes, the `CryptoResult` and `RiskScore` models for high-risk assets are grouped, chunked, and pushed to ChromaDB. The user's query is vectorized with the selected embedding model, and we retrieve the Top-K relevant scan facts to stuff into the LLM context.

