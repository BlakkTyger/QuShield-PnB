# Phase 5 — Scan Orchestrator (Pipeline Integration)

> **Goal**: Wire together Discovery → Crypto Inspector → CBOM → Risk into a single end-to-end scan pipeline triggered by a function call. This is the integration phase.
> **Estimated time**: 3–4 hours
> **Dependencies**: P1 + P2 + P3 + P4 all complete and standalone tests passing

---

## Checklist

### P5.1 — Orchestrator Class
- [ ] Create `backend/app/services/orchestrator.py`:
  - Class `ScanOrchestrator`:
    - Method `start_scan(targets: list[str], config: dict = None) -> str`
      - Creates `ScanJob` record in DB (status=queued)
      - Returns `scan_id`
    - Method `run_scan(scan_id: str) -> dict`
      - Executes phases sequentially with retry logic:
      ```
      Phase 0: Validate targets (domain format, reachability check)
      Phase 1: Run Discovery Engine (Go binary via subprocess)
      Phase 2: Run Crypto Inspector on all discovered assets
      Phase 3: Build CBOM for each asset
      Phase 4: Compute risk scores for all assets
      ```
      - Updates `ScanJob.status` and `ScanJob.current_phase` after each phase
      - On failure: retry the phase up to 3 times (simple try/except with sleep 2s, 4s, 8s)
      - On complete: set status=completed, record `completed_at`
      - Returns: scan summary dict

    - Method `get_scan_status(scan_id: str) -> dict`
      - Returns current status, phase, progress, timing

  - **Retry logic** (replacing Temporal for POC):
    ```python
    for attempt in range(max_retries):
        try:
            result = phase_function()
            break
        except Exception as e:
            wait_time = 2 ** (attempt + 1)
            logger.warning(f"Phase {phase} failed, retry {attempt+1}/{max_retries} in {wait_time}s", ...)
            time.sleep(wait_time)
    ```

  - **Progress tracking**: after each phase, update scan_job record:
    ```python
    scan_job.current_phase = phase_number
    scan_job.status = "running"
    db.commit()
    ```

  - Logs: phase transitions, asset counts per phase, timing per phase, total duration

- [ ] **Phase 0 — Target Validation**:
  - Function `validate_targets(targets: list[str]) -> list[str]`
  - Validate: domain format (regex), not an IP in private range, DNS resolves
  - Returns: list of validated targets
  - Logs: input count, valid count, invalid targets with reasons

**✅ Verify**: Create orchestrator instance, call `validate_targets(["google.com", "not_a_domain", "192.168.1.1"])` → returns `["google.com"]`, logs invalids

---

### P5.2 — End-to-End Pipeline Test
- [ ] Create `backend/tests/integration/test_full_pipeline.py`:
  - Test: Run full scan against `example.com`
  - Assert Phase 1: At least 1 asset discovered
  - Assert Phase 2: All discovered assets have crypto fingerprints
  - Assert Phase 3: All assets have CBOM records  
  - Assert Phase 4: All assets have risk scores
  - Assert: ScanJob status = "completed"
  - Assert: All database tables have records for this scan_id
  - Timing: Full pipeline < 120 seconds for 1 domain

**✅ Integration Test**:
```bash
cd backend && python -m pytest tests/integration/test_full_pipeline.py -v --timeout=180
```

**📝 Log to DEV_LOG.md**: Pipeline timing per phase, asset counts, risk distribution, any errors

---

### P5.3 — Smoke Test Script
- [ ] Update `scripts/smoke_test.py`:
  - Takes domain as CLI argument
  - Runs the full pipeline using `ScanOrchestrator`
  - Prints a structured summary using `rich`:
    ```
    ╔══════════════════════════════════════════╗
    ║     QuShield-PnB Smoke Test Report      ║
    ╠══════════════════════════════════════════╣
    ║ Domain:     example.com                  ║
    ║ Status:     ✅ COMPLETED                 ║
    ║ Duration:   47.3 seconds                 ║
    ╠══════════════════════════════════════════╣
    ║ Phase 1 — Discovery                      ║
    ║   Assets found: 3                        ║
    ║   Time: 12.1s                            ║
    ║ Phase 2 — Crypto Inspection              ║
    ║   TLS scanned: 3                         ║
    ║   Certificates: 7                        ║
    ║   Time: 18.4s                            ║
    ║ Phase 3 — CBOM Generation                ║
    ║   Components: 15                         ║
    ║   Vulnerable: 8                          ║
    ║   Time: 2.3s                             ║
    ║ Phase 4 — Risk Assessment                ║
    ║   Quantum Critical: 1                    ║
    ║   Quantum Vulnerable: 2                  ║
    ║   Average Risk Score: 742                ║
    ║   Time: 1.5s                             ║
    ╚══════════════════════════════════════════╝
    ```

**✅ Smoke Test**:
```bash
python scripts/smoke_test.py example.com
# Expected: Colored summary showing all 4 phases complete
```

---

**✅ Phase 5 Complete** when:
1. `python scripts/smoke_test.py example.com` completes successfully
2. Integration test passes within 120 seconds
3. All database tables populated for the test scan
4. No phase-to-phase data loss (every discovered asset has crypto + CBOM + risk)
5. `DEV_LOG.md` has full pipeline results


---

# Phase 6 — Compliance Engine & Graph Builder

> **Goal**: Implement regulatory compliance checks and the in-memory graph topology with blast radius analysis.
> **Estimated time**: 4–5 hours
> **Dependencies**: P5 complete (full pipeline data in DB)

---

## Checklist

### P6.1 — Standalone: Compliance Rule Engine
- [ ] Create `backend/app/services/compliance.py`:
  - Function `evaluate_compliance(asset_id: str, cbom_data: dict, crypto_data: dict) -> dict`
  - Checks (all boolean — pass/fail):
    1. **FIPS 203**: ML-KEM deployed? (check CBOM components)
    2. **FIPS 204**: ML-DSA deployed? 
    3. **FIPS 205**: SLH-DSA available?
    4. **TLS 1.3 Enforced**: TLS version ≥ 1.3 AND no TLS 1.0/1.1 support
    5. **Forward Secrecy**: key exchange uses ECDHE/DHE/ML-KEM
    6. **Cert Key Length**: public key ≥ 2048 bits
    7. **CT Logged**: certificate found in CT logs
    8. **Chain Valid**: certificate chain validates correctly
  - Returns: `{"checks": [...], "passed": int, "failed": int, "compliance_pct": float}`
  - Logs: asset_id, checks passed/failed, compliance percentage

- [ ] Create `backend/tests/standalone/test_compliance.py`:
  - Test 1: Asset with TLS 1.3 + ECDHE + RSA-4096 cert → passes TLS/FS/key-length, fails FIPS
  - Test 2: Asset with TLS 1.0 + RSA key exchange → fails TLS, FS, multiple checks
  - Test 3: Full PQC asset (hypothetical) → passes everything

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_compliance.py -v
```

---

### P6.2 — Standalone: Crypto-Agility Score
- [ ] Add function to `compliance.py`:
  - Function `compute_agility_score(asset_data: dict, cert_history: list = None) -> dict`
  - Five factors (20 points each, total 0–100):
    1. **Dynamic cipher negotiation** (20): Server preference configured? Check if SSLyze detected server cipher preference vs client preference
    2. **Automated cert renewal** (20): Cert issuer is Let's Encrypt? Cert lifetime < 90 days?
    3. **Key rotation frequency** (20): Default 10/20 for first scan (no history). If history: check rotation interval
    4. **Crypto library recency** (20): Detected OpenSSL/library version within 1 year of latest
    5. **Documented ownership** (20): Default 10/20 for POC (user hasn't input ownership data yet)
  - Returns: `{"agility_score": int, "factors": [...]}`
  - Logs: each factor's score, total

**✅ Standalone Test**: Test with google.com data (likely auto-renewal, modern cipher) → expect score > 50

---

### P6.3 — Standalone: In-Memory Graph Builder (NetworkX)
- [ ] Create `backend/app/services/graph_builder.py`:
  - Function `build_topology_graph(scan_id: str, db: Session) -> dict`
  - Uses `networkx.DiGraph()` to build the topology:
    - Nodes: Domain, IP, Certificate, Service (with type attribute)
    - Edges: RESOLVES_TO, USES_CERTIFICATE, RUNS_SERVICE, ISSUED_BY, CHAINS_TO
  - For each node: attach metadata (risk_class, pqc_ready, nist_level)
  - Serializes graph to JSON: `{"nodes": [...], "edges": [...]}`
  - Saves JSON to `data/graphs/{scan_id}.json`
  - Logs: node count by type, edge count, file size

- [ ] Create `backend/tests/standalone/test_graph_builder.py`:
  - Build graph from mock data (3 domains, 2 IPs, 4 certs)
  - Assert: correct node count, correct edge count
  - Assert: JSON output parseable

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_graph_builder.py -v
```

---

### P6.4 — Standalone: Blast Radius Computation
- [ ] Add function to `graph_builder.py`:
  - Function `compute_blast_radius(graph: nx.DiGraph, cert_fingerprint: str) -> dict`
  - Algorithm: BFS from certificate node → count all reachable Domain nodes
    - Follow edges: USES_CERTIFICATE (reverse), CHAINS_TO, SHARES_CERT_WITH
  - Returns: `{"certificate": fingerprint, "blast_radius": int, "affected_domains": [str], "affected_services": [str]}`
  - Uses `networkx.bfs_tree()` for traversal
  - Logs: cert fingerprint, blast radius count

- [ ] Add function `compute_all_blast_radii(graph: nx.DiGraph) -> list[dict]`:
  - Runs blast radius for every certificate node
  - Sorts by blast radius descending
  - Returns list

**✅ Standalone Test**:
```bash
# Test: Graph with 1 cert shared by 3 domains → blast_radius = 3
cd backend && python -m pytest tests/standalone/test_graph_builder.py::test_blast_radius -v
```

---

### P6.5 — Integration: Add Compliance & Graph to Pipeline
- [ ] Update `orchestrator.py` to add:
  ```
  Phase 5a: Run compliance checks for all assets (parallel-ready)
  Phase 5b: Build topology graph + blast radius (parallel-ready)
  ```
  - Both run after Phase 4 (risk engine)
  - Save compliance results to DB
  - Save graph JSON to filesystem
  - Update scan_job to include Phase 5

- [ ] Update integration test and smoke test to verify Phase 5a and 5b

**✅ Integration Test**:
```bash
cd backend && python -m pytest tests/integration/test_full_pipeline.py -v
python scripts/smoke_test.py example.com
# Verify: compliance_results table populated, graph JSON exists
```

---

**✅ Phase 6 Complete** when:
1. Compliance checks correctly evaluate all 8 rules
2. Crypto-agility scores compute correctly (0-100 range)
3. NetworkX graph builds with correct structure
4. Blast radius correctly computed via BFS
5. Both integrated into the pipeline, smoke test shows Phase 5
6. `DEV_LOG.md` updated with Phase 6 entries
