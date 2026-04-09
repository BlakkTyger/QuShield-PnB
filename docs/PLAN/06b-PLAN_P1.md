# Phase 1 — Discovery Engine (Go Binary)

> **Goal**: Build a standalone Go CLI that takes a domain, discovers subdomains, resolves IPs, scans ports, probes HTTP services, and outputs a JSON file of discovered assets.
> **Estimated time**: 5–6 hours
> **Dependencies**: P0 complete, Go 1.22+ installed
> **External APIs**: subfinder sources (works without API keys, better with them)

---

## Architecture for POC

The Discovery Engine runs as a **standalone Go CLI binary** that:
1. Takes input: domain name(s) as CLI argument
2. Runs enumeration (subdomains, ports, HTTP probing)
3. Outputs: JSON file at `data/discovery/{scan_id}.json`
4. The Python backend calls this binary via `subprocess` and reads the output JSON

This avoids Kafka, avoids gRPC, avoids any inter-process communication complexity.

**Command**: `./discovery-engine --domain example.com --output data/discovery/sc_abc123.json`

---

## Checklist

### P1.1 — Go Project Setup
- [ ] Create `discovery/go.mod` with module name `qushield/discovery`
- [ ] Run `go mod init qushield/discovery`
- [ ] Install dependencies:
  ```bash
  cd discovery
  go get github.com/projectdiscovery/subfinder/v2/pkg/runner
  go get github.com/projectdiscovery/dnsx/libs/dnsx  
  go get github.com/projectdiscovery/naabu/v2/pkg/runner
  go get github.com/projectdiscovery/httpx/runner
  go get github.com/oschwald/geoip2-golang
  go mod tidy
  ```
- [ ] Create `discovery/internal/config/config.go` — reads env vars for API keys
- [ ] Create `discovery/internal/logger/logger.go` — structured JSON logger to file + stdout
  - Log format must match the Python logger format (same JSON fields)
  - Writes to `logs/discovery/{date}.jsonl`

**✅ Verify**: `cd discovery && go build ./... && echo "Build OK"` → prints "Build OK"

---

### P1.2 — Standalone: Subdomain Enumeration (subfinder)
- [ ] Create `discovery/pkg/subdomain/subdomain.go`:
  - Function `Enumerate(domain string, apiKeys map[string]string) ([]string, error)`
  - Uses subfinder's `runner` package programmatically
  - Returns deduplicated list of discovered subdomains
  - Logs: domain input, source count, subdomain count, duration

- [ ] Create `discovery/tests/subdomain_test.go`:
  - Test against `hackerone.com` (known to have many subdomains)
  - Assert: at least 5 subdomains returned
  - Assert: all subdomains end with `.hackerone.com`
  - Log: full list of subdomains found + timing

**✅ Standalone Test**: 
```bash
cd discovery && go test ./pkg/subdomain/ -v -run TestEnumerate -count=1
# Expected: PASS, 5+ subdomains found for hackerone.com, logged to logs/discovery/
```

**📝 Log to DEV_LOG.md**: subdomains found, timing, any errors

---

### P1.3 — Standalone: DNS Resolution (dnsx)
- [ ] Create `discovery/pkg/dns/resolver.go`:
  - Function `Resolve(subdomains []string) ([]ResolvedHost, error)`
  - `ResolvedHost` struct: `Hostname, IPv4, IPv6, CNAME string`
  - Uses dnsx for concurrent A/AAAA/CNAME resolution
  - Logs: input count, resolved count, failed count, duration

- [ ] Create `discovery/tests/resolver_test.go`:
  - Input: `["www.google.com", "mail.google.com", "nonexistent.example.invalid"]`
  - Assert: google.com resolves to valid IPs
  - Assert: nonexistent returns empty/error
  - Assert: timing < 5 seconds

**✅ Standalone Test**:
```bash
cd discovery && go test ./pkg/dns/ -v -run TestResolve -count=1
```

**📝 Log to DEV_LOG.md**: resolved count, sample IPs, timing

---

### P1.4 — Standalone: Port Scanning (naabu)
- [ ] Create `discovery/pkg/portscan/scanner.go`:
  - Function `Scan(hosts []string, ports string) ([]PortResult, error)`
  - `PortResult` struct: `Host, IP string; Port int; Protocol string`
  - Uses naabu with CONNECT scan (no root needed) for POC
  - Default: scan top 100 ports (not 1000 — faster for POC)
  - Rate limit: 500 packets/sec (polite scanning)
  - Logs: host count, open port count, duration

- [ ] Create `discovery/tests/portscan_test.go`:
  - Test against `scanme.nmap.org` (explicitly allows scanning)
  - Assert: port 80 and/or 22 found open
  - Assert: timing < 30 seconds

**✅ Standalone Test**:
```bash
cd discovery && go test ./pkg/portscan/ -v -run TestScan -count=1
# NOTE: May need sudo for SYN scan. CONNECT scan works without.
```

**📝 Log to DEV_LOG.md**: open ports found, timing

---

### P1.5 — Standalone: HTTP Probing (httpx)
- [ ] Create `discovery/pkg/httpprobe/prober.go`:
  - Function `Probe(targets []string) ([]HTTPResult, error)`
  - `HTTPResult` struct: `URL, Host, StatusCode, Title, WebServer, TLSVersion, ContentLength, Technologies`
  - Uses httpx for HTTP/HTTPS probing
  - Follows redirects, captures response headers
  - Logs: input count, live hosts, HTTPS count, duration

- [ ] Create `discovery/tests/httpprobe_test.go`:
  - Test against `["https://example.com", "https://google.com"]`
  - Assert: both return status 200 or 301
  - Assert: web server detected (e.g., "nginx", "gws")

**✅ Standalone Test**:
```bash
cd discovery && go test ./pkg/httpprobe/ -v -run TestProbe -count=1
```

**📝 Log to DEV_LOG.md**: live hosts, web servers detected, timing

---

### P1.6 — Standalone: Deduplication Engine
- [ ] Create `discovery/pkg/dedup/dedup.go`:
  - Function `Deduplicate(results []DiscoveredAsset) []DiscoveredAsset`
  - `DiscoveredAsset` struct: unifies subdomain + IP + port + HTTP probe data
  - Key: `SHA256(normalize(hostname) + ip + port)`
  - Confidence scoring: methods_that_found / total_methods
  - Logs: input count, output count (after dedup), duplicates removed

- [ ] Create `discovery/tests/dedup_test.go`:
  - Create mock assets with known duplicates
  - Assert: correct deduplication
  - Assert: confidence scores are accurate

**✅ Standalone Test**:
```bash
cd discovery && go test ./pkg/dedup/ -v -run TestDeduplicate -count=1
```

---

### P1.7 — CLI Integration: Full Discovery Pipeline
- [ ] Create `discovery/main.go`:
  - CLI flags: `--domain` (required), `--output` (JSON file path), `--ports` (default "top100"), `--timeout` (default 30s)
  - Orchestrates: subfinder → DNS resolve → naabu → httpx → dedup → write JSON
  - Output JSON schema:
    ```json
    {
      "scan_id": "sc_...",
      "domain": "example.com",
      "started_at": "...",
      "completed_at": "...",
      "assets": [
        {
          "hostname": "www.example.com",
          "ip_v4": "93.184.216.34",
          "ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
          "http": {"status_code": 200, "title": "Example Domain", "web_server": "ECS"},
          "discovery_methods": ["subfinder", "dns", "httpx"],
          "confidence_score": 0.6
        }
      ],
      "stats": {
        "subdomains_found": 5,
        "ips_resolved": 3,
        "open_ports": 8,
        "live_http": 4,
        "duration_seconds": 45.2
      }
    }
    ```
  - Print progress to stdout: `[1/5] Subdomain enumeration... found 12 subdomains`

- [ ] Build binary: `cd discovery && go build -o bin/discovery-engine .`

**✅ Integration Test**:
```bash
cd discovery && go build -o bin/discovery-engine .
./bin/discovery-engine --domain scanme.nmap.org --output /tmp/test_discovery.json
python -c "import json; d=json.load(open('/tmp/test_discovery.json')); print(f'Found {len(d[\"assets\"])} assets')"
# Expected: 1+ assets with open ports, valid JSON output
```

**📝 Log to DEV_LOG.md**: Full output stats, timing, any issues encountered

---

### P1.8 — Python Wrapper for Discovery Engine
- [ ] Create `backend/app/services/discovery_runner.py`:
  - Function `run_discovery(domain: str, scan_id: str) -> list[dict]`
  - Calls Go binary via `subprocess.run()`
  - Reads output JSON file
  - Returns list of discovered assets as Python dicts
  - Handles: binary not found, timeout (60s), non-zero exit code
  - Logs: subprocess command, exit code, asset count, duration

- [ ] Create `backend/tests/standalone/test_discovery_runner.py`:
  - Test against `example.com`
  - Assert: returns list of assets
  - Assert: each asset has required fields (hostname, ip_v4)

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_discovery_runner.py -v
```

**📝 Log to DEV_LOG.md**: Results from Python wrapper test

---

### P1.9 — Asset Persistence
- [ ] Create `backend/app/services/asset_manager.py`:
  - Function `save_discovered_assets(scan_id: str, assets: list[dict], db: Session) -> list[Asset]`
  - For each discovered asset:
    - Create `Asset` record in database
    - Create `AssetPort` records for each open port
  - Handle duplicates: if asset with same hostname+ip exists, update `last_seen_at`
  - Logs: assets created, assets updated, ports created

- [ ] Create `backend/tests/standalone/test_asset_manager.py`:
  - Create mock discovery output (3 assets)
  - Save to database
  - Query back and verify all fields
  - Test duplicate handling

**✅ Standalone Test**:
```bash
cd backend && python -m pytest tests/standalone/test_asset_manager.py -v
```

---

**✅ Phase 1 Complete** when:
1. `./bin/discovery-engine --domain scanme.nmap.org --output /tmp/test.json` produces valid JSON
2. Python wrapper reads the JSON and saves assets to PostgreSQL
3. All standalone tests pass
4. `DEV_LOG.md` has entries for P1.2 through P1.9
