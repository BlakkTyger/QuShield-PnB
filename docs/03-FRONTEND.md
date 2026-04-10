I'll think through this systematically — user journeys, information hierarchy, cognitive load, and scan workflow — before planning each page.Here is the full Frontend & UX plan, starting with the overall navigation architecture, then a deep-dive into every page.

---

## Navigation Architecture — First Principles

Before placing any elements, three user personas govern every design decision:

**Security Analyst** — runs scans, drills into findings, wants raw data and filters.
**CISO / Security Lead** — needs the summary, the risk score, the regulatory gap. Never wants to run a scan manually.
**Developer / Migration Engineer** — needs the technical playbooks, CBOM exports, and library-level specifics.

The navigation must serve all three without making any of them wade through the others' workflows.Now, the detailed page-by-page specification:

---

## Page 1 — Quick Scan

**Purpose:** The front door to the product. Zero friction entry for any user who wants an immediate answer about one domain. Must return meaningful results in under 60 seconds.

**Layout:** Full-width, single-column, centered. No sidebar clutter — the scan is the whole experience.

**UI Components:**

The page opens with a large, prominent search bar: `Enter a domain, URL, or IP address` with a green "Scan Now" button. Beneath it, a row of example tags (bank.sbi.co.in, hdfcbank.com) that auto-populate on click.

Once scanning begins, the search bar locks and a real-time progress stepper appears below it showing five phases sequentially: DNS Resolution → Certificate Retrieval → TLS Handshake → Cipher Negotiation → Risk Scoring. Each phase lights up as it completes, with a small animated pulse. A live log console streams raw output in monospace on the right side at 12px, collapsible.

When complete, the page splits into two regions:

**Left column — Instant Scorecard:**
- A large circular gauge (0–1000) showing the Quantum Cyber Rating in the center. Color transitions: red below 300, amber 300–700, green above 700. The label below says `Quantum Critical / Vulnerable / Ready`.
- Below the gauge: four metric cards in a 2×2 grid — TLS Version, Key Exchange Algorithm, Certificate Expiry, NIST Quantum Security Level (0–6).

**Right column — Key Findings Cards:**
- A vertical stack of finding cards, each with a severity pill (Critical / High / Medium / Low), a one-line finding title, and a two-line explanation. Example: `[Critical] RSA-2048 key exchange detected — vulnerable to Shor's algorithm. Estimated HNDL exposure: active.`
- A "Run Full Infrastructure Audit →" CTA button at the bottom that pre-populates Discovery page with this domain.

---

## Page 2 — Dashboard

**Purpose:** The CISO's home screen. Never requires interaction — it renders a living summary of the entire organisation's quantum posture. Think of it as the C-suite briefing printed fresh every morning.

**Layout:** Fixed header with org name + last scan timestamp + a "Refresh Scan" button. Content in a responsive card grid below.

**Top strip — Four headline metrics (full width, 4 cards side by side):**

| Metric | What it shows |
|---|---|
| Quantum Cyber Rating | 0–1000 gauge. The single most important number. |
| Assets at HNDL Risk | Count of assets with active harvest-now-decrypt-later exposure |
| Days to Next Cert Expiry | Countdown to the nearest critical certificate expiration |
| Regulatory Compliance | % gap vs. RBI/SEBI/PCI requirements |

**Main content — two-column layout:**

**Left column (60% width):**

*Asset Risk Distribution chart* — a horizontal stacked bar across the full width showing asset counts by classification: Quantum Critical (red) / Quantum Vulnerable (orange) / Quantum at Risk (amber) / Quantum Aware (blue) / Quantum Ready (green). Clicking any segment deep-links to the Discovery page pre-filtered to that risk class.

*Algorithm Exposure Breakdown* — a donut chart with six segments for the key exchange algorithms detected across all assets: RSA-2048, RSA-4096, ECDHE P-256, ECDHE P-384, ML-KEM (hybrid), ML-KEM (pure). The outer ring color-codes quantum-vulnerable (warm) vs quantum-safe (cool). A center label shows `X% of handshakes quantum-vulnerable`.

*Certificate Health Timeline* — a bar chart showing count of certificates expiring in 0–30 / 30–60 / 60–90 / 90–180 / 180+ days. Bars color-coded by whether the expiring cert's key algorithm is quantum-safe or not.

**Right column (40% width):**

*Regulatory Deadline Countdown* — a vertical list of 5–6 named regulatory deadlines with days-remaining countdowns. Each row: flag + regulation name + deadline date + a mini progress bar showing the bank's current compliance % for that regulation. E.g.: `RBI Crypto Governance — 31 Dec 2026 — 43 days remaining — 28% complete`.

*Critical Alerts Feed* — a scrollable live feed of the 10 most critical findings. Each entry: severity icon + asset name + one-line finding + timestamp. Clicking any alert opens the full asset detail in the CBOM Explorer.

*PQC Adoption Progress* — a single large progress bar: `X of Y assets PQC Ready`. Below it, three smaller bars: Hybrid Deployed / Classical Only / Quantum Critical.

**Bottom strip — Three summary tables (tabs):**

Tabs: `Top 10 Highest Risk Assets` / `Certificates Expiring Soon` / `Recently Discovered Assets`. Each tab is a compact 10-row table with the most critical columns only — designed for quick scanning, not exhaustive data. A "View All →" link exits to the relevant detailed page.

---

## Page 3 — Discovery & Inventory

**Purpose:** The analyst's primary work environment. This is where full infrastructure scans are initiated, monitored, and explored. The page has two distinct modes: **Scan Mode** (before/during a scan) and **Inventory Mode** (after a scan completes).

**Layout:** Full-width with a persistent top panel for scan controls and a main content area below that transitions between modes.

**Scan Control Panel (always visible at top):**

A horizontal bar containing: a multi-domain input field with tag-style chips for each target domain, a "Scan Scope" dropdown (Public Web Apps / APIs / All Asset Types), a "Scan Depth" selector (Quick / Standard / Deep), a schedule toggle (Run Now / Schedule), and a large "Start Discovery" button. A small help tooltip explains what each phase does.

**Phase Progress (visible during scan):**

A five-phase stepper replaces the lower content area during an active scan:

Phase 1 — DNS & Asset Enumeration (subdomain brute-force, CT log mining, BGP/ASN sweep)
Phase 2 — Certificate Intelligence (certificate retrieval, chain analysis, CA identification)
Phase 3 — Service & Port Scanning (open ports, web server fingerprinting, API endpoint detection)
Phase 4 — Cryptographic Fingerprinting (TLS handshake simulation, cipher suite enumeration, key exchange recording)
Phase 5 — Third-Party Dependency Mapping (NPCI/payment gateway endpoints, CBS vendor API detection, CDN termination point identification)

Each phase shows a live counter: `Phase 2: Processed 847 / 2,341 certificates`. A pause/cancel button is always visible. Estimated completion time updates every 30 seconds.

**Inventory Mode (after scan):**

The page splits into a filter sidebar (left, 240px) and the main asset table (right, full remaining width).

*Filter Sidebar:*
- Asset Type (checkboxes): Web App, API Endpoint, Gateway, Load Balancer, DNS Server, VPN Endpoint, Third-Party
- Risk Level (checkboxes): Quantum Critical, Vulnerable, At Risk, Aware, Ready
- TLS Version: 1.0, 1.1, 1.2, 1.3
- Key Exchange: RSA, ECDHE, ML-KEM, Unknown
- Certificate Status: Valid, Expiring Soon (<30 days), Expired, Self-Signed
- Discovery Method: DNS Enum, CT Logs, ASN Sweep, Manual
- IPv6 Support: Yes / No

*Main Asset Inventory Table:*
Full-width table with sticky header and virtual scrolling for large asset counts. Columns (in order): Checkbox, Asset Name (clickable, opens slide-out detail panel), URL, Type (pill badge), Risk Level (colored pill), TLS Version, Key Exchange, Certificate Expiry, NIST Quantum Level (0–6 badge), Last Scan. 

Row hover reveals a quick-action menu: `View CBOM / View in Topology / Open Migration Plan / Flag for Review`.

Clicking an asset name opens a right-side slide-out panel (400px wide) without leaving the page. The panel shows: full asset metadata, all detected cipher suites ranked by strength, certificate chain visualization, linked third-party dependencies, and a direct link to the full CBOM view for that asset.

**Sub-tabs within Inventory Mode:**

Four tabs below the scan control panel: `All Assets` / `Third-Party Integrations` / `Shadow Assets` / `Nameserver Records`.

The Shadow Assets tab is particularly important — it highlights assets detected during scanning that are not present in the bank's official CMDB. These get a yellow `Unregistered` badge and are automatically flagged for review.

---

## Page 4 — CBOM Explorer

**Purpose:** The deepest data view in the product. This is where analysts and developers inspect the full cryptographic fingerprint of every asset, down to the library level. It also serves as the audit evidence store.

**Layout:** Three-panel layout — asset list (left, 280px), CBOM detail (center, remaining width), export panel (right, collapsible 280px).

**Left Panel — Asset Selector:**
A searchable, sortable list of all scanned assets. Each row: asset name, risk level pill, and a small color dot indicating NIST Quantum Security Level. Sort options: by risk level, by name, by scan date. A "Group by" dropdown: by Type / by Domain / by CA / by Key Exchange.

**Center Panel — CBOM Detail View (tabs):**

Tab 1 — Algorithm Inventory:
A structured table showing every cryptographic algorithm detected on the selected asset. Columns: Algorithm Name, Category (KEM / Signature / Symmetric / Hash), Key Length, NIST Quantum Security Level, Quantum Vulnerable flag (Yes/No), Usage Context (TLS Handshake / JWT Signing / Code Signing / Data Encryption), Recommended PQC Replacement. Rows for quantum-vulnerable algorithms are highlighted in soft red.

Tab 2 — Certificate Chain:
A visual tree (rendered as an SVG inside the tab) showing the full certificate chain: Leaf cert → Intermediate CA(s) → Root CA. Each node in the tree shows: Common Name, Issuer, Key Type, Key Length, Valid From/To, NIST Quantum Level, and a PQC-readiness badge. Arrows between nodes are colored green (quantum-safe) or red (quantum-vulnerable). Clicking any node expands it to show the full SHA fingerprint, SAN list, and raw certificate metadata.

Tab 3 — Protocol & Library Map:
A breakdown of all cryptographic libraries and protocol versions detected. For each library (OpenSSL 1.1.1w, BouncyCastle 1.78, etc.): current version, latest available version, PQC support status, CVEs against the current version, and an upgrade recommendation. TLS protocol version breakdown shows a mini bar chart: what % of endpoints support TLS 1.3, TLS 1.2 only, or legacy versions.

Tab 4 — Key & Secret Metadata:
A table of all key material identified (not the raw keys — metadata only): Key ID/reference, Key Type, Key Length, Storage Location (HSM / K8s Secret / Env Variable / Hardcoded flag), Rotation Policy, Last Rotated, Quantum Vulnerability Status. HSM entries show: vendor, model, firmware version, PQC support status.

Tab 5 — Raw CBOM (JSON):
The machine-readable CycloneDX 1.6 CBOM for the selected asset, displayed in a syntax-highlighted JSON viewer with collapse/expand controls. The `nistQuantumSecurityLevel` field is visually highlighted in amber for values 0–2 (insufficient) and green for 3+.

**Right Panel — Export & Compliance:**
Collapsible panel with export options: CycloneDX 1.6 JSON, PDF Report, CSV. Below: a compliance summary for the selected asset — which regulatory requirements it satisfies and which it fails.

**Top bar — Portfolio-Level Charts (always visible, not per-asset):**
A horizontal strip of four mini-charts showing org-wide CBOM statistics: Key Length Distribution (bar), Cipher Suite Usage (donut), TLS Version Mix (pie), Top 5 Certificate Authorities by asset count (horizontal bar). These do not change when an asset is selected — they always show the portfolio view.

---

## Page 5 — PQC Compliance

**Purpose:** Regulatory alignment tracking. Maps the organisation's cryptographic posture against every named standard and deadline. The CISO's evidence board for board meetings and regulatory inspections.

**Layout:** Full-width. Top section = headline compliance score + deadline countdown banner. Below = tabbed compliance detail.

**Headline Section:**

A large compliance score card in the center: `PQC Compliance Score: 43/100` with a horizontal progress bar. Below it, a two-sentence summary: `41 of 97 assets meet NIST FIPS 203/204/205 requirements. 0 assets have completed full PQC migration.`

Flanking the score: a row of named regulatory deadline countdown cards. Each card: regulation name, jurisdiction flag, deadline date, bank's current compliance %, and a red/amber/green status dot. E.g.: `NIST FIPS Deprecation — US — Dec 2030 — 12%`, `RBI Crypto Governance — IN — Dec 2026 — 28%`, `PCI DSS 4.0 TLS — Global — Mar 2025 — 94%`.

**Compliance Detail Tabs:**

Tab 1 — FIPS Compliance Matrix:
A grid where rows = assets (showing top 20, with a "View All" toggle) and columns = FIPS standards (FIPS 203 ML-KEM deployed / FIPS 204 ML-DSA deployed / FIPS 205 SLH-DSA available / TLS 1.3 enforced / Forward Secrecy enabled / Hybrid Mode active / Classical deprecated). Each cell is a green checkmark or red X. The header row shows column-level pass rates: `FIPS 203: 8% of assets`.

Tab 2 — Crypto-Agility Assessment:
A per-asset table showing the Crypto-Agility Score (0–100) with the five component scores: Dynamic Cipher Negotiation, Automated Certificate Renewal, Automated Key Rotation, Cryptographic Abstraction Layer, Documented Owner + SLA. Assets below 40 show a `Migration-Blocked` warning badge. A summary card at the top shows the distribution: `12 Migration-Blocked / 34 Low Agility / 28 Moderate / 23 High`.

Tab 3 — India Regulatory Tracker:
A dedicated view for Indian banking regulations with a vertical accordion for each regulation: RBI IT Framework, RBI Cyber Security Framework, SEBI CSCRF, NPCI UPI Security Guidelines, DPDP Act 2023. Each accordion expands to show: the specific cryptographic requirement, the bank's current status for that requirement, the gap, and a direct link to the relevant asset list. A "Generate Compliance Report" button at the bottom produces a pre-formatted PDF for RBI submission.

Tab 4 — Hybrid Deployment Tracker:
A timeline visualization showing the progression of hybrid TLS deployments (classical + ML-KEM simultaneously) across the asset portfolio over the past 90 days. A Sankey diagram shows the flow from `Classical Only → Hybrid → Full PQC`. Target milestones for each phase are marked on the timeline.

---

## Page 6 — Risk Intelligence

**Purpose:** The quantitative risk engine. Where Mosca's Theorem is applied, HNDL exposure windows are visualized, and the mathematical foundation of every risk score is exposed for analyst review.

**Layout:** Full-width. Left sidebar (260px) for asset selector + filter. Main content area shows the risk model for the selected asset or the portfolio view.

**Portfolio Heatmap (default view — no asset selected):**

A large 2D heatmap fills the main content area. X-axis: Data Shelf Life (0→20 years). Y-axis: Estimated Migration Time (0→5 years). Each asset is plotted as a dot on this grid. Color: Quantum Critical (red) / Vulnerable (orange) / At Risk (amber) / Safe (green). The Mosca threshold line (X+Y = CRQC arrival estimate) is drawn across the grid as a dashed diagonal — any asset above-right of this line is HNDL-exposed. Hovering a dot shows the asset name, its coordinates, and its risk score. Clicking drills into the per-asset risk view.

**Per-Asset Risk View (when an asset is selected):**

Split into four panels:

Panel 1 — Mosca's Theorem Calculator:
Three interactive sliders with live computation. Slider 1: Migration Time estimate (draggable, auto-populated from the crypto-agility score). Slider 2: Data Shelf Life (populated from asset type defaults, editable). Slider 3: CRQC Arrival Estimate (three presets: Pessimistic 2029 / Median 2032 / Optimistic 2035, plus a custom date input). Below the sliders: a large `X + Y = Z.  [Z] vs [CRQC]` equation rendered in real time, with a verdict: `EXPOSED — migration must complete before [date]` or `SAFE — current pace is sufficient`.

Panel 2 — HNDL Exposure Window:
A horizontal timeline from today → 2040. Three colored regions: `Data already harvested (red, from earliest known scan date to today)`, `Active harvest window (orange, today → estimated CRQC arrival)`, `Post-CRQC decryption risk (dark red, after CRQC arrival)`. The asset's estimated migration completion date is marked as a vertical line — if it falls after the CRQC arrival line, it's in the danger zone and the timeline turns red.

Panel 3 — TNFL (Trust Now Forge Later) Assessment:
A checklist showing whether this asset uses digital signatures in contexts where forgery would be catastrophic: SWIFT message signing, UPI transaction authorization, software/firmware update signing, certificate issuance, payment terminal authentication. For each applicable use case, the panel shows whether the current signing algorithm (ECDSA / RSA-PSS / HMAC) is quantum-vulnerable and what the consequence of signature forgery would be.

Panel 4 — Risk Score Breakdown:
The asset's 0–1000 quantum risk score decomposed into its five components with individual sub-scores and brief rationale. Allows analysts to understand exactly why an asset scored the way it did and which factor to improve first.

---

## Page 7 — Topology Map

**Purpose:** Spatial, relational intelligence. Shows how assets connect to each other, how certificates propagate across the infrastructure, and where a single compromised key or certificate would cause cascading failure.

**Layout:** Nearly full-screen canvas. A thin control bar at the top; a collapsible detail panel on the right (360px) that opens when a node is clicked.

**Canvas:**

A force-directed graph rendered using D3.js. Node types: Domain (circle), IP Address (square), Certificate (diamond), Service (hexagon), HSM/Key Store (pentagon), Organization/CA (large circle). Edge types: solid line (domain→IP), dashed line (domain→certificate), dotted line (IP→service), bold line (certificate→trust dependency).

Node color encodes PQC readiness: red = Quantum Critical, amber = Vulnerable, green = Ready, gray = Unknown.

Node size encodes blast radius: nodes whose certificate or key is shared across many assets are rendered larger — visually showing the amplified risk of that node.

**Control Bar:**
- Filter by: Node Type, Risk Level, TLS Version, Key Exchange Algorithm
- Layer toggle: Show/hide Certificate Edges, Trust Chain Edges, Service Edges
- Layout selector: Force-Directed / Hierarchical (DNS tree) / Radial (cert trust)
- Search: Type an asset name to highlight it and its first-degree connections, dimming everything else
- Zoom controls: +/−/reset, scroll-to-zoom enabled

**Right Detail Panel (opens on node click):**

Shows the full metadata for the clicked node: Name, Type, Risk Level, IP(s), Linked certificates, Linked services, NIST Quantum Level, Last Seen, HNDL exposure status. Below: a mini list of all first-degree connections with their risk levels. A "View Full CBOM →" button and a "View in Migration Planner →" button.

**Blast Radius Mode:**
A special mode activated from the top bar: click any certificate node to see which assets would be compromised if that certificate's private key were broken by a quantum computer. Affected nodes pulse red. A summary card appears: `Breaking this RSA-2048 certificate would expose 47 assets and compromise 3 critical payment gateway endpoints.`

**Trust Chain View (sub-view):**
Accessible from the Layout dropdown. Renders the certificate trust hierarchy as a top-down tree: Root CAs at the top, intermediate CAs in the middle, leaf certificates at the bottom. Color-codes each CA's PQC roadmap status.

---

## Page 8 — Migration Planner

**Purpose:** Converts risk intelligence into an actionable, developer-ready migration plan. The bridge between the security team and the engineering team.

**Layout:** Vertical scrolling page with a fixed "Mission Control" strip at the top showing overall migration progress.

**Mission Control Strip:**
A horizontal bar pinned to the top: `Migration Progress: Phase 1 (Hybrid) — 12% complete`. Four milestone indicators: Phase 0 (TLS hygiene) / Phase 1 (Hybrid KEM) / Phase 2 (Full PQC) / Phase 3 (Certified). Each milestone has a completion percentage and a target date. The strip also shows: `[N] Migration-Blocked assets` and `[N] Critical assets not yet started`.

**Roadmap View (top section):**

A Gantt-style horizontal timeline spanning today → 36 months. Each asset is a horizontal bar colored by its risk level. Bars begin at estimated start and end at estimated completion based on crypto-agility score and complexity. A vertical red line marks today. A vertical dashed line marks the pessimistic CRQC arrival estimate. Any bar that ends after the CRQC line is highlighted in red.

Filter controls above the Gantt: by asset type, by team/owner, by phase, by risk level. This allows the migration lead to view "all payment gateway migrations" or "all third-party vendor dependencies" as a sub-timeline.

**Playbook Library (main section):**

A card grid of technical migration playbooks. Each playbook is a card showing: stack icon, title, difficulty (Easy/Medium/Hard), estimated effort (hours), and relevant asset types. Cards are sorted by urgency (how many critical assets they apply to).

Clicking a playbook opens a full-page slide-out with: step-by-step technical instructions, specific library versions and config file changes, code samples, test procedures, rollback steps, and performance impact notes. Example playbooks:

- `nginx + OpenSSL 3.5.0: Enable ML-KEM hybrid TLS` — Medium, 4 hours, applies to 23 assets
- `Java (BouncyCastle): Migrate JWT signing to ML-DSA` — Hard, 12 hours, applies to 8 assets
- `Thales Luna HSM v7.9 Firmware Upgrade` — Hard, 8 hours + vendor scheduling, applies to all assets using Luna HSMs

**Vendor Readiness Tracker (bottom section):**

A table of every third-party product or vendor identified in the CBOM, showing: product name, vendor, current version in use, PQC roadmap published status, target PQC-ready version, estimated availability date, and risk if delayed. Rows where the vendor has no published PQC roadmap are highlighted in red. An "Add Vendor" button allows manual entries for unlisted products.

---

## Page 9 — Reports & Compliance

**Purpose:** Packaging the platform's output for regulators, auditors, board members, and internal stakeholders. Must produce both machine-readable artifacts (for RBI audits) and human-readable executive summaries (for board briefings).

**Layout:** A two-column layout. Left column (360px): report configuration. Right column: preview and history.

**Report Builder (left column):**

A step-by-step form with clear section headers:

Step 1 — Report Type: Radio buttons: Quantum Risk Executive Summary / CBOM Audit Package (CycloneDX 1.6) / RBI Crypto Governance Submission / PQC Migration Progress Report / Full Infrastructure Scan Report / Custom.

Step 2 — Scope: Asset selector (all / by type / by risk level / select individual assets). Date range for scan data included.

Step 3 — Sections to include: Checkbox list (Discovery Summary / Asset Inventory / CBOM Detail / PQC Compliance Matrix / Risk Intelligence / Migration Progress / Regulatory Gap Analysis / AI-Generated Executive Commentary).

Step 4 — Delivery: Format (PDF / JSON / CSV / XLSX). Password protection toggle. Email delivery addresses. Secure download link expiry duration.

Step 5 — Schedule (if scheduling): Frequency (One-time / Weekly / Monthly / Quarterly). Day and time. Timezone.

A "Generate Report" button at the bottom. For AI-generated reports, a toggle: `Include AI Executive Commentary (uses local LLM inference)` — when enabled, the AI analyst section runs locally and inserts a narrative interpretation of the findings.

**Preview & History (right column):**

A live preview pane showing the first page of the report being built, auto-updating as the user selects sections. Below it: a table of previously generated reports with: name, type, generated date, generated by, file size, and download/share links. Reports older than 90 days are greyed out and marked with a retention warning.

---

## Page 10 — AI Assistant

**Purpose:** Natural language interface to the entire platform's data. Answers questions that require correlating across multiple data sources — queries that would otherwise require a skilled analyst spending hours in tables and charts.

**Layout:** Chat-first. A centered conversation thread (700px max-width) with a persistent input bar at the bottom. A collapsible right panel (280px) for data context cards.

**Chat Interface:**

The thread opens with four suggested starter queries rendered as clickable cards:
- `"Which of our assets are currently exposed to HNDL attacks?"`
- `"Generate a board-level summary of our quantum risk position"`
- `"Which third-party vendors have no PQC roadmap?"`
- `"What is our estimated migration timeline at current pace?"`

Clicking any card sends the query. The AI response appears as a message bubble with: the answer in prose, followed by a data card (table or chart) embedded inline in the message thread when the answer involves quantitative output. Every data claim in the response is linked to the underlying scan data — hovering a number shows a tooltip: `Source: Discovery Scan — Jan 2026`.

The AI has full context of all scan data, CBOM entries, risk scores, and regulatory requirements. It operates on local LLM inference (as specified), keeping all banking data on-premise.

**Right Context Panel:**

When a user asks a question, the context panel shows which datasets the AI is querying in real time — a transparency layer so analysts can validate the AI's sources. It lists: `Querying: Asset Inventory (97 records), CBOM Database (2,341 entries), Risk Scores (97 assets)`.

**AI Report Generation Sub-section:**

A dedicated panel below the chat — accessed via a `Generate AI Report` button — where the user provides a free-text brief: `Audience: RBI Inspector. Tone: Technical. Focus: Certificate hygiene gaps and FIPS 203 adoption status.` The AI produces a full structured report draft in the chat thread, which can then be sent to the Reports page for formatting and delivery.

---

## Cross-Cutting Design Decisions

**Global search bar** (top-right, always visible): searches across assets, CVEs, algorithm names, certificate fingerprints, and vendor names. Results are grouped by type and link directly to the relevant page + filtered view.

**Contextual deep-links everywhere:** Every risk score, every asset name, every certificate fingerprint is a clickable link that navigates to the appropriate detail page with the correct context pre-loaded. The user should never need to navigate manually to correlate two pieces of data.

**Live telemetry indicator:** A small green pulse dot in the top navigation bar shows when a scan is actively running in the background. Clicking it opens a mini scan monitor overlay without leaving the current page.

**Persistent notification center:** A bell icon in the top bar accumulates critical alerts — new shadow assets detected, certificates expiring in 30 days, new CVEs against detected library versions. Clicking opens a drawer with the full alert list, each linking to the relevant asset.

**Keyboard shortcuts** throughout: `Cmd+K` opens global search, `Cmd+Shift+S` starts a new scan, `Cmd+E` exports the current view, `Esc` closes any slide-out or overlay.

---

## Addendum: Phase 7B New Pages (2026-04-10)

### Page — Authentication (Login / Register)

**Purpose**: Gate access to scan history, cached results, and user-specific data.

**Login Page**: Centered card with email + password fields, "Log In" button, "Forgot password?" link, and "Sign Up" link. JWT tokens stored in httpOnly cookies.

**Register Page & Verification Popup**: Email + password + confirm password. On submit, shows a modal popup asking for the Email Verification OTP/link that was console-logged. User must input the OTP here. User cannot access scan history until email is verified.

**Auth State**: If not logged in, Quick Scan is available without auth (public). Shallow/Deep scans require login. All scan history requires login.

### Page — Scan History

**Purpose**: Show all scans run by the current user, grouped by domain.

**Layout**: Table with columns: Domain, Scan Type (Quick/Shallow/Deep), Status, Date, Assets Found, Risk Rating. Filterable by scan type, domain, date range. Clicking a row navigates to the scan results dashboard.

**Smart Cache Indicator**: If a cached result exists for a domain, show a "Cached" badge with time remaining. "Re-scan" button to force a fresh scan.

### Page — Interactive GeoIP Map

**Purpose**: Visualize all discovered IPs for a scan on an interactive map of India (or world).

**Map Implementation**: Leaflet.js with OpenStreetMap tiles. Each IP plotted as a circle marker, color-coded by quantum risk status:
- Red: Quantum Critical / Quantum Vulnerable
- Amber: Quantum At Risk
- Green: Quantum Ready / Quantum Aware

**Marker Hover Tooltip**: Hostname, IP address, Asset Type, TLS Version, Risk Score, NIST Quantum Level, Organization/ISP.

**Marker Click**: Opens slide-out panel with full asset detail (certificates, CBOM, compliance checks).

**Cluster View**: For domains with many assets in the same city/datacenter, markers auto-cluster with a count badge. Clicking a cluster zooms in.

**Sidebar**: Summary stats — total IPs, geographic distribution (top 5 cities), % in India vs overseas, ISP breakdown.

### Page — Quick Scan (Updated)

**Updates to existing Quick Scan page**:
- Scan type selector: Quick (3–8s) | Shallow (30–90s) | Deep (5–10 min) — defaulting to Quick
- If cached results exist for a higher tier, show "Instant results available from [Shallow/Deep] scan run on [date]" with a "View" button
- Quick Scan results now include: Quantum Cyber Rating gauge, TLS version, cert expiry, NIST level, key findings, one-click "Upgrade to Deep Scan" CTA

### Page — Vendor Readiness Dashboard

**Purpose**: Show PQC readiness of technology vendors relevant to the scanned bank's infrastructure.

**Layout**: Card grid, one per vendor. Each card shows vendor name, product, PQC status badge (Ready/In Progress/Unknown), supported algorithms, and risk-if-delayed severity. Critical blockers highlighted in red at the top.

---

## Phase 8 UX Updates (Monte Carlo & Risk Engine)

### Page — Post-Quantum Risk Dashboard (Updated)

**Monte Carlo CRQC Arrival Chart**:
- Replaces static "pessimistic/median/optimistic" text with an interactive probability density curve chart (rendered via Recharts or Chart.js).
- **Y-axis**: Probability % | **X-axis**: Year (2027–2045).
- **Curve Shape**: Log-normal distribution showing a heavy right tail (reflecting asymmetric quantum uncertainty).
- **Interactive Elements**:
  - Hovering over a year shows the exact probability of CRQC arrival.
  - A slider below the chart allows analysts to adjust `mode_year` and `sigma` spread assumptions, instantly animating the curve update and recalculating portfolio risk metrics below.
  - Vertical annotation lines for: P5 (Aggressive), P50 (Median), P95 (Conservative).

**Certificate Expiry vs CRQC Race Overview**:
- A dedicated card next to the CRQC arrival chart.
- **Visual**: A horizontal stacked bar chart showing the breakdown of certificates by race status:
  - Green (Safe): PQC verified.
  - Amber (Natural Rotation): Expires before CRQC arrival, safe to swap next cycle.
  - Red (At Risk): Valid during CRQC arrival — **requires out-of-band proactive replacement**.
- **Interaction**: Clicking the "At Risk" segment filters the asset list below to immediately show those vulnerable certificates.

### Page — Asset Risk Detail (Updated)

**Per-Asset Quantum Exposure**:
- New component showing the individual asset's Mosca's Inequality (X + Y > Z) as a gauge.
- **Visual Component**: "Probability of Quantum Exposure" dial (0-100%).
### Page — Deep Scan Live Progress Tracker

**Purpose**: Provide an engaging, real-time loading screen during long-running Deep Scans. Keeps the user focused and reduces perceived wait time.

**Technical Spec (SSE)**:
- Connects to `GET /api/v1/scans/{scan_id}/stream`.
- Listens for `text/event-stream` messages parsing `data` JSON payloads.
- Handles reconnection automatically. Stops listening when `event_type` is `scan_complete` or `scan_failed`.

**Layout**:
- **Top Header**: "Deep Scan in Progress" with a large, glowing circle pulse animation.
- **Left Panel (Phase Map)**: A vertical stepper showing 6 phases.
  1. Asset Discovery  
  2. Cryptographic Inspection  
  3. Bill of Materials (CBOM) Generation  
  4. Quantum Risk Assessment  
  5. Regulatory Compliance  
  6. Topology Mapping  
  The current phase is highlighted in blue and slowly pulses. Completed phases show a green checkmark.
- **Center Panel (Live Feed)**: A terminal-like "hacker style" auto-scrolling log.
  - Receives `asset_discovered` and `crypto_result` events.
  - Example: `[10:45:01] Discovered: api.bank.in (192.168.1.5)`
  - Example: `[10:45:05] Scanned api.bank.in: TLSv1.3 | AES-256-GCM | Quant-Safe: FALSE`
- **Right Panel (Metrics)**: Live updating counters driven by the SSE stream:
  - Assets Discovered (integer)
  - Crypto Handshakes (progress bar, driven by `crypto_result` pct field)
  - Estimated Time Remaining (derived from average per-asset processing time).
- **Completion State**: When `scan_complete` arrives, the stream disconnects, a confetti animation plays, and a CTA "View Full Results" appears.