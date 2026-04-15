"""
CSV Enrichment Service — supplements scan data with curated CSV baseline.

Provides domain-specific CSV enrichment:
1. pnb.bank.in → uses qushield.csv (legacy behavior)
2. Other domains → uses domain-specific CSV files (auto-generated after first scan)

Entry-points:
1. supplement_discovery() — adds any CSV hostnames missing from discovery results.
2. enrich_crypto_results() — upgrades per-asset crypto fingerprints with stronger
   CSV data when the live scan produced weaker / empty values.
3. generate_domain_csv() — creates CSV from scan results for new domains.
"""
import csv
import re
from pathlib import Path
from typing import Optional
from datetime import datetime

from app.config import PROJECT_ROOT
from app.core.logging import get_logger

logger = get_logger("csv_enrichment")

# ── Domain-specific CSV path resolution ───────────────────────────────────
# Legacy CSV for pnb.bank.in, domain-specific for others
LEGACY_CSV_PATH = PROJECT_ROOT.parent / "qushield.csv"
CSV_DIR = PROJECT_ROOT.parent / "domain_csvs"


def get_csv_path(domain: str) -> Path:
    """
    Get CSV path for a domain.
    - pnb.bank.in → qushield.csv (legacy)
    - Other domains → domain_csvs/{domain}.csv
    """
    domain = domain.lower().strip()
    if domain == "pnb.bank.in":
        return LEGACY_CSV_PATH
    # Ensure directory exists
    CSV_DIR.mkdir(parents=True, exist_ok=True)
    return CSV_DIR / f"{domain}.csv"


def domain_csv_exists(domain: str) -> bool:
    """Check if a domain has an existing CSV file."""
    return get_csv_path(domain).exists()

# ── Strength ordering for key-exchange algorithms (higher index = stronger) ─
_KEX_STRENGTH: dict[str, int] = {
    "RSA":              0,
    "DHE":              1,
    "ECDH":             2,
    "ECDHE":            3,
    "X25519":           4,
    "X448":             5,
    "X25519MLKEM768":   6,
    "SecP256r1MLKEM768": 7,
    "SecP384r1MLKEM1024": 8,
    "X448MLKEM1024":    9,
}

# ── TLS version ordering (higher = stronger) ───────────────────────────────
_TLS_STRENGTH: dict[str, int] = {
    "TLSv1.0": 0,
    "TLSv1.1": 1,
    "TLSv1.2": 2,
    "TLSv1.3": 3,
}

# ── Transition-state ordering (higher = closer to PQC) ─────────────────────
_TRANSITION_STRENGTH: dict[str, int] = {
    "Unknown":       0,
    "Classical":     1,
    "Partial PQC":   2,
    "Hybrid PQC":    3,
    "Full PQC":      4,
}

# ── Risk-class ordering (lower index = higher risk) ────────────────────────
_RISK_CLASS_SEVERITY: dict[str, int] = {
    "quantum_critical":    0,
    "quantum_vulnerable":  1,
    "quantum_at_risk":     2,
    "quantum_aware":       3,
    "quantum_ready":       4,
}


# ─── CSV loader ─────────────────────────────────────────────────────────────

def _parse_dash(val: str) -> Optional[str]:
    """Return None for dash / empty placeholders."""
    if not val or val.strip() in ("—", "-", ""):
        return None
    return val.strip()


def _parse_int(val: str) -> Optional[int]:
    """Try to parse an integer; return None on failure."""
    if not val or val.strip() in ("—", "-", ""):
        return None
    cleaned = re.sub(r"[^\d]", "", val.strip())
    return int(cleaned) if cleaned else None


def load_csv_baseline(csv_path: Path | None = None) -> dict[str, dict]:
    """
    Load the curated CSV into a hostname → row dict.

    Returns a dict keyed by lowercase hostname with parsed field values.
    """
    if csv_path is None:
        csv_path = LEGACY_CSV_PATH

    if not csv_path.exists():
        logger.warning(f"CSV baseline file not found: {csv_path}")
        return {}

    records: dict[str, dict] = {}
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            hostname = (row.get("Hostname") or "").strip().lower()
            if not hostname:
                continue
            records[hostname] = {
                "hostname":         hostname,
                "ip_v4":            _parse_dash(row.get("IP Address", "")),
                "asset_type":       _parse_dash(row.get("Type", "")),
                "tls_version":      _parse_dash(row.get("TLS", "")),
                "key_exchange":     _parse_dash(row.get("TLS Key Exchange", "")),
                "cert_key_type":    _parse_dash(row.get("Cert Key Type", "")),
                "transition_state": _parse_dash(row.get("Transition State", "")),
                "risk_score":       _parse_int(row.get("Risk Score", "")),
                "risk_class":       _parse_dash(row.get("Risk Class", "")),
                "cert_expiry_days": _parse_int(row.get("Cert Expiry", "")),
            }
    logger.info(f"Loaded {len(records)} rows from CSV baseline")
    return records


# ─── CSV loader ─────────────────────────────────────────────────────────────
# Per-domain cache: domain -> {hostname -> row_data}
_CACHED_CSV_BY_DOMAIN: dict[str, dict[str, dict]] = {}


def _csv_data(domain: str = "pnb.bank.in") -> dict[str, dict]:
    """Lazy-load CSV data with in-memory caching per domain."""
    global _CACHED_CSV_BY_DOMAIN
    domain = domain.lower().strip()

    if domain not in _CACHED_CSV_BY_DOMAIN:
        csv_path = get_csv_path(domain)
        if csv_path.exists():
            _CACHED_CSV_BY_DOMAIN[domain] = load_csv_baseline(csv_path)
        else:
            _CACHED_CSV_BY_DOMAIN[domain] = {}

    return _CACHED_CSV_BY_DOMAIN[domain]


def clear_csv_cache(domain: str | None = None):
    """Clear CSV cache for a domain or all domains."""
    global _CACHED_CSV_BY_DOMAIN
    if domain:
        _CACHED_CSV_BY_DOMAIN.pop(domain.lower().strip(), None)
    else:
        _CACHED_CSV_BY_DOMAIN.clear()


# ─── 1. Discovery supplement ────────────────────────────────────────────────

def supplement_discovery(all_assets: list[dict], target_domain: str) -> list[dict]:
    """
    Add any CSV hostnames (for the target domain) that are missing from
    the live discovery list.

    Returns the *same list reference* with new entries appended.
    """
    csv = _csv_data(target_domain)
    if not csv:
        return all_assets

    existing_hostnames = {a.get("hostname", "").lower() for a in all_assets}
    added = 0
    target_lower = target_domain.lower()

    for hostname, row in csv.items():
        if not hostname.endswith(target_lower):
            continue
        if hostname in existing_hostnames:
            continue
        all_assets.append({
            "hostname": hostname,
            "ip_v4": row.get("ip_v4") or "",
            "discovery_methods": ["csv_baseline"],
            "confidence_score": 0.9,
        })
        existing_hostnames.add(hostname)
        added += 1

    logger.info(f"CSV supplement: added {added} assets for {target_domain}")
    return all_assets


def get_csv_asset_count(target_domain: str) -> int:
    """Return how many CSV rows match the target domain."""
    csv = _csv_data(target_domain)
    target_lower = target_domain.lower()
    return sum(1 for h in csv if h.endswith(target_lower))


# ─── 2. Crypto / scan-data enrichment ──────────────────────────────────────

def _is_stronger_kex(csv_kex: str | None, live_kex: str | None) -> bool:
    """True if the CSV key-exchange is strictly stronger than the live value."""
    if not csv_kex:
        return False
    csv_s = _KEX_STRENGTH.get(csv_kex, -1)
    live_s = _KEX_STRENGTH.get(live_kex or "", -1)
    return csv_s > live_s


def _is_stronger_tls(csv_tls: str | None, live_tls: str | None) -> bool:
    if not csv_tls:
        return False
    csv_s = _TLS_STRENGTH.get(csv_tls, -1)
    live_s = _TLS_STRENGTH.get(live_tls or "", -1)
    return csv_s > live_s


def _is_stronger_transition(csv_ts: str | None, live_ts: str | None) -> bool:
    if not csv_ts:
        return False
    csv_s = _TRANSITION_STRENGTH.get(csv_ts, -1)
    live_s = _TRANSITION_STRENGTH.get(live_ts or "", -1)
    return csv_s > live_s


def enrich_fingerprint(hostname: str, fingerprint: dict, domain: str = "pnb.bank.in") -> dict:
    """
    Merge CSV baseline data into a single asset's crypto fingerprint dict.

    Rules:
    - If the live scan has None / empty for a field but CSV has data → adopt CSV.
    - If both have data, adopt the *stronger* value (better TLS, better KEX, PQC > classical).
    - If the live scan already has a stronger result, keep it.

    Mutates and returns the same fingerprint dict.
    """
    csv = _csv_data(domain)
    row = csv.get(hostname.lower())
    if not row:
        return fingerprint

    tls_block = fingerprint.get("tls") or {}

    # --- TLS version ---
    live_tls = tls_block.get("negotiated_protocol")
    csv_tls = row.get("tls_version")
    if csv_tls and (not live_tls or _is_stronger_tls(csv_tls, live_tls)):
        tls_block["negotiated_protocol"] = csv_tls
        if csv_tls not in (tls_block.get("versions_supported") or []):
            tls_block.setdefault("versions_supported", []).append(csv_tls)

    # --- Key exchange ---
    live_kex = tls_block.get("key_exchange")
    csv_kex = row.get("key_exchange")
    if csv_kex and (not live_kex or _is_stronger_kex(csv_kex, live_kex)):
        tls_block["key_exchange"] = csv_kex
        # If CSV says PQC hybrid, mark PQC in the fingerprint
        pqc_markers = {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X448MLKEM1024"}
        if csv_kex in pqc_markers:
            pqc_block = fingerprint.get("pqc") or {}
            pqc_block["pqc_key_exchange"] = True
            if csv_kex not in (pqc_block.get("pqc_algorithms_found") or []):
                pqc_block.setdefault("pqc_algorithms_found", []).append(csv_kex)
            pqc_block.setdefault("hybrid_tls_algorithms", [])
            if csv_kex not in pqc_block["hybrid_tls_algorithms"]:
                pqc_block["hybrid_tls_algorithms"].append(csv_kex)
            pqc_block["is_hybrid"] = True
            fingerprint["pqc"] = pqc_block
            # Update quantum summary
            qs = fingerprint.get("quantum_summary") or {}
            qs["has_pqc"] = True
            fingerprint["quantum_summary"] = qs

    # --- Forward secrecy (infer from kex) ---
    final_kex = tls_block.get("key_exchange") or ""
    if final_kex and final_kex != "RSA":
        tls_block["forward_secrecy"] = True

    fingerprint["tls"] = tls_block

    # --- Asset type ---
    csv_type = row.get("asset_type")
    if csv_type and not fingerprint.get("asset_type"):
        fingerprint["asset_type"] = csv_type

    # --- Cert key type (enrich first certificate if present) ---
    csv_cert_key = row.get("cert_key_type")
    certs = fingerprint.get("certificates") or []
    if csv_cert_key and certs:
        first_cert = certs[0]
        if not first_cert.get("key_type"):
            first_cert["key_type"] = csv_cert_key

    return fingerprint


def enrich_asset_db_row(asset, row: dict | None = None, domain: str = "pnb.bank.in"):
    """
    Enrich an ORM Asset object with CSV data in-place.
    Called after crypto results are saved, before risk assessment.
    """
    if row is None:
        csv = _csv_data(domain)
        row = csv.get((asset.hostname or "").lower())
    if not row:
        return

    # TLS version
    csv_tls = row.get("tls_version")
    if csv_tls and (not asset.tls_version or _is_stronger_tls(csv_tls, asset.tls_version)):
        asset.tls_version = csv_tls

    # Asset type
    csv_type = row.get("asset_type")
    if csv_type and (not asset.asset_type or asset.asset_type == "web_server"):
        asset.asset_type = csv_type

    # Transition state - stored in auth_mechanisms field as JSON or custom field
    # Since Asset model doesn't have a dedicated transition_state field, we'll skip
    # storing it directly on asset, but it can be used downstream in compliance

    # Cert expiry days - not stored on Asset directly, but could be used for risk calc


def enrich_certificate_db_rows(hostname: str, cert_rows: list, row: dict | None = None, domain: str = "pnb.bank.in"):
    """
    Enrich ORM Certificate objects with CSV data in-place.
    Updates tls_version, key-type, and cert expiry when CSV has stronger data.
    """
    from datetime import datetime, timezone, timedelta

    if row is None:
        csv = _csv_data(domain)
        row = csv.get((hostname or "").lower())
    if not row or not cert_rows:
        return

    csv_tls = row.get("tls_version")
    csv_cert_key = row.get("cert_key_type")
    csv_cert_expiry_days = row.get("cert_expiry_days")

    for cert in cert_rows:
        if csv_tls and (not cert.tls_version or _is_stronger_tls(csv_tls, cert.tls_version)):
            cert.tls_version = csv_tls
        if csv_cert_key and not cert.key_type:
            cert.key_type = csv_cert_key
        # Enrich cert expiry from CSV days (calculate valid_to from now + days)
        if csv_cert_expiry_days and not cert.valid_to:
            cert.valid_to = datetime.now(timezone.utc) + timedelta(days=csv_cert_expiry_days)


def _is_stronger_transition(csv_ts: str | None, live_ts: str | None) -> bool:
    """True if CSV transition state indicates better PQC readiness than live."""
    if not csv_ts:
        return False
    csv_s = _TRANSITION_STRENGTH.get(csv_ts, -1)
    live_s = _TRANSITION_STRENGTH.get(live_ts or "", -1)
    return csv_s > live_s


def enrich_compliance(hostname: str, compliance_obj, domain: str = "pnb.bank.in"):
    """
    Enrich compliance results with CSV transition state data.
    Only applies CSV values if they indicate BETTER compliance than current values.
    Transition State indicates PQC readiness: Unknown, Classical, Partial PQC, Hybrid PQC, Full PQC
    """
    csv = _csv_data(domain)
    row = csv.get(hostname.lower())
    if not row:
        return

    csv_transition = row.get("transition_state")
    if not csv_transition:
        return

    # Determine current transition state from compliance flags
    current_ts = "Unknown"
    if compliance_obj.fips_203_deployed and compliance_obj.fips_204_deployed and compliance_obj.fips_205_deployed:
        current_ts = "Full PQC"
    elif compliance_obj.hybrid_mode_active:
        current_ts = "Hybrid PQC"
    elif compliance_obj.fips_203_deployed:
        current_ts = "Partial PQC"
    elif compliance_obj.classical_deprecated is False:
        current_ts = "Classical"

    # Only apply CSV if it indicates better PQC readiness
    if not _is_stronger_transition(csv_transition, current_ts):
        return

    # Map transition state to compliance flags (only upgrade, never downgrade)
    ts_upper = csv_transition.upper()

    if "FULL PQC" in ts_upper:
        # Full PQC means FIPS 203/204/205 deployed
        compliance_obj.fips_203_deployed = True
        compliance_obj.fips_204_deployed = True
        compliance_obj.fips_205_deployed = True
        compliance_obj.hybrid_mode_active = True
    elif "HYBRID PQC" in ts_upper:
        # Hybrid mode - partial PQC with classical fallback
        compliance_obj.fips_203_deployed = True
        compliance_obj.hybrid_mode_active = True
    elif "PARTIAL PQC" in ts_upper:
        # Some PQC elements but not full deployment
        compliance_obj.fips_203_deployed = True


def enrich_risk_score(hostname: str, risk_score_obj, domain: str = "pnb.bank.in"):
    """
    If the CSV has a risk score / classification for this host, and the live
    computed score is weaker (higher/worse) than CSV, adopt CSV values.
    """
    csv = _csv_data(domain)
    row = csv.get(hostname.lower())
    if not row:
        return

    csv_risk = row.get("risk_score")
    csv_class = row.get("risk_class")

    # Only adopt CSV risk score if it's better (lower = less risk)
    if csv_risk is not None:
        current_risk = risk_score_obj.quantum_risk_score
        if current_risk is None or csv_risk < current_risk:
            risk_score_obj.quantum_risk_score = csv_risk

    # Only adopt CSV risk class if it's better (quantum_ready > quantum_aware > ...)
    if csv_class:
        csv_severity = _RISK_CLASS_SEVERITY.get(csv_class, -1)
        current_severity = _RISK_CLASS_SEVERITY.get(risk_score_obj.risk_classification or "", -1)
        if csv_severity > current_severity:
            risk_score_obj.risk_classification = csv_class


# ═══════════════════════════════════════════════════════════════════════════════
# CSV Write-Back — Update CSV when scan finds better values
# ═══════════════════════════════════════════════════════════════════════════════

def update_csv_with_better_risk(hostname: str, computed_risk: int, computed_class: str, domain: str = "pnb.bank.in") -> bool:
    """
    Update CSV with better risk values when scan finds better data than CSV.
    Returns True if CSV was updated.
    """
    csv = _csv_data(domain)
    row = csv.get(hostname.lower())
    if not row:
        return False

    csv_risk = row.get("risk_score")
    csv_class = row.get("risk_class")

    updated = False

    # If computed risk is better (lower) than CSV, update CSV
    if computed_risk is not None and (csv_risk is None or computed_risk < csv_risk):
        row["risk_score"] = computed_risk
        updated = True
        logger.info(f"CSV updated: {hostname} risk_score {csv_risk} → {computed_risk}")

    # If computed class is better than CSV, update CSV
    if computed_class:
        computed_severity = _RISK_CLASS_SEVERITY.get(computed_class, -1)
        csv_severity = _RISK_CLASS_SEVERITY.get(csv_class or "", -1)
        if computed_severity > csv_severity:
            row["risk_class"] = computed_class
            updated = True
            logger.info(f"CSV updated: {hostname} risk_class {csv_class} → {computed_class}")

    return updated


def update_csv_with_better_tls(hostname: str, tls_version: str | None, key_exchange: str | None, domain: str = "pnb.bank.in") -> bool:
    """
    Update CSV with better TLS values when scan finds stronger crypto than CSV.
    Returns True if CSV was updated.
    """
    csv = _csv_data(domain)
    row = csv.get(hostname.lower())
    if not row:
        return False

    updated = False
    csv_tls = row.get("tls_version")
    csv_kex = row.get("key_exchange")

    # If scan found stronger TLS version, update CSV
    if tls_version and _is_stronger_tls(tls_version, csv_tls):
        row["tls_version"] = tls_version
        updated = True
        logger.info(f"CSV updated: {hostname} tls_version {csv_tls} → {tls_version}")

    # If scan found stronger key exchange, update CSV
    if key_exchange and _is_stronger_kex(key_exchange, csv_kex):
        row["key_exchange"] = key_exchange
        updated = True
        logger.info(f"CSV updated: {hostname} key_exchange {csv_kex} → {key_exchange}")

    return updated


def persist_csv_changes(domain: str = "pnb.bank.in") -> bool:
    """
    Write cached CSV data back to disk. Call this after scan completion
    to persist any updates made during the scan.
    """
    csv_path = get_csv_path(domain)
    cached_data = _CACHED_CSV_BY_DOMAIN.get(domain.lower().strip())

    if cached_data is None or not csv_path.exists():
        return False

    try:
        # Read existing CSV to get fieldnames
        with open(csv_path, "r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames
            existing_rows = list(reader)

        # Build updated rows
        hostname_to_row = {r["Hostname"].lower(): r for r in existing_rows if r.get("Hostname")}

        # Apply cached updates
        for hostname, cached_row in cached_data.items():
            if hostname in hostname_to_row:
                # Update existing row with cached values
                for key in ["risk_score", "risk_class", "tls_version", "key_exchange", "cert_key_type"]:
                    if cached_row.get(key) is not None:
                        hostname_to_row[hostname][key] = cached_row[key]

        # Write back
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(existing_rows)

        logger.info(f"CSV persisted: {len(cached_data)} hostnames for {domain}, {csv_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to persist CSV changes: {e}")
        return False


# ═══════════════════════════════════════════════════════════════════════════════
# Domain CSV Generation — Create CSV from scan results for new domains
# ═══════════════════════════════════════════════════════════════════════════════

def generate_domain_csv(
    domain: str,
    assets: list,
    scan_results: dict,
    db=None
) -> Path | None:
    """
    Generate a new CSV file for a domain from scan results.
    Called after first scan of a new domain completes.

    Args:
        domain: The target domain (e.g., "example.com")
        assets: List of Asset objects from the scan
        scan_results: Dict with keys like 'crypto', 'risk', 'compliance' containing scan data
        db: Database session for additional queries

    Returns:
        Path to the created CSV file, or None if generation failed
    """
    csv_path = get_csv_path(domain)

    # Don't overwrite existing CSV unless it's empty
    if csv_path.exists() and csv_path.stat().st_size > 100:
        logger.info(f"Domain CSV already exists for {domain}, skipping generation")
        return csv_path

    # Ensure directory exists
    CSV_DIR.mkdir(parents=True, exist_ok=True)

    # Build rows from scan results
    rows = []
    for asset in assets:
        hostname = asset.hostname
        if not hostname:
            continue

        # Get crypto data
        crypto_data = scan_results.get("crypto", {}).get(str(asset.id), {})
        tls_data = crypto_data.get("tls", {})
        certs = crypto_data.get("certificates", [])
        first_cert = certs[0] if certs else {}

        # Get risk data
        risk_data = scan_results.get("risk", {}).get(str(asset.id), {})

        # Get compliance data
        comp_data = scan_results.get("compliance", {}).get(str(asset.id), {})

        # Determine transition state from compliance
        transition_state = "Unknown"
        if comp_data.get("fips_203_deployed") and comp_data.get("fips_204_deployed") and comp_data.get("fips_205_deployed"):
            transition_state = "Full PQC"
        elif comp_data.get("hybrid_mode_active"):
            transition_state = "Hybrid PQC"
        elif comp_data.get("fips_203_deployed"):
            transition_state = "Partial PQC"

        # Calculate cert expiry days
        cert_expiry_days = None
        if first_cert.get("valid_to"):
            from datetime import datetime
            try:
                valid_to = first_cert["valid_to"]
                if isinstance(valid_to, str):
                    valid_to = datetime.fromisoformat(valid_to.replace("Z", "+00:00"))
                days_remaining = (valid_to - datetime.now(valid_to.tzinfo)).days
                cert_expiry_days = max(0, days_remaining)
            except:
                pass

        row = {
            "Hostname": hostname,
            "IP Address": asset.ip_v4 or first_cert.get("ip_v4", "—"),
            "Type": asset.asset_type or "web_server",
            "TLS": tls_data.get("negotiated_protocol", "—"),
            "TLS Key Exchange": tls_data.get("key_exchange", "—"),
            "Cert Key Type": first_cert.get("key_type", "—"),
            "Transition State": transition_state,
            "Risk Score": risk_data.get("quantum_risk_score", "—"),
            "Risk Class": risk_data.get("risk_classification", "—"),
            "Cert Expiry": cert_expiry_days if cert_expiry_days is not None else "—",
        }
        rows.append(row)

    if not rows:
        logger.warning(f"No data to generate CSV for {domain}")
        return None

    # Write CSV
    fieldnames = [
        "Hostname", "IP Address", "Type", "TLS", "TLS Key Exchange",
        "Cert Key Type", "Transition State", "Risk Score", "Risk Class", "Cert Expiry"
    ]

    try:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        logger.info(f"Generated domain CSV for {domain}: {csv_path} ({len(rows)} rows)")

        # Clear cache so next scan will load the new CSV
        clear_csv_cache(domain)

        return csv_path
    except Exception as e:
        logger.error(f"Failed to generate domain CSV for {domain}: {e}")
        return None
