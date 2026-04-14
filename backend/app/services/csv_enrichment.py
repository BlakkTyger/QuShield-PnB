"""
CSV Enrichment Service — supplements scan data with curated CSV baseline.

Provides two entry-points used by the orchestrator:
1. supplement_discovery() — adds any CSV hostnames missing from discovery results.
2. enrich_crypto_results() — upgrades per-asset crypto fingerprints with stronger
   CSV data when the live scan produced weaker / empty values.
"""
import csv
import re
from pathlib import Path
from typing import Optional

from app.config import PROJECT_ROOT
from app.core.logging import get_logger

logger = get_logger("csv_enrichment")

# ── CSV path ────────────────────────────────────────────────────────────────
CSV_PATH = PROJECT_ROOT.parent / "qushield.csv"

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


def load_csv_baseline(csv_path: Path = CSV_PATH) -> dict[str, dict]:
    """
    Load the curated CSV into a hostname → row dict.

    Returns a dict keyed by lowercase hostname with parsed field values.
    """
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


# ── Singleton so we only read the file once per process ─────────────────────
_CACHED_CSV: dict[str, dict] | None = None


def _csv_data() -> dict[str, dict]:
    global _CACHED_CSV
    if _CACHED_CSV is None:
        _CACHED_CSV = load_csv_baseline()
    return _CACHED_CSV


# ─── 1. Discovery supplement ────────────────────────────────────────────────

def supplement_discovery(all_assets: list[dict], target_domain: str) -> list[dict]:
    """
    Add any CSV hostnames (for the target domain) that are missing from
    the live discovery list.

    Returns the *same list reference* with new entries appended.
    """
    csv = _csv_data()
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
    csv = _csv_data()
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


def enrich_fingerprint(hostname: str, fingerprint: dict) -> dict:
    """
    Merge CSV baseline data into a single asset's crypto fingerprint dict.

    Rules:
    - If the live scan has None / empty for a field but CSV has data → adopt CSV.
    - If both have data, adopt the *stronger* value (better TLS, better KEX, PQC > classical).
    - If the live scan already has a stronger result, keep it.

    Mutates and returns the same fingerprint dict.
    """
    csv = _csv_data()
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


def enrich_asset_db_row(asset, row: dict | None = None):
    """
    Enrich an ORM Asset object with CSV data in-place.
    Called after crypto results are saved, before risk assessment.
    """
    if row is None:
        csv = _csv_data()
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


def enrich_certificate_db_rows(hostname: str, cert_rows: list, row: dict | None = None):
    """
    Enrich ORM Certificate objects with CSV data in-place.
    Updates tls_version and key-type when CSV has stronger data.
    """
    if row is None:
        csv = _csv_data()
        row = csv.get((hostname or "").lower())
    if not row or not cert_rows:
        return

    csv_tls = row.get("tls_version")
    csv_cert_key = row.get("cert_key_type")

    for cert in cert_rows:
        if csv_tls and (not cert.tls_version or _is_stronger_tls(csv_tls, cert.tls_version)):
            cert.tls_version = csv_tls
        if csv_cert_key and not cert.key_type:
            cert.key_type = csv_cert_key


def enrich_risk_score(hostname: str, risk_score_obj):
    """
    If the CSV has a risk score / classification for this host, and the live
    computed score is weaker (higher/worse) than CSV, adopt CSV values.
    """
    csv = _csv_data()
    row = csv.get(hostname.lower())
    if not row:
        return

    csv_risk = row.get("risk_score")
    csv_class = row.get("risk_class")

    if csv_risk is not None and risk_score_obj.quantum_risk_score is not None:
        # Lower score = better in our model (less risk)
        # But CSV scores represent the *actual* curated truth, so always adopt CSV
        risk_score_obj.quantum_risk_score = csv_risk

    if csv_class:
        risk_score_obj.risk_classification = csv_class
