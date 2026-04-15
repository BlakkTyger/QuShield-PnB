"""
Risk Engine — Mosca's theorem, quantum risk scoring, HNDL exposure, and TNFL assessment.

Implements the 5-factor weighted quantum risk scoring model from the
algorithm research document (§ 4.3), with Mosca's inequality for timeline
risk and HNDL/TNFL specialized assessments for banking assets.
"""
import json
import uuid as uuid_mod
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

import numpy as np

from app.config import settings, PROJECT_ROOT
from app.core.logging import get_logger
from app.core.timing import timed

logger = get_logger("risk_engine")

# Load static data files
_DATA_DIR = PROJECT_ROOT / "app" / "data"

with open(_DATA_DIR / "data_shelf_life_defaults.json") as f:
    SHELF_LIFE_DEFAULTS = json.load(f)


# ─── CRQC Arrival Scenarios ─────────────────────────────────────────────────

CRQC_SCENARIOS = {
    "pessimistic": 2029,  # Gidney 2025 improvements, aggressive estimates
    "median": 2032,       # GRI median expert consensus
    "optimistic": 2035,   # Conservative, slow hardware progress
}

# Default migration times by asset type (years)
MIGRATION_TIME_DEFAULTS = {
    "swift_endpoint": 3.0,
    "core_banking_api": 2.5,
    "internet_banking": 1.5,
    "upi_gateway": 1.0,
    "otp_2fa": 0.5,
    "mobile_banking": 2.0,
    "web_server": 1.0,
    "api": 1.5,
    "mail_server": 1.0,
    "dns": 0.5,
    "unknown": 1.5,
}


# ─── P4.1: Mosca's Inequality Calculator ────────────────────────────────────


@timed(service="risk_engine")
def compute_mosca(
    migration_time_years: float,
    data_shelf_life_years: float,
    crqc_scenarios: dict = None,
    reference_year: int = None,
) -> dict:
    """
    Compute Mosca's inequality: X + Y > Z → asset is at quantum risk.

    Args:
        migration_time_years: X = estimated time to migrate to PQC (years)
        data_shelf_life_years: Y = how long data must remain confidential (years)
        crqc_scenarios: dict with pessimistic/median/optimistic CRQC arrival years
        reference_year: base year for Z computation (default: current year)

    Returns dict with exposure status for each scenario and years_until_exposure.
    """
    if crqc_scenarios is None:
        crqc_scenarios = CRQC_SCENARIOS
    if reference_year is None:
        reference_year = datetime.now(timezone.utc).year

    x = migration_time_years
    y = data_shelf_life_years

    results = {}
    for scenario, crqc_year in crqc_scenarios.items():
        z = crqc_year - reference_year  # years until CRQC
        exposed = (x + y) > z
        margin = z - (x + y)  # positive = safe, negative = exposed
        results[f"exposed_{scenario}"] = exposed
        results[f"z_{scenario}"] = z
        results[f"margin_{scenario}"] = round(margin, 2)

    # Years until first exposure (pessimistic scenario)
    z_pessimistic = crqc_scenarios.get("pessimistic", 2029) - reference_year
    results["years_until_exposure"] = round(z_pessimistic - (x + y), 2)
    results["x_migration"] = x
    results["y_shelf_life"] = y
    results["reference_year"] = reference_year

    logger.info(
        f"Mosca: X={x:.1f}yr + Y={y:.1f}yr vs Z(pessimistic)={z_pessimistic:.1f}yr → "
        f"exposed={results['exposed_pessimistic']}",
        extra={
            "x": x, "y": y,
            "exposed_pessimistic": results["exposed_pessimistic"],
            "exposed_median": results["exposed_median"],
            "exposed_optimistic": results["exposed_optimistic"],
        },
    )

    return results


def compute_mosca_batch(
    assets: list[dict],
    crqc_scenarios: dict = None,
    reference_year: int = None,
) -> list[dict]:
    """
    Vectorized Mosca computation for a batch of assets using numpy.

    Each asset dict must have 'migration_time_years' and 'data_shelf_life_years'.
    """
    if crqc_scenarios is None:
        crqc_scenarios = CRQC_SCENARIOS
    if reference_year is None:
        reference_year = datetime.now(timezone.utc).year

    n = len(assets)
    x_arr = np.array([a.get("migration_time_years", 1.5) for a in assets])
    y_arr = np.array([a.get("data_shelf_life_years", 5.0) for a in assets])

    results = []
    for i in range(n):
        asset_result = {"asset_index": i}
        for scenario, crqc_year in crqc_scenarios.items():
            z = crqc_year - reference_year
            exposed = bool((x_arr[i] + y_arr[i]) > z)
            asset_result[f"exposed_{scenario}"] = exposed
            asset_result[f"z_{scenario}"] = z
        asset_result["x_migration"] = float(x_arr[i])
        asset_result["y_shelf_life"] = float(y_arr[i])
        results.append(asset_result)

    return results


# ─── P4.2: Quantum Risk Score (0–1000) ──────────────────────────────────────

# Classification thresholds
RISK_CLASSIFICATIONS = [
    (0, 199, "quantum_ready"),
    (200, 399, "quantum_aware"),
    (400, 599, "quantum_at_risk"),
    (600, 799, "quantum_vulnerable"),
    (800, 1000, "quantum_critical"),
]


def _classify_risk(score: int) -> str:
    """Classify a risk score into a named category."""
    for low, high, name in RISK_CLASSIFICATIONS:
        if low <= score <= high:
            return name
    return "quantum_critical"


@timed(service="risk_engine")
def compute_risk_score(
    asset_data: dict,
    cbom_data: dict,
    compliance_data: dict = None,
) -> dict:
    """
    Compute the 5-factor quantum risk score (0–1000).

    Factors:
    1. PQC Algorithm Deployment (30%) — from CBOM components
    2. HNDL Exposure (25%) — from Mosca result
    3. Crypto-Agility (15%) — from compliance/default
    4. Certificate Hygiene (10%) — key length, valid chain, CT logged
    5. Regulatory Compliance (10%) — from compliance/default
    6. Migration Velocity (10%) — default 0 for first scan

    Higher score = worse (more risk). Score is inverted from raw factors.
    """
    factors = []

    # ── Factor 1: PQC Algorithm Deployment (30%) ─────────────────────────
    # Lower is better (fewer PQC = higher risk)
    components = cbom_data.get("components", [])
    total_crypto = sum(1 for c in components if c.get("type") in ("algorithm", "key_exchange"))
    pqc_count = sum(1 for c in components if not c.get("is_vulnerable", True) and c.get("type") in ("algorithm", "key_exchange"))
    vulnerable_count = sum(1 for c in components if c.get("is_vulnerable", True) and c.get("type") in ("algorithm", "key_exchange"))

    if total_crypto > 0:
        pqc_ratio = pqc_count / total_crypto
        # Score: 0% PQC = 300 risk points, 100% PQC = 0 risk points
        pqc_score = int((1 - pqc_ratio) * 300)
    else:
        pqc_score = 300  # No crypto data = max risk

    # Cert-vs-KEX transition adjustment:
    # - Hybrid KEX with classical cert is partial progress (small risk reduction).
    # - Pure classical cert + classical KEX remains higher risk.
    certs_for_posture = asset_data.get("certificates", []) or []
    cert_key_types = [(c.get("key_type") or "").upper() for c in certs_for_posture]
    has_classical_cert = any(
        ("RSA" in c) or ("ECDSA" in c) or (c.startswith("EC-"))
        for c in cert_key_types
    )
    has_pqc_cert = any(
        any(marker in c for marker in ("ML-DSA", "SLH-DSA", "FALCON", "FN-DSA"))
        for c in cert_key_types
    )
    kex_name = (asset_data.get("tls_key_exchange") or "").upper()
    has_hybrid_kex = bool(
        (compliance_data or {}).get("hybrid_mode_active")
        or ("MLKEM" in kex_name)
        or ("ML-KEM" in kex_name)
        or ("KYBER" in kex_name)
    )

    posture_adjustment = 0
    posture_note = "No cert/KEX posture adjustment"
    if has_hybrid_kex and has_classical_cert and not has_pqc_cert:
        posture_adjustment = -40
        posture_note = "Hybrid/PQC KEX present, but certificate auth remains classical (partial transition)"
    elif (not has_hybrid_kex) and has_classical_cert:
        posture_adjustment = 20
        posture_note = "Classical certificate and no hybrid/PQC key exchange detected"
    elif has_hybrid_kex and has_pqc_cert:
        posture_adjustment = -80
        posture_note = "PQC/hybrid detected in both certificate and key exchange planes"
    pqc_score = max(0, min(300, pqc_score + posture_adjustment))

    factors.append({
        "name": "pqc_deployment",
        "score": pqc_score,
        "weight": 0.30,
        "max_possible": 300,
        "rationale": (
            f"{pqc_count}/{total_crypto} algorithms are PQC-safe ({pqc_ratio*100:.0f}%). "
            f"{posture_note} (adjustment {posture_adjustment:+d})."
            if total_crypto > 0
            else f"No crypto components found. {posture_note} (adjustment {posture_adjustment:+d})."
        ),
    })

    # ── Factor 2: HNDL Exposure (25%) ────────────────────────────────────
    # Check Mosca's inequality for this asset
    asset_type = asset_data.get("asset_type", "unknown")
    shelf_life = SHELF_LIFE_DEFAULTS.get(asset_type, {}).get("shelf_life_years", 5.0)
    migration_time = MIGRATION_TIME_DEFAULTS.get(asset_type, 1.5)

    mosca = compute_mosca(migration_time, shelf_life)
    # Score: exposed in pessimistic = 250, exposed in median = 200, exposed in optimistic = 150
    if mosca["exposed_pessimistic"]:
        if mosca["exposed_median"]:
            if mosca["exposed_optimistic"]:
                hndl_score = 250  # Exposed in ALL scenarios
            else:
                hndl_score = 200  # Exposed in pessimistic + median
        else:
            hndl_score = 150  # Exposed only in pessimistic
    else:
        hndl_score = 0  # Not exposed in any scenario

    factors.append({
        "name": "hndl_exposure",
        "score": hndl_score,
        "weight": 0.25,
        "max_possible": 250,
        "rationale": f"Mosca: X={migration_time}yr + Y={shelf_life}yr, exposed_pessimistic={mosca['exposed_pessimistic']}",
    })

    # ── Factor 3: Crypto-Agility Readiness (15%) ────────────────────────
    if compliance_data and "crypto_agility_score" in compliance_data:
        agility = compliance_data["crypto_agility_score"]  # 0-100
    else:
        agility = 50  # Default
    # Score: 100 agility = 0 risk, 0 agility = 150 risk
    agility_score = int((1 - agility / 100) * 150)

    factors.append({
        "name": "crypto_agility",
        "score": agility_score,
        "weight": 0.15,
        "max_possible": 150,
        "rationale": f"Crypto-agility score: {agility}/100",
    })

    # ── Factor 4: Certificate Hygiene (10%) ──────────────────────────────
    certs = [c for c in components if c.get("type") == "certificate"]
    hygiene_checks = {"key_length": False, "chain_valid": True, "ct_logged": False, "not_expiring": True}

    for cert in certs:
        key_length = cert.get("key_length", 0)
        if key_length >= 2048:
            hygiene_checks["key_length"] = True

    # Use asset_data for more cert info
    cert_data_list = asset_data.get("certificates", [])
    for cert in cert_data_list:
        if cert.get("is_ct_logged"):
            hygiene_checks["ct_logged"] = True
        if cert.get("chain_valid") is False:
            hygiene_checks["chain_valid"] = False
        days_expiry = cert.get("days_until_expiry", 365)
        if isinstance(days_expiry, (int, float)) and days_expiry < 30:
            hygiene_checks["not_expiring"] = False

    checks_passed = sum(1 for v in hygiene_checks.values() if v)
    hygiene_ratio = checks_passed / max(len(hygiene_checks), 1)
    # Score: perfect hygiene = 0 risk, no hygiene = 100 risk
    hygiene_score = int((1 - hygiene_ratio) * 100)

    factors.append({
        "name": "certificate_hygiene",
        "score": hygiene_score,
        "weight": 0.10,
        "max_possible": 100,
        "rationale": f"Hygiene checks: {checks_passed}/{len(hygiene_checks)} passed ({hygiene_checks})",
    })

    # ── Factor 5: Regulatory Compliance (10%) ────────────────────────────
    if compliance_data and "compliance_pct" in compliance_data:
        compliance_pct = compliance_data["compliance_pct"]
    else:
        compliance_pct = 50  # Default
    # Score: 100% compliant = 0 risk, 0% = 100 risk
    compliance_score = int((1 - compliance_pct / 100) * 100)

    factors.append({
        "name": "regulatory_compliance",
        "score": compliance_score,
        "weight": 0.10,
        "max_possible": 100,
        "rationale": f"Compliance: {compliance_pct}%",
    })

    # ── Factor 6: Migration Velocity (10%) ───────────────────────────────
    if compliance_data and "migration_velocity" in compliance_data:
        velocity = compliance_data["migration_velocity"]  # 0-100
    else:
        velocity = 0  # Default: no migration started
    # Score: 100% velocity = 0 risk, 0% = 100 risk
    velocity_score = int((1 - velocity / 100) * 100)

    factors.append({
        "name": "migration_velocity",
        "score": velocity_score,
        "weight": 0.10,
        "max_possible": 100,
        "rationale": f"Migration velocity: {velocity}%",
    })

    # ── Total Score ──────────────────────────────────────────────────────
    total_score = sum(f["score"] for f in factors)
    total_score = max(0, min(1000, total_score))  # Clamp to 0-1000
    classification = _classify_risk(total_score)

    result = {
        "quantum_risk_score": total_score,
        "risk_classification": classification,
        "factors": factors,
        "mosca": mosca,
    }

    logger.info(
        f"Risk score: {total_score} ({classification})",
        extra={
            "score": total_score,
            "classification": classification,
            "pqc_ratio": pqc_ratio if total_crypto > 0 else 0,
            "hndl_exposed": mosca["exposed_pessimistic"],
        },
    )

    return result


# ─── Data Sensitivity Multipliers for HNDL ─────────────────────────────────

SENSITIVITY_MULTIPLIERS = {
    "swift_endpoint": 5.0,
    "internet_banking": 3.0,
    "upi_gateway": 3.0,
    "core_banking_api": 3.5,
    "api_gateway": 2.5,
    "api": 2.0,
    "mail_server": 2.0,
    "mobile_banking": 2.5,
    "otp_2fa": 2.0,
    "web_server": 1.0,
    "dns_server": 0.5,
    "dns": 0.5,
    "cdn_endpoint": 0.5,
    "unknown": 1.0,
}


# ─── P4.3: HNDL Exposure Window ─────────────────────────────────────────────


@timed(service="risk_engine")
def compute_hndl_window(
    first_seen: datetime,
    cipher_vulnerable: bool,
    data_shelf_life_years: float,
    crqc_year: int = None,
    asset_type: str = None,
) -> dict:
    """
    Compute the Harvest-Now-Decrypt-Later exposure window.

    Args:
        first_seen: When the asset was first observed with vulnerable crypto
        cipher_vulnerable: Whether the current cipher is quantum-vulnerable
        data_shelf_life_years: How long the data must remain confidential
        crqc_year: Estimated CRQC arrival (default: pessimistic scenario)
        asset_type: Asset type for sensitivity multiplier (e.g., "swift_endpoint")

    Returns dict with harvest_start, harvest_end, decrypt_risk_end, exposure status,
    and weighted_exposure with sensitivity multiplier applied.
    """
    if crqc_year is None:
        crqc_year = CRQC_SCENARIOS["pessimistic"]

    now = datetime.now(timezone.utc)
    crqc_date = datetime(crqc_year, 1, 1, tzinfo=timezone.utc)
    shelf_life_delta = timedelta(days=int(data_shelf_life_years * 365.25))

    exposure_years = round(
        max(0, (crqc_date - first_seen).days / 365.25 + data_shelf_life_years),
        2,
    )

    # Apply sensitivity multiplier
    multiplier = SENSITIVITY_MULTIPLIERS.get(asset_type or "unknown", 1.0)
    weighted_exposure = round(exposure_years * multiplier, 2)

    result = {
        "harvest_start": first_seen.isoformat(),
        "harvest_end": crqc_date.isoformat(),
        "decrypt_risk_start": crqc_date.isoformat(),
        "decrypt_risk_end": (crqc_date + shelf_life_delta).isoformat(),
        "is_currently_exposed": cipher_vulnerable and now < crqc_date,
        "exposure_years": exposure_years,
        "sensitivity_multiplier": multiplier,
        "weighted_exposure": weighted_exposure,
        "asset_type": asset_type,
        "days_until_crqc": max(0, (crqc_date - now).days),
        "cipher_vulnerable": cipher_vulnerable,
    }

    logger.info(
        f"HNDL window: harvest {first_seen.year}-{crqc_year}, "
        f"decrypt risk until {crqc_year + int(data_shelf_life_years)}",
        extra={
            "harvest_start": first_seen.isoformat(),
            "crqc_year": crqc_year,
            "exposure_years": exposure_years,
            "sensitivity_multiplier": multiplier,
            "weighted_exposure": weighted_exposure,
            "is_currently_exposed": result["is_currently_exposed"],
        },
    )

    return result


# ─── Dynamic Migration Complexity Scoring ──────────────────────────────────

# Base migration times by asset type (years)
MIGRATION_BASE_TIMES = {
    "swift_endpoint": 4.0,
    "core_banking_api": 3.0,
    "internet_banking": 2.5,
    "upi_gateway": 2.0,
    "mobile_banking": 2.5,
    "otp_2fa": 1.0,
    "api_gateway": 2.0,
    "api": 1.5,
    "mail_server": 1.0,
    "web_server": 1.0,
    "dns_server": 0.5,
    "dns": 0.5,
    "cdn_endpoint": 0.5,
    "unknown": 1.5,
}


def compute_migration_complexity(
    asset_type: str,
    agility_score: float = 50.0,
    is_third_party: bool = False,
    is_pinned: bool = False,
    has_forward_secrecy: bool = True,
) -> dict:
    """
    Compute dynamic migration complexity (Mosca's X parameter).

    Instead of static defaults, adjusts based on real scan data:
    - Low crypto-agility → +2 years (migration-blocked)
    - Third-party dependency → +1 year (vendor coordination)
    - Certificate pinning → +1 year (mobile app update barrier)
    - No forward secrecy → +0.5 years (cipher reconfiguration)

    Returns dict with complexity_years, base_time, adjustments, and capped total.
    """
    base = MIGRATION_BASE_TIMES.get(asset_type, 1.5)
    adjustments = []

    complexity = base

    if agility_score < 40:
        complexity += 2.0
        adjustments.append({"reason": "low_crypto_agility", "penalty": 2.0,
                           "detail": f"Agility score {agility_score:.0f}/100 < 40"})

    if is_third_party:
        complexity += 1.0
        adjustments.append({"reason": "third_party_dependency", "penalty": 1.0,
                           "detail": "Vendor coordination required"})

    if is_pinned:
        complexity += 1.0
        adjustments.append({"reason": "certificate_pinning", "penalty": 1.0,
                           "detail": "Mobile app cert pinning requires app update cycle"})

    if not has_forward_secrecy:
        complexity += 0.5
        adjustments.append({"reason": "no_forward_secrecy", "penalty": 0.5,
                           "detail": "Cipher suite reconfiguration needed"})

    # Cap at 8 years
    capped = min(complexity, 8.0)

    return {
        "complexity_years": round(capped, 1),
        "base_time_years": base,
        "adjustments": adjustments,
        "total_penalty": round(complexity - base, 1),
        "was_capped": complexity > 8.0,
        "asset_type": asset_type,
    }


# ─── P4.4: TNFL Risk Assessment ─────────────────────────────────────────────

# TNFL rule table from algorithm research § 4.5
_TNFL_RULES = [
    {
        "check": "SWIFT signing",
        "asset_types": ["swift_endpoint"],
        "signature_algos": ["RSA", "ECDSA", "ECDHE-RSA", "ECDHE-ECDSA"],
        "severity": "CRITICAL",
    },
    {
        "check": "UPI authorization",
        "asset_types": ["upi_gateway"],
        "signature_algos": ["RSA", "ECDSA", "ECDHE-RSA", "ECDHE-ECDSA"],
        "severity": "CRITICAL",
    },
    {
        "check": "Core banking signing",
        "asset_types": ["core_banking_api"],
        "signature_algos": ["RSA", "ECDSA"],
        "severity": "HIGH",
    },
    {
        "check": "Certificate issuance",
        "asset_types": ["ca"],  # Certificate Authority
        "signature_algos": ["RSA", "ECDSA"],
        "severity": "HIGH",
    },
    {
        "check": "JWT signing",
        "asset_types": ["*"],  # Any asset
        "auth_mechs": ["JWT-RS256", "JWT-RS384", "JWT-RS512", "JWT-ES256", "JWT-ES384",
                        "OIDC", "Bearer"],
        "signature_algos": ["RSA", "ECDSA", "ECDHE-RSA"],
        "severity": "MEDIUM",
    },
    {
        "check": "mTLS authentication",
        "asset_types": ["*"],
        "auth_mechs": ["mTLS"],
        "signature_algos": ["RSA", "ECDSA"],
        "severity": "MEDIUM",
    },
]


@timed(service="risk_engine")
def assess_tnfl(
    asset_type: str,
    signature_algorithm: str,
    auth_mechanisms: list = None,
) -> dict:
    """
    Assess Trust-Now-Forge-Later (TNFL) risk for an asset.

    Evaluates whether the asset's signature-dependent operations are
    vulnerable to future quantum forgery attacks.

    Returns dict with tnfl_risk, tnfl_severity, tnfl_contexts.
    """
    if auth_mechanisms is None:
        auth_mechanisms = []

    result = {
        "tnfl_risk": False,
        "tnfl_severity": None,
        "tnfl_contexts": [],
    }

    sig_upper = signature_algorithm.upper() if signature_algorithm else ""

    for rule in _TNFL_RULES:
        # Check asset type match
        type_match = asset_type in rule["asset_types"] or "*" in rule["asset_types"]
        if not type_match:
            continue

        # Check signature algorithm match
        algo_match = any(
            algo.upper() in sig_upper or sig_upper.startswith(algo.upper())
            for algo in rule.get("signature_algos", [])
        )

        # Check auth mechanism match (if rule has auth_mechs)
        auth_match = True
        if "auth_mechs" in rule:
            auth_match = any(
                mech in auth_mechanisms
                for mech in rule["auth_mechs"]
            )

        if algo_match and (auth_match or "auth_mechs" not in rule):
            result["tnfl_risk"] = True
            result["tnfl_contexts"].append(rule["check"])
            # Keep highest severity
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            current_sev = severity_order.get(result["tnfl_severity"], 0)
            rule_sev = severity_order.get(rule["severity"], 0)
            if rule_sev > current_sev:
                result["tnfl_severity"] = rule["severity"]

    logger.info(
        f"TNFL assessment: type={asset_type}, sig={signature_algorithm} → "
        f"risk={result['tnfl_risk']}, severity={result['tnfl_severity']}",
        extra={
            "asset_type": asset_type,
            "signature_algorithm": signature_algorithm,
            "tnfl_risk": result["tnfl_risk"],
            "tnfl_severity": result["tnfl_severity"],
            "contexts": result["tnfl_contexts"],
        },
    )

    return result


# ─── P4.5: Full Risk Assessment for an Asset ────────────────────────────────


@timed(service="risk_engine")
def assess_asset_risk(asset_id: str, scan_id: str, db) -> dict:
    """
    Full risk assessment for a single asset.

    Pulls asset data + CBOM components from DB, runs:
    Mosca → risk score → HNDL window → TNFL.
    Saves RiskScore and RiskFactor records to DB.

    Returns full risk assessment dict.
    """
    from app.models.asset import Asset
    from app.models.cbom import CBOMRecord, CBOMComponent
    from app.models.certificate import Certificate
    from app.models.compliance import ComplianceResult
    from app.models.risk import RiskScore, RiskFactor

    asset_uuid = uuid_mod.UUID(asset_id) if isinstance(asset_id, str) else asset_id
    scan_uuid = uuid_mod.UUID(scan_id) if isinstance(scan_id, str) else scan_id

    # Fetch asset
    asset = db.query(Asset).filter(Asset.id == asset_uuid).first()
    if not asset:
        return {"error": f"Asset {asset_id} not found"}

    # Fetch CBOM components for this asset
    cbom_record = db.query(CBOMRecord).filter(
        CBOMRecord.asset_id == asset_uuid,
        CBOMRecord.scan_id == scan_uuid,
    ).first()

    cbom_components = []
    if cbom_record:
        cbom_components = db.query(CBOMComponent).filter(
            CBOMComponent.cbom_id == cbom_record.id
        ).all()

    # Fetch certificates
    certificates = db.query(Certificate).filter(
        Certificate.asset_id == asset_uuid,
        Certificate.scan_id == scan_uuid,
    ).all()
    compliance = db.query(ComplianceResult).filter(
        ComplianceResult.asset_id == asset_uuid,
        ComplianceResult.scan_id == scan_uuid,
    ).order_by(ComplianceResult.computed_at.desc()).first()

    # Build data dicts for risk computation
    asset_type = _infer_asset_type(asset.hostname)
    asset_data = {
        "hostname": asset.hostname,
        "asset_type": asset_type,
        "tls_key_exchange": certificates[0].negotiated_cipher if certificates else None,
        "certificates": [
            {
                "key_type": c.key_type,
                "key_length": c.key_length,
                "is_ct_logged": c.is_ct_logged,
                "chain_valid": c.chain_valid,
                "days_until_expiry": (c.valid_to - datetime.now(timezone.utc)).days if c.valid_to else 365,
            }
            for c in certificates
        ],
    }

    cbom_data = {
        "components": [
            {
                "name": c.name,
                "type": c.component_type,
                "is_vulnerable": c.is_quantum_vulnerable,
                "nist_level": c.nist_quantum_level,
                "key_type": c.key_type,
                "key_length": c.key_length,
            }
            for c in cbom_components
        ],
    }
    kex_component_name = next(
        (
            c.get("name")
            for c in cbom_data["components"]
            if c.get("type") == "key_exchange" and c.get("name")
        ),
        None,
    )
    if kex_component_name:
        asset_data["tls_key_exchange"] = kex_component_name

    # Compute risk score
    risk_result = compute_risk_score(
        asset_data,
        cbom_data,
        compliance_data={
            "hybrid_mode_active": bool(compliance.hybrid_mode_active) if compliance else False,
            "fips_203_deployed": bool(compliance.fips_203_deployed) if compliance else False,
            "fips_204_deployed": bool(compliance.fips_204_deployed) if compliance else False,
            "fips_205_deployed": bool(compliance.fips_205_deployed) if compliance else False,
            "crypto_agility_score": (compliance.crypto_agility_score if compliance else 50),
            "compliance_pct": (compliance.compliance_pct if compliance else 50),
        },
    )

    # Compute HNDL window
    first_seen = asset.created_at if hasattr(asset, "created_at") and asset.created_at else datetime.now(timezone.utc)
    cipher_vulnerable = any(c.is_quantum_vulnerable for c in certificates) if certificates else True
    shelf_life = SHELF_LIFE_DEFAULTS.get(asset_type, {}).get("shelf_life_years", 5.0)
    hndl = compute_hndl_window(first_seen, cipher_vulnerable, shelf_life)

    # Compute TNFL
    sig_algo = certificates[0].signature_algorithm if certificates else "RSA"
    auth_mechs = []  # Would come from auth fingerprinting
    tnfl = assess_tnfl(asset_type, sig_algo, auth_mechs)

    # Save to DB
    risk_score_record = RiskScore(
        asset_id=asset_uuid,
        scan_id=scan_uuid,
        quantum_risk_score=risk_result["quantum_risk_score"],
        risk_classification=risk_result["risk_classification"],
        mosca_x=risk_result["mosca"]["x_migration"],
        mosca_y=risk_result["mosca"]["y_shelf_life"],
        mosca_z_pessimistic=float(CRQC_SCENARIOS["pessimistic"]),
        mosca_z_median=float(CRQC_SCENARIOS["median"]),
        mosca_z_optimistic=float(CRQC_SCENARIOS["optimistic"]),
        hndl_exposed=hndl["is_currently_exposed"],
        tnfl_risk=tnfl["tnfl_risk"],
        tnfl_severity=tnfl["tnfl_severity"],
    )
    db.add(risk_score_record)
    db.flush()

    # Save risk factors
    for factor in risk_result["factors"]:
        db_factor = RiskFactor(
            risk_score_id=risk_score_record.id,
            factor_name=factor["name"],
            factor_score=factor["score"],
            factor_weight=factor["weight"],
            rationale=factor["rationale"],
        )
        db.add(db_factor)

    db.commit()

    logger.info(
        f"Risk assessment complete for {asset.hostname}: "
        f"score={risk_result['quantum_risk_score']} ({risk_result['risk_classification']})",
        extra={
            "asset_id": asset_id,
            "score": risk_result["quantum_risk_score"],
            "classification": risk_result["risk_classification"],
            "tnfl_risk": tnfl["tnfl_risk"],
            "hndl_exposed": hndl["is_currently_exposed"],
        },
    )

    return {
        "asset_id": asset_id,
        "hostname": asset.hostname,
        "risk_score": risk_result,
        "hndl": hndl,
        "tnfl": tnfl,
        "risk_record_id": str(risk_score_record.id),
    }


def assess_all_assets(scan_id: str, db, skip_asset_ids: set = None) -> list[dict]:
    """
    Run risk assessment for all assets in a scan.

    Args:
        skip_asset_ids: Optional set of asset ID strings to skip (already cloned).

    Returns list of risk assessment results.
    """
    from app.models.asset import Asset
    from app.models.scan import ScanJob

    scan_uuid = uuid_mod.UUID(scan_id) if isinstance(scan_id, str) else scan_id
    assets = db.query(Asset).filter(Asset.scan_id == scan_uuid).all()
    skip = skip_asset_ids or set()

    results = []
    for i, asset in enumerate(assets):
        if str(asset.id) not in skip:
            try:
                result = assess_asset_risk(str(asset.id), scan_id, db)
                results.append(result)
                logger.info(f"[{i+1}/{len(assets)}] Assessed {asset.hostname}")
            except Exception as e:
                logger.error(f"[{i+1}/{len(assets)}] Failed {asset.hostname}: {e}")
                results.append({"asset_id": str(asset.id), "error": str(e)})
        else:
            logger.info(f"[{i+1}/{len(assets)}] Skipped {asset.hostname} (cloned)")

    # Summary
    classifications = {}
    for r in results:
        if "risk_score" in r:
            cls = r["risk_score"]["risk_classification"]
            classifications[cls] = classifications.get(cls, 0) + 1

    logger.info(
        f"Risk assessment complete: {len(results)} assets — {classifications}",
        extra={"scan_id": scan_id, "total": len(results), "distribution": classifications},
    )

    return results


def _infer_asset_type(hostname: str) -> str:
    """Infer asset type from hostname patterns."""
    hostname_lower = hostname.lower()

    if "swift" in hostname_lower:
        return "swift_endpoint"
    if "upi" in hostname_lower or "npci" in hostname_lower:
        return "upi_gateway"
    if "otp" in hostname_lower or "2fa" in hostname_lower or "auth" in hostname_lower:
        return "otp_2fa"
    if "mobile" in hostname_lower or "mbanking" in hostname_lower:
        return "mobile_banking"
    if "core" in hostname_lower or "cbs" in hostname_lower:
        return "core_banking_api"
    if "api" in hostname_lower:
        return "api"
    if "mail" in hostname_lower or "smtp" in hostname_lower:
        return "mail_server"
    if "dns" in hostname_lower or "ns1" in hostname_lower or "ns2" in hostname_lower:
        return "dns"
    if "bank" in hostname_lower or "online" in hostname_lower or "net" in hostname_lower:
        return "internet_banking"

    return "web_server"


# ─── Certificate Expiry vs CRQC Race Analysis ──────────────────────────────


@timed(service="risk_engine")
def compute_cert_crqc_race(scan_id: str, db) -> dict:
    """
    Analyze the race between certificate expiry dates and estimated CRQC arrival.

    Classifies each certificate as:
    - 'natural_rotation': cert expires BEFORE CRQC → good (natural reissue opportunity)
    - 'at_risk': cert will NOT expire before CRQC arrival → bad (classical cert active during CRQC)
    - 'safe': cert uses PQC algorithms or is already hybrid

    Also estimates migration completion date from per-asset complexity scores.

    Returns dict with per-certificate analysis, summary counts, and recommendations.
    """
    from app.models.asset import Asset
    from app.models.certificate import Certificate
    from app.models.compliance import ComplianceResult

    scan_uuid = uuid_mod.UUID(scan_id) if isinstance(scan_id, str) else scan_id

    # Fetch all certificates for this scan
    certificates = db.query(Certificate).filter(Certificate.scan_id == scan_uuid).all()
    assets = db.query(Asset).filter(Asset.scan_id == scan_uuid).all()
    asset_map = {str(a.id): a for a in assets}

    # CRQC arrival estimates
    crqc_pessimistic = datetime(CRQC_SCENARIOS["pessimistic"], 1, 1, tzinfo=timezone.utc)
    crqc_median = datetime(CRQC_SCENARIOS["median"], 1, 1, tzinfo=timezone.utc)
    crqc_optimistic = datetime(CRQC_SCENARIOS["optimistic"], 1, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)

    # PQC-safe key types and algorithms
    pqc_safe_markers = {"ML-KEM", "ML-DSA", "SLH-DSA", "FN-DSA", "HQC", "FALCON"}

    cert_results = []
    summary = {"natural_rotation": 0, "at_risk": 0, "safe": 0, "expired": 0}

    for cert in certificates:
        asset = asset_map.get(str(cert.asset_id))
        hostname = asset.hostname if asset else "unknown"
        asset_type = _infer_asset_type(hostname) if asset else "unknown"

        # Check if cert is already PQC-safe
        is_pqc = False
        if cert.key_type:
            for marker in pqc_safe_markers:
                if marker.upper() in cert.key_type.upper():
                    is_pqc = True
                    break
        if cert.signature_algorithm:
            for marker in pqc_safe_markers:
                if marker.upper() in cert.signature_algorithm.upper():
                    is_pqc = True
                    break

        # Determine cert expiry
        cert_expiry = cert.valid_to if hasattr(cert, "valid_to") and cert.valid_to else None
        if cert_expiry and cert_expiry.tzinfo is None:
            cert_expiry = cert_expiry.replace(tzinfo=timezone.utc)

        # Compute migration estimate for this asset
        agility_score = 50.0
        if asset:
            comp = db.query(ComplianceResult).filter(
                ComplianceResult.asset_id == asset.id,
                ComplianceResult.scan_id == scan_uuid,
            ).first()
            if comp and comp.crypto_agility_score is not None:
                agility_score = comp.crypto_agility_score

        migration = compute_migration_complexity(asset_type, agility_score)
        migration_completion = now + timedelta(days=int(migration["complexity_years"] * 365.25))

        # Classification
        if is_pqc:
            race_status = "safe"
            recommendation = "Already PQC-secured. No action needed."
        elif cert_expiry is None:
            race_status = "at_risk"
            recommendation = "No expiry data. Assume at risk — schedule PQC cert reissue."
        elif cert_expiry < now:
            race_status = "expired"
            recommendation = "Certificate expired. Reissue with PQC algorithm."
        elif cert_expiry < crqc_pessimistic:
            race_status = "natural_rotation"
            recommendation = (
                f"Cert expires {cert_expiry.strftime('%Y-%m-%d')} before CRQC "
                f"({CRQC_SCENARIOS['pessimistic']}). Reissue with PQC at next renewal."
            )
        elif cert_expiry < crqc_median:
            race_status = "at_risk"
            recommendation = (
                f"Cert expires {cert_expiry.strftime('%Y-%m-%d')} — between pessimistic "
                f"({CRQC_SCENARIOS['pessimistic']}) and median ({CRQC_SCENARIOS['median']}) "
                f"CRQC estimates. Proactively reissue with PQC before {CRQC_SCENARIOS['pessimistic']}."
            )
        else:
            race_status = "at_risk"
            recommendation = (
                f"Cert valid until {cert_expiry.strftime('%Y-%m-%d')} — will be active during "
                f"likely CRQC arrival. Critical: reissue with PQC algorithm ASAP."
            )

        summary[race_status] = summary.get(race_status, 0) + 1

        cert_results.append({
            "hostname": hostname,
            "subject_cn": cert.common_name,
            "issuer_cn": cert.issuer,
            "key_type": cert.key_type,
            "key_length": cert.key_length,
            "signature_algorithm": cert.signature_algorithm,
            "not_after": cert_expiry.isoformat() if cert_expiry else None,
            "days_until_expiry": (cert_expiry - now).days if cert_expiry and cert_expiry > now else 0,
            "is_pqc": is_pqc,
            "race_status": race_status,
            "crqc_pessimistic": crqc_pessimistic.isoformat(),
            "crqc_median": crqc_median.isoformat(),
            "migration_completion_est": migration_completion.isoformat(),
            "migration_years": migration["complexity_years"],
            "recommendation": recommendation,
        })

    # Sort: at_risk first, then natural_rotation, then safe
    status_order = {"at_risk": 0, "expired": 1, "natural_rotation": 2, "safe": 3}
    cert_results.sort(key=lambda x: status_order.get(x["race_status"], 99))

    total = len(certificates)
    result = {
        "scan_id": scan_id,
        "total_certificates": total,
        "safe": summary.get("safe", 0),
        "natural_rotation": summary.get("natural_rotation", 0),
        "at_risk": summary.get("at_risk", 0),
        "expired": summary.get("expired", 0),
        "pct_at_risk": summary.get("at_risk", 0) / max(total, 1),
        "crqc_median_arrival": CRQC_SCENARIOS["median"],
        "analysis_date": now.isoformat(),
        "crqc_scenarios": CRQC_SCENARIOS,
        "certificates": cert_results,
        "headline": _generate_race_headline(summary, total),
    }

    logger.info(
        f"Cert-CRQC race analysis: {len(certificates)} certs — {summary}",
        extra={"scan_id": scan_id, "summary": summary},
    )

    return result


def _generate_race_headline(summary: dict, total: int) -> str:
    """Generate a human-readable headline for the cert-CRQC race analysis."""
    at_risk = summary.get("at_risk", 0)
    natural = summary.get("natural_rotation", 0)
    safe = summary.get("safe", 0)

    if at_risk == 0:
        return f"✅ All {total} certificates are either PQC-safe or will expire before CRQC arrival."
    elif at_risk >= total * 0.7:
        return f"⚠️ CRITICAL: {at_risk}/{total} certificates will still be active during CRQC arrival. Immediate PQC reissue needed."
    else:
        return f"⚠️ {at_risk}/{total} certificates at risk of being active during CRQC. {natural} have natural rotation opportunities."
