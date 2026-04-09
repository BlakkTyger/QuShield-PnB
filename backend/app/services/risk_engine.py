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
_DATA_DIR = PROJECT_ROOT / "backend" / "app" / "data"

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

    factors.append({
        "name": "pqc_deployment",
        "score": pqc_score,
        "weight": 0.30,
        "max_possible": 300,
        "rationale": f"{pqc_count}/{total_crypto} algorithms are PQC-safe ({pqc_ratio*100:.0f}%)" if total_crypto > 0 else "No crypto components found",
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


# ─── P4.3: HNDL Exposure Window ─────────────────────────────────────────────


@timed(service="risk_engine")
def compute_hndl_window(
    first_seen: datetime,
    cipher_vulnerable: bool,
    data_shelf_life_years: float,
    crqc_year: int = None,
) -> dict:
    """
    Compute the Harvest-Now-Decrypt-Later exposure window.

    Args:
        first_seen: When the asset was first observed with vulnerable crypto
        cipher_vulnerable: Whether the current cipher is quantum-vulnerable
        data_shelf_life_years: How long the data must remain confidential
        crqc_year: Estimated CRQC arrival (default: pessimistic scenario)

    Returns dict with harvest_start, harvest_end, decrypt_risk_end, exposure status.
    """
    if crqc_year is None:
        crqc_year = CRQC_SCENARIOS["pessimistic"]

    now = datetime.now(timezone.utc)
    crqc_date = datetime(crqc_year, 1, 1, tzinfo=timezone.utc)
    shelf_life_delta = timedelta(days=int(data_shelf_life_years * 365.25))

    result = {
        "harvest_start": first_seen.isoformat(),
        "harvest_end": crqc_date.isoformat(),
        "decrypt_risk_start": crqc_date.isoformat(),
        "decrypt_risk_end": (crqc_date + shelf_life_delta).isoformat(),
        "is_currently_exposed": cipher_vulnerable and now < crqc_date,
        "exposure_years": round(
            max(0, (crqc_date - first_seen).days / 365.25 + data_shelf_life_years),
            2,
        ),
        "days_until_crqc": max(0, (crqc_date - now).days),
        "cipher_vulnerable": cipher_vulnerable,
    }

    logger.info(
        f"HNDL window: harvest {first_seen.year}-{crqc_year}, "
        f"decrypt risk until {crqc_year + int(data_shelf_life_years)}",
        extra={
            "harvest_start": first_seen.isoformat(),
            "crqc_year": crqc_year,
            "exposure_years": result["exposure_years"],
            "is_currently_exposed": result["is_currently_exposed"],
        },
    )

    return result


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

    # Build data dicts for risk computation
    asset_type = _infer_asset_type(asset.hostname)
    asset_data = {
        "hostname": asset.hostname,
        "asset_type": asset_type,
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

    # Compute risk score
    risk_result = compute_risk_score(asset_data, cbom_data)

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


def assess_all_assets(scan_id: str, db) -> list[dict]:
    """
    Run risk assessment for all assets in a scan.

    Returns list of risk assessment results.
    """
    from app.models.asset import Asset
    from app.models.scan import ScanJob

    scan_uuid = uuid_mod.UUID(scan_id) if isinstance(scan_id, str) else scan_id
    assets = db.query(Asset).filter(Asset.scan_id == scan_uuid).all()

    results = []
    for i, asset in enumerate(assets):
        try:
            result = assess_asset_risk(str(asset.id), scan_id, db)
            results.append(result)
            logger.info(f"[{i+1}/{len(assets)}] Assessed {asset.hostname}")
        except Exception as e:
            logger.error(f"[{i+1}/{len(assets)}] Failed {asset.hostname}: {e}")
            results.append({"asset_id": str(asset.id), "error": str(e)})

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
