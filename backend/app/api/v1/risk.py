"""
Risk API Router — heatmap, breakdown, HNDL exposure, Mosca simulator.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.core.database import get_db
from app.models.risk import RiskScore, RiskFactor
from app.models.asset import Asset
from app.models.asset import AssetPort
from app.models.certificate import Certificate
from app.models.compliance import ComplianceResult
from app.models.cbom import CBOMComponent, CBOMRecord
from app.schemas.risk import MoscaInput
from app.services.risk_engine import compute_mosca

router = APIRouter()


@router.get("/scan/{scan_id}")
def list_risk_scores(
    scan_id: UUID,
    risk_class: Optional[str] = Query(None, description="Filter: quantum_ready, quantum_aware, quantum_at_risk, quantum_vulnerable, quantum_critical"),
    sort_by: Optional[str] = Query("quantum_risk_score", description="Sort field"),
    sort_dir: Optional[str] = Query("desc"),
    db: Session = Depends(get_db),
):
    """List all risk scores for a scan."""
    # Use joinedload to fetch assets in a single query, avoiding N+1 problem
    query = db.query(RiskScore).options(
        joinedload(RiskScore.asset)
    ).filter(RiskScore.scan_id == scan_id)
    if risk_class:
        query = query.filter(RiskScore.risk_classification == risk_class)

    # Sorting
    sort_col = getattr(RiskScore, sort_by, RiskScore.quantum_risk_score)
    if sort_dir == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())

    risks = query.all()
    items = []
    for r in risks:
        asset = r.asset  # Use preloaded asset from joinedload
        items.append({
            "id": str(r.id),
            "asset_id": str(r.asset_id),
            "hostname": asset.hostname if asset else None,
            "asset_type": asset.asset_type if asset else None,
            "quantum_risk_score": r.quantum_risk_score,
            "risk_classification": r.risk_classification,
            "mosca_x": r.mosca_x,
            "mosca_y": r.mosca_y,
            "hndl_exposed": r.hndl_exposed,
            "tnfl_risk": r.tnfl_risk,
            "tnfl_severity": r.tnfl_severity,
            "computed_at": str(r.computed_at),
        })
    return {"items": items, "total": len(items)}


@router.get("/scan/{scan_id}/heatmap")
def get_risk_heatmap(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """
    Risk heatmap data — risk score + classification for each asset,
    structured for frontend visualization.
    """
    # Use joinedload to fetch assets in a single query, avoiding N+1 problem
    risks = db.query(RiskScore).options(
        joinedload(RiskScore.asset)
    ).filter(RiskScore.scan_id == scan_id).all()
    if not risks:
        raise HTTPException(status_code=404, detail="No risk data for this scan")

    heatmap = []
    for r in risks:
        asset = r.asset  # Use preloaded asset from joinedload
        heatmap.append({
            "asset_id": str(r.asset_id),
            "hostname": asset.hostname if asset else "unknown",
            "asset_type": asset.asset_type if asset else "unknown",
            "score": r.quantum_risk_score,
            "classification": r.risk_classification,
            "hndl_exposed": r.hndl_exposed,
            "tnfl_risk": r.tnfl_risk,
        })

    # Compute classification distribution
    dist = {}
    for h in heatmap:
        cls = h["classification"]
        dist[cls] = dist.get(cls, 0) + 1

    avg_score = round(sum(h["score"] for h in heatmap) / max(len(heatmap), 1), 1)

    return {
        "scan_id": str(scan_id),
        "total_assets": len(heatmap),
        "average_risk_score": avg_score,
        "classification_distribution": dist,
        "assets": heatmap,
    }


@router.get("/asset/{asset_id}")
def get_asset_risk_detail(
    asset_id: UUID,
    db: Session = Depends(get_db),
):
    """Detailed risk breakdown for a single asset with all factors."""
    risk = db.query(RiskScore).filter(RiskScore.asset_id == asset_id).order_by(
        RiskScore.computed_at.desc()
    ).first()
    if not risk:
        raise HTTPException(status_code=404, detail="No risk score for this asset")

    factors = db.query(RiskFactor).filter(RiskFactor.risk_score_id == risk.id).all()
    asset = db.query(Asset).filter(Asset.id == asset_id).first()

    return {
        "asset_id": str(asset_id),
        "hostname": asset.hostname if asset else None,
        "quantum_risk_score": risk.quantum_risk_score,
        "risk_classification": risk.risk_classification,
        "mosca": {
            "x_migration_years": risk.mosca_x,
            "y_shelf_life_years": risk.mosca_y,
            "z_pessimistic": risk.mosca_z_pessimistic,
            "z_median": risk.mosca_z_median,
            "z_optimistic": risk.mosca_z_optimistic,
        },
        "hndl_exposed": risk.hndl_exposed,
        "tnfl_risk": risk.tnfl_risk,
        "tnfl_severity": risk.tnfl_severity,
        "computed_at": str(risk.computed_at),
        "factors": [
            {
                "name": f.factor_name,
                "score": f.factor_score,
                "weight": f.factor_weight,
                "rationale": f.rationale,
            }
            for f in factors
        ],
    }


@router.get("/scan/{scan_id}/hndl")
def get_hndl_exposure(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """HNDL (Harvest Now, Decrypt Later) exposure for all assets in a scan."""
    # Use joinedload to fetch assets in a single query, avoiding N+1 problem
    risks = db.query(RiskScore).options(
        joinedload(RiskScore.asset)
    ).filter(RiskScore.scan_id == scan_id).all()
    if not risks:
        raise HTTPException(status_code=404, detail="No risk data for this scan")

    from app.services.risk_engine import SENSITIVITY_MULTIPLIERS

    exposed = []
    safe = []
    for r in risks:
        asset = r.asset  # Use preloaded asset from joinedload
        asset_type = asset.asset_type if asset else "unknown"
        multiplier = SENSITIVITY_MULTIPLIERS.get(asset_type, 1.0)
        weighted_x = round((r.mosca_x or 0) * multiplier, 2)
        entry = {
            "asset_id": str(r.asset_id),
            "hostname": asset.hostname if asset else "unknown",
            "asset_type": asset_type,
            "hndl_exposed": r.hndl_exposed,
            "mosca_x": r.mosca_x,
            "mosca_y": r.mosca_y,
            "sensitivity_multiplier": multiplier,
            "weighted_exposure": weighted_x,
        }
        if r.hndl_exposed:
            exposed.append(entry)
        else:
            safe.append(entry)

    # Sort exposed by weighted_exposure descending (most critical first)
    exposed.sort(key=lambda e: e["weighted_exposure"], reverse=True)

    return {
        "scan_id": str(scan_id),
        "total_exposed": len(exposed),
        "total_safe": len(safe),
        "exposed_assets": exposed,
        "safe_assets": safe,
    }


@router.post("/mosca/simulate")
def simulate_mosca(input_data: MoscaInput):
    """
    Simulate Mosca's inequality with custom parameters.
    X + Y > Z → quantum risk exposure.
    """
    result = compute_mosca(
        migration_time_years=input_data.migration_time_years,
        data_shelf_life_years=input_data.data_shelf_life_years,
        crqc_scenarios={
            "pessimistic": input_data.crqc_pessimistic_year,
            "median": input_data.crqc_median_year,
            "optimistic": input_data.crqc_optimistic_year,
        },
    )
    return {
        "input": input_data.model_dump(),
        "result": result,
    }


@router.get("/scan/{scan_id}/enterprise-rating")
def get_enterprise_quantum_rating(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """
    Enterprise Cyber Quantum Rating — aggregate organization-level score (0–1000).
    6-dimension weighted model from 02-OUTPUTS.md Module 9.

    Dimensions:
    - PQC Algorithm Deployment (30%): % of critical assets using NIST PQC algorithms
    - HNDL Exposure Reduction (25%): % of traffic protected by hybrid or full PQC KEM
    - Crypto-Agility Readiness (15%): Average crypto-agility score across portfolio
    - Certificate Hygiene (10%): Expiry management, key lengths, CT compliance
    - Regulatory Compliance (10%): RBI/SEBI/PCI gap score
    - Migration Velocity (10%): Rate of PQC adoption (approximated as % quantum-ready assets)
    """
    risks = db.query(RiskScore).filter(RiskScore.scan_id == scan_id).all()
    if not risks:
        raise HTTPException(status_code=404, detail="No risk data for this scan")

    compliances = db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()
    certs = db.query(Certificate).filter(Certificate.scan_id == scan_id).all()
    components = db.query(CBOMComponent).filter(CBOMComponent.scan_id == scan_id).all()

    total_assets = len(risks)

    # Dimension 1: PQC Algorithm Deployment (30%)
    # % of assets with at least one PQC algorithm (FIPS 203/204/205)
    pqc_deployed = sum(
        1 for c in compliances
        if c.fips_203_deployed or c.fips_204_deployed or c.fips_205_deployed
    )
    pqc_pct = pqc_deployed / max(total_assets, 1) * 100
    dim_pqc = pqc_pct * 10  # scale 0-100% to 0-1000

    # Dimension 2: HNDL Exposure Reduction (25%)
    # % of assets NOT HNDL-exposed (hybrid or PQC protects new sessions)
    hndl_safe = sum(1 for r in risks if not r.hndl_exposed)
    hndl_pct = hndl_safe / max(total_assets, 1) * 100
    dim_hndl = hndl_pct * 10

    # Dimension 3: Crypto-Agility Readiness (15%)
    # Average agility score normalized to 0-1000
    avg_agility = sum(c.crypto_agility_score for c in compliances) / max(len(compliances), 1)
    dim_agility = avg_agility * 10  # 0-100 → 0-1000

    # Dimension 4: Certificate Hygiene (10%)
    # Composite: key length adequate (>=2048), CT logged, chain valid, not expired
    if certs:
        adequate_keys = sum(1 for c in certs if (c.key_length or 0) >= 2048)
        ct_logged = sum(1 for c in certs if c.is_ct_logged)
        hygiene_score = ((adequate_keys + ct_logged) / (len(certs) * 2)) * 1000
    else:
        hygiene_score = 500  # neutral if no certs found
    dim_hygiene = hygiene_score

    # Dimension 5: Regulatory Compliance (10%)
    # Average of RBI, SEBI, PCI, NPCI compliance percentages
    if compliances:
        rbi_pct = sum(1 for c in compliances if c.rbi_compliant) / len(compliances) * 100
        sebi_pct = sum(1 for c in compliances if c.sebi_compliant) / len(compliances) * 100
        pci_pct = sum(1 for c in compliances if c.pci_compliant) / len(compliances) * 100
        npci_pct = sum(1 for c in compliances if c.npci_compliant) / len(compliances) * 100
        avg_reg_pct = (rbi_pct + sebi_pct + pci_pct + npci_pct) / 4
        dim_regulatory = avg_reg_pct * 10
    else:
        dim_regulatory = 0

    # Dimension 6: Migration Velocity (10%)
    # Approximated as % of assets classified quantum_ready or quantum_aware
    migrated = sum(
        1 for r in risks
        if r.risk_classification in ("quantum_ready", "quantum_aware")
    )
    migration_pct = migrated / max(total_assets, 1) * 100
    dim_migration = migration_pct * 10

    # Weighted composite score
    composite = round(
        dim_pqc * 0.30 +
        dim_hndl * 0.25 +
        dim_agility * 0.15 +
        dim_hygiene * 0.10 +
        dim_regulatory * 0.10 +
        dim_migration * 0.10
    )
    composite = max(0, min(1000, composite))

    # Organization-level label
    if composite >= 900:
        label = "Quantum Elite"
    elif composite >= 750:
        label = "Quantum Ready"
    elif composite >= 550:
        label = "Quantum Progressing"
    elif composite >= 300:
        label = "Quantum Vulnerable"
    else:
        label = "Quantum Critical"

    return {
        "scan_id": str(scan_id),
        "enterprise_rating": composite,
        "label": label,
        "total_assets": total_assets,
        "dimensions": {
            "pqc_deployment": {"score": round(dim_pqc), "weight": 0.30, "pct_deployed": round(pqc_pct, 1)},
            "hndl_reduction": {"score": round(dim_hndl), "weight": 0.25, "pct_safe": round(hndl_pct, 1)},
            "crypto_agility": {"score": round(dim_agility), "weight": 0.15, "avg_agility": round(avg_agility, 1)},
            "certificate_hygiene": {"score": round(dim_hygiene), "weight": 0.10},
            "regulatory_compliance": {"score": round(dim_regulatory), "weight": 0.10},
            "migration_velocity": {"score": round(dim_migration), "weight": 0.10, "pct_migrated": round(migration_pct, 1)},
        },
    }


@router.get("/scan/{scan_id}/migration-plan")
def get_migration_plan(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """
    Auto-generated prioritized migration roadmap based on scan data.
    Rule-based (no AI required). Produces 4 migration phases.
    """
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    if not assets:
        raise HTTPException(status_code=404, detail="No assets for this scan")

    from app.services.risk_engine import compute_migration_complexity

    risks = {str(r.asset_id): r for r in db.query(RiskScore).filter(RiskScore.scan_id == scan_id).all()}
    compliances = {str(c.asset_id): c for c in db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()}
    certs = db.query(Certificate).filter(Certificate.scan_id == scan_id).all()

    # Index certs by asset for pinning lookup
    cert_by_asset = {}
    for c in certs:
        cert_by_asset.setdefault(str(c.asset_id), []).append(c)

    # Weak certs: RSA <= 1024 or expired
    weak_certs = [c for c in certs if (c.key_length or 0) <= 1024]

    phase0 = []  # Immediate (0-90 days)
    phase1 = []  # Hybrid Deployment (90d-18mo)
    phase2 = []  # Full PQC (18mo-36mo)
    phase3 = []  # Verification (36mo+)

    for a in assets:
        asset_id = str(a.id)
        risk = risks.get(asset_id)
        comp = compliances.get(asset_id)
        score = risk.quantum_risk_score if risk else 0
        classification = risk.risk_classification if risk else "unknown"
        agility = comp.crypto_agility_score if comp else 0

        # Dynamic migration complexity
        asset_certs = cert_by_asset.get(asset_id, [])
        is_pinned = any(getattr(c, "is_pinned", False) for c in asset_certs)
        has_fs = comp.forward_secrecy if comp else True
        complexity = compute_migration_complexity(
            asset_type=a.asset_type or "unknown",
            agility_score=agility,
            is_third_party=getattr(a, "is_third_party", False),
            is_pinned=is_pinned,
            has_forward_secrecy=has_fs,
        )

        entry = {
            "asset_id": asset_id,
            "hostname": a.hostname,
            "asset_type": a.asset_type,
            "risk_score": score,
            "classification": classification,
            "agility_score": agility,
            "migration_complexity": complexity,
        }

        # Phase 0: Critical emergencies
        if classification == "quantum_critical":
            entry["action"] = "Emergency: disable weak ciphers, enforce TLS 1.2+, replace weak certificates"
            entry["priority"] = "CRITICAL"
            phase0.append(entry)
        # Phase 0: Weak TLS or no forward secrecy on high-value assets
        elif comp and not comp.tls_13_enforced and a.asset_type in ("swift_endpoint", "internet_banking", "upi_gateway"):
            entry["action"] = "Enforce TLS 1.3, enable forward secrecy, automate cert renewal"
            entry["priority"] = "HIGH"
            phase0.append(entry)
        # Phase 1: Hybrid ML-KEM deployment candidates (high risk, classical-only)
        elif classification == "quantum_vulnerable" and score >= 700:
            entry["action"] = "Deploy ML-KEM+X25519 hybrid TLS, priority by transaction volume"
            entry["priority"] = "HIGH"
            phase1.append(entry)
        elif classification == "quantum_vulnerable":
            entry["action"] = "Schedule hybrid TLS deployment, update cipher configuration"
            entry["priority"] = "MEDIUM"
            phase1.append(entry)
        # Phase 2: Full PQC migration
        elif classification == "quantum_at_risk":
            entry["action"] = "Migrate to full PQC (ML-KEM + ML-DSA), upgrade HSM firmware if applicable"
            entry["priority"] = "MEDIUM"
            phase2.append(entry)
        # Phase 3: Verification / already migrating
        else:
            entry["action"] = "Verify PQC deployment, obtain CBOM audit, submit compliance evidence"
            entry["priority"] = "LOW"
            phase3.append(entry)

    # Sort each phase by risk score descending
    for phase in (phase0, phase1, phase2, phase3):
        phase.sort(key=lambda x: x["risk_score"], reverse=True)

    return {
        "scan_id": str(scan_id),
        "phases": {
            "phase_0_immediate": {
                "timeline": "0-90 days",
                "description": "Disable weak ciphers, enforce TLS 1.2+, replace weak certificates, enable forward secrecy",
                "asset_count": len(phase0),
                "assets": phase0,
            },
            "phase_1_hybrid": {
                "timeline": "90 days - 18 months",
                "description": "Deploy ML-KEM+X25519 hybrid TLS on internet-facing endpoints",
                "asset_count": len(phase1),
                "assets": phase1,
            },
            "phase_2_full_pqc": {
                "timeline": "18 months - 36 months",
                "description": "Full PQC migration: ML-KEM key exchange, ML-DSA signatures, HSM upgrade",
                "asset_count": len(phase2),
                "assets": phase2,
            },
            "phase_3_verification": {
                "timeline": "36+ months",
                "description": "Full CBOM audit, third-party PQC verification, regulatory certification",
                "asset_count": len(phase3),
                "assets": phase3,
            },
        },
        "weak_certificates": len(weak_certs),
        "migration_blocked_assets": sum(1 for a in assets if compliances.get(str(a.id), None) and compliances[str(a.id)].crypto_agility_score < 40),
    }


# ─── Monte Carlo CRQC Simulation Endpoints ──────────────────────────────────


@router.post("/monte-carlo/simulate")
def simulate_monte_carlo(
    n_simulations: int = Query(10000, ge=100, le=100000, description="Number of Monte Carlo samples"),
    mode_year: float = Query(2032, ge=2027, le=2045, description="Most likely CRQC arrival year"),
    sigma: float = Query(3.5, ge=0.5, le=10, description="Distribution spread (years)"),
    seed: Optional[int] = Query(None, description="Random seed for reproducibility"),
):
    """
    Monte Carlo simulation of CRQC arrival year.

    Returns probability distribution, cumulative distribution, and percentile estimates.
    Uses log-normal distribution to model asymmetric uncertainty.
    """
    from app.services.monte_carlo import simulate_crqc_arrival

    result = simulate_crqc_arrival(
        n_simulations=n_simulations,
        mode_year=mode_year,
        sigma=sigma,
        seed=seed,
    )
    return result


@router.post("/monte-carlo/asset-exposure")
def simulate_asset_exposure_endpoint(
    migration_time_years: float = Query(..., ge=0, le=20, description="X: migration time (years)"),
    data_shelf_life_years: float = Query(..., ge=0, le=50, description="Y: data shelf life (years)"),
    n_simulations: int = Query(10000, ge=100, le=100000),
    mode_year: float = Query(2032, ge=2027, le=2045),
    sigma: float = Query(3.5, ge=0.5, le=10),
    seed: Optional[int] = Query(None),
):
    """
    Monte Carlo exposure simulation for a single asset.

    For each CRQC arrival sample, checks Mosca's inequality (X + Y > Z).
    Returns probability of quantum exposure.
    """
    from app.services.monte_carlo import simulate_asset_exposure

    result = simulate_asset_exposure(
        migration_time_years=migration_time_years,
        data_shelf_life_years=data_shelf_life_years,
        n_simulations=n_simulations,
        mode_year=mode_year,
        sigma=sigma,
        seed=seed,
    )
    return result


@router.get("/scan/{scan_id}/monte-carlo")
def simulate_portfolio_monte_carlo(
    scan_id: UUID,
    n_simulations: int = Query(10000, ge=100, le=100000),
    mode_year: float = Query(2032, ge=2027, le=2045),
    sigma: float = Query(3.5, ge=0.5, le=10),
    seed: Optional[int] = Query(None),
    db: Session = Depends(get_db),
):
    """
    Full portfolio Monte Carlo simulation from scan data.

    Uses same CRQC arrival samples for all assets (correlated risk).
    Returns per-asset exposure probability, portfolio summary, and risk distribution.
    """
    from app.services.monte_carlo import simulate_portfolio
    from app.services.risk_engine import (
        MIGRATION_TIME_DEFAULTS, SHELF_LIFE_DEFAULTS,
        _infer_asset_type, compute_migration_complexity,
    )

    assets_db = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    if not assets_db:
        raise HTTPException(status_code=404, detail="No assets found for this scan")

    # Bulk query all compliance results for this scan to avoid N+1 problem
    compliances = db.query(ComplianceResult).filter(
        ComplianceResult.scan_id == scan_id
    ).all()
    # Build lookup dict by asset_id for O(1) access
    compliance_by_asset = {str(c.asset_id): c for c in compliances}

    # Build asset list with Mosca parameters
    asset_list = []
    for a in assets_db:
        asset_type = _infer_asset_type(a.hostname)
        # Use preloaded compliance data from dict instead of querying per asset
        comp = compliance_by_asset.get(str(a.id))

        agility = comp.crypto_agility_score if comp else 50.0
        migration = compute_migration_complexity(asset_type, agility)
        shelf_life = SHELF_LIFE_DEFAULTS.get(asset_type, {}).get("shelf_life_years", 5.0)

        asset_list.append({
            "hostname": a.hostname,
            "asset_type": asset_type,
            "migration_time_years": migration["complexity_years"],
            "data_shelf_life_years": shelf_life,
        })

    result = simulate_portfolio(
        assets=asset_list,
        n_simulations=n_simulations,
        mode_year=mode_year,
        sigma=sigma,
        seed=seed,
    )
    result["scan_id"] = str(scan_id)
    return result


# ─── Certificate Expiry vs CRQC Race Endpoint ───────────────────────────────


@router.get("/scan/{scan_id}/cert-race")
def get_cert_crqc_race(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """
    Certificate expiry vs CRQC arrival race analysis.

    Classifies each certificate as:
    - natural_rotation: cert expires before CRQC (good - natural reissue opportunity)
    - at_risk: cert will still be active during CRQC (bad - needs proactive reissue)
    - safe: cert already uses PQC algorithms

    Also estimates migration completion date from complexity scores.
    """
    from app.services.risk_engine import compute_cert_crqc_race

    result = compute_cert_crqc_race(str(scan_id), db)

    if result["total_certificates"] == 0:
        raise HTTPException(status_code=404, detail="No certificates found for this scan")

    return result
