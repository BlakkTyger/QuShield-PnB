"""
Compliance API Router — FIPS matrix, regulatory compliance, crypto-agility.
"""
import json
from datetime import date, datetime
from typing import Optional
from uuid import UUID
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.config import PROJECT_ROOT
from app.models.compliance import ComplianceResult
from app.models.asset import Asset

router = APIRouter()


@router.get("/scan/{scan_id}")
def list_compliance_results(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """List all compliance results for a scan."""
    results = db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()
    items = []
    for r in results:
        asset = db.query(Asset).filter(Asset.id == r.asset_id).first()
        items.append({
            "id": str(r.id),
            "asset_id": str(r.asset_id),
            "hostname": asset.hostname if asset else None,
            "fips_203_deployed": r.fips_203_deployed,
            "fips_204_deployed": r.fips_204_deployed,
            "fips_205_deployed": r.fips_205_deployed,
            "tls_13_enforced": r.tls_13_enforced,
            "forward_secrecy": r.forward_secrecy,
            "hybrid_mode_active": r.hybrid_mode_active,
            "cert_key_adequate": r.cert_key_adequate,
            "ct_logged": r.ct_logged,
            "chain_valid": r.chain_valid,
            "rbi_compliant": r.rbi_compliant,
            "sebi_compliant": r.sebi_compliant,
            "pci_compliant": r.pci_compliant,
            "npci_compliant": r.npci_compliant,
            "crypto_agility_score": r.crypto_agility_score,
            "compliance_pct": r.compliance_pct,
            "computed_at": str(r.computed_at),
        })
    return {"items": items, "total": len(items)}


@router.get("/scan/{scan_id}/fips-matrix")
def get_fips_matrix(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """FIPS 203/204/205 deployment matrix for all assets in a scan."""
    results = db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()
    if not results:
        raise HTTPException(status_code=404, detail="No compliance data for this scan")

    matrix = []
    for r in results:
        asset = db.query(Asset).filter(Asset.id == r.asset_id).first()
        matrix.append({
            "asset_id": str(r.asset_id),
            "hostname": asset.hostname if asset else "unknown",
            "asset_type": asset.asset_type if asset else "unknown",
            "fips_203_ml_kem": r.fips_203_deployed,
            "fips_204_ml_dsa": r.fips_204_deployed,
            "fips_205_slh_dsa": r.fips_205_deployed,
            "hybrid_mode": r.hybrid_mode_active,
            "classical_deprecated": r.classical_deprecated,
            "tls_13": r.tls_13_enforced,
            "forward_secrecy": r.forward_secrecy,
        })

    # Summary
    total = len(matrix)
    summary = {
        "total_assets": total,
        "fips_203_deployed": sum(1 for m in matrix if m["fips_203_ml_kem"]),
        "fips_204_deployed": sum(1 for m in matrix if m["fips_204_ml_dsa"]),
        "fips_205_deployed": sum(1 for m in matrix if m["fips_205_slh_dsa"]),
        "hybrid_active": sum(1 for m in matrix if m["hybrid_mode"]),
        "tls_13_enforced": sum(1 for m in matrix if m["tls_13"]),
    }

    return {"scan_id": str(scan_id), "summary": summary, "matrix": matrix}


@router.get("/scan/{scan_id}/regulatory")
def get_regulatory_compliance(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """India-specific regulatory compliance summary (RBI, SEBI, PCI, NPCI)."""
    results = db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()
    if not results:
        raise HTTPException(status_code=404, detail="No compliance data for this scan")

    total = len(results)
    return {
        "scan_id": str(scan_id),
        "total_assets": total,
        "regulations": {
            "rbi_it_framework": {
                "compliant": sum(1 for r in results if r.rbi_compliant),
                "non_compliant": sum(1 for r in results if not r.rbi_compliant),
                "pct": round(sum(1 for r in results if r.rbi_compliant) / max(total, 1) * 100, 1),
            },
            "sebi_cscrf": {
                "compliant": sum(1 for r in results if r.sebi_compliant),
                "non_compliant": sum(1 for r in results if not r.sebi_compliant),
                "pct": round(sum(1 for r in results if r.sebi_compliant) / max(total, 1) * 100, 1),
            },
            "pci_dss_4": {
                "compliant": sum(1 for r in results if r.pci_compliant),
                "non_compliant": sum(1 for r in results if not r.pci_compliant),
                "pct": round(sum(1 for r in results if r.pci_compliant) / max(total, 1) * 100, 1),
            },
            "npci_upi": {
                "compliant": sum(1 for r in results if r.npci_compliant),
                "non_compliant": sum(1 for r in results if not r.npci_compliant),
                "pct": round(sum(1 for r in results if r.npci_compliant) / max(total, 1) * 100, 1),
            },
        },
    }


@router.get("/scan/{scan_id}/agility")
def get_agility_distribution(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """Crypto-agility score distribution across all assets."""
    results = db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()
    if not results:
        raise HTTPException(status_code=404, detail="No compliance data for this scan")

    scores = [r.crypto_agility_score for r in results]
    buckets = {"0-20": 0, "21-40": 0, "41-60": 0, "61-80": 0, "81-100": 0}
    for s in scores:
        if s <= 20:
            buckets["0-20"] += 1
        elif s <= 40:
            buckets["21-40"] += 1
        elif s <= 60:
            buckets["41-60"] += 1
        elif s <= 80:
            buckets["61-80"] += 1
        else:
            buckets["81-100"] += 1

    return {
        "scan_id": str(scan_id),
        "total_assets": len(scores),
        "average_agility": round(sum(scores) / max(len(scores), 1), 1),
        "min_agility": min(scores) if scores else 0,
        "max_agility": max(scores) if scores else 0,
        "distribution": buckets,
    }


@router.get("/asset/{asset_id}")
def get_asset_compliance_detail(
    asset_id: UUID,
    db: Session = Depends(get_db),
):
    """Detailed compliance result for a single asset including all checks."""
    r = db.query(ComplianceResult).filter(ComplianceResult.asset_id == asset_id).order_by(
        ComplianceResult.computed_at.desc()
    ).first()
    if not r:
        raise HTTPException(status_code=404, detail="No compliance data for this asset")

    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    return {
        "asset_id": str(asset_id),
        "hostname": asset.hostname if asset else None,
        "fips_203_deployed": r.fips_203_deployed,
        "fips_204_deployed": r.fips_204_deployed,
        "fips_205_deployed": r.fips_205_deployed,
        "tls_13_enforced": r.tls_13_enforced,
        "forward_secrecy": r.forward_secrecy,
        "hybrid_mode_active": r.hybrid_mode_active,
        "classical_deprecated": r.classical_deprecated,
        "cert_key_adequate": r.cert_key_adequate,
        "ct_logged": r.ct_logged,
        "chain_valid": r.chain_valid,
        "rbi_compliant": r.rbi_compliant,
        "sebi_compliant": r.sebi_compliant,
        "pci_compliant": r.pci_compliant,
        "npci_compliant": r.npci_compliant,
        "crypto_agility_score": r.crypto_agility_score,
        "compliance_pct": r.compliance_pct,
        "checks": r.checks_json,
        "computed_at": str(r.computed_at),
    }


@router.get("/deadlines")
def get_regulatory_deadlines():
    """Regulatory deadline reference data with countdown timers."""
    data_file = PROJECT_ROOT / "app" / "data" / "regulatory_deadlines.json"
    try:
        with open(data_file) as f:
            deadlines = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Regulatory deadlines data not found")

    today = date.today()
    enriched = []
    for d in deadlines:
        entry = dict(d)
        dl = d.get("deadline")
        if dl:
            try:
                deadline_date = date.fromisoformat(dl)
                days_remaining = (deadline_date - today).days
                entry["days_remaining"] = days_remaining
                if days_remaining < 0:
                    entry["urgency"] = "overdue"
                elif days_remaining <= 90:
                    entry["urgency"] = "critical"
                elif days_remaining <= 365:
                    entry["urgency"] = "warning"
                else:
                    entry["urgency"] = "info"
            except (ValueError, TypeError):
                entry["days_remaining"] = None
                entry["urgency"] = "unknown"
        else:
            entry["days_remaining"] = None
            entry["urgency"] = "ongoing"
        enriched.append(entry)

    return {"deadlines": enriched, "as_of": str(today)}


@router.get("/vendor-readiness")
def get_vendor_readiness():
    """PQC readiness status of key technology vendors (HSMs, CAs, CBS, libraries)."""
    data_file = PROJECT_ROOT / "app" / "data" / "vendor_readiness.json"
    try:
        with open(data_file) as f:
            vendors = json.load(f)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Vendor readiness data not found")

    # Summarize
    ready = sum(1 for v in vendors if v.get("pqc_support_status") == "available")
    in_progress = sum(1 for v in vendors if v.get("pqc_support_status") in ("in_progress", "pilot", "testing"))
    unknown = sum(1 for v in vendors if v.get("pqc_support_status") in ("unknown",))
    critical_blockers = [
        v["vendor"] + " — " + v["product"]
        for v in vendors
        if v.get("risk_if_delayed") == "CRITICAL"
    ]

    return {
        "vendors": vendors,
        "summary": {
            "total": len(vendors),
            "ready": ready,
            "in_progress": in_progress,
            "unknown": unknown,
            "critical_blockers": critical_blockers,
        },
    }
