"""
CBOM API Router — per-asset CBOM, aggregate, export CycloneDX JSON, algorithm distributions.
"""
import json
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.asset import Asset
from app.models.auth import User
from app.models.scan import ScanJob
from app.api.v1.auth import get_optional_user

router = APIRouter()

def get_superadmin_id(db: Session) -> UUID:
    sa_email = "superadmin@qushield.local"
    sa = db.query(User).filter(User.email == sa_email).first()
    return sa.id if sa else None

def check_scan_access(db: Session, scan_id: UUID, user: Optional[User]) -> bool:
    scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan: return False
    sa_id = get_superadmin_id(db)
    return (scan.user_id == sa_id) or (user and scan.user_id == user.id) or (user and user.id == sa_id)


@router.get("/scan/{scan_id}")
def list_cboms_for_scan(
    scan_id: UUID,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all CBOMs generated for a scan."""
    if not check_scan_access(db, scan_id, user):
        raise HTTPException(status_code=404, detail="Scan not found")
    records = db.query(CBOMRecord).filter(CBOMRecord.scan_id == scan_id).all()
    items = []
    for r in records:
        asset = db.query(Asset).filter(Asset.id == r.asset_id).first()
        items.append({
            "id": str(r.id),
            "asset_id": str(r.asset_id),
            "hostname": asset.hostname if asset else None,
            "spec_version": r.spec_version,
            "total_components": r.total_components,
            "vulnerable_components": r.vulnerable_components,
            "quantum_ready_pct": r.quantum_ready_pct,
            "file_path": r.file_path,
            "generated_at": str(r.generated_at),
        })
    return {"items": items, "total": len(items)}


@router.get("/asset/{asset_id}")
def get_cbom_for_asset(
    asset_id: UUID,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get CBOM for a specific asset with all components."""
    record = db.query(CBOMRecord).filter(CBOMRecord.asset_id == asset_id).order_by(
        CBOMRecord.generated_at.desc()
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="No CBOM found for this asset")

    if not check_scan_access(db, record.scan_id, user):
        raise HTTPException(status_code=404, detail="Access denied")

    components = db.query(CBOMComponent).filter(CBOMComponent.cbom_id == record.id).all()
    return {
        "id": str(record.id),
        "asset_id": str(record.asset_id),
        "scan_id": str(record.scan_id),
        "spec_version": record.spec_version,
        "total_components": record.total_components,
        "vulnerable_components": record.vulnerable_components,
        "quantum_ready_pct": record.quantum_ready_pct,
        "generated_at": str(record.generated_at),
        "components": [
            {
                "id": str(c.id),
                "name": c.name,
                "algorithm_name": c.name,  # Frontend expects algorithm_name
                "component_type": c.component_type,
                "nist_quantum_level": c.nist_quantum_level,
                "quantum_vulnerable": c.is_quantum_vulnerable,  # Frontend expects quantum_vulnerable
                "is_quantum_vulnerable": c.is_quantum_vulnerable,
                "key_type": c.key_type,
                "key_length": c.key_length,
                "tls_version": c.tls_version,
                "bom_ref": c.bom_ref,
            }
            for c in components
        ],
    }


@router.get("/asset/{asset_id}/export")
def export_cbom_cyclonedx(
    asset_id: UUID,
    db: Session = Depends(get_db),
):
    """Export raw CycloneDX JSON file for an asset."""
    record = db.query(CBOMRecord).filter(CBOMRecord.asset_id == asset_id).order_by(
        CBOMRecord.generated_at.desc()
    ).first()
    if not record or not record.file_path:
        raise HTTPException(status_code=404, detail="No CBOM file found for this asset")

    try:
        with open(record.file_path, "r") as f:
            content = f.read()
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{asset_id}.cdx.json"'},
        )
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="CBOM file not found on disk")


@router.get("/scan/{scan_id}/aggregate")
def get_aggregate_cbom(
    scan_id: UUID,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """
    Aggregate CBOM statistics for a scan — algorithm distribution,
    quantum readiness breakdown, component type counts.
    """
    if not check_scan_access(db, scan_id, user):
        raise HTTPException(status_code=404, detail="Scan not found")
    components = db.query(CBOMComponent).filter(CBOMComponent.scan_id == scan_id).all()
    if not components:
        raise HTTPException(status_code=404, detail="No CBOM components found for this scan")

    # Algorithm distribution
    algo_dist = {}
    type_dist = {}
    nist_dist = {}
    vulnerable_count = 0
    total = len(components)

    for c in components:
        # Algorithm name distribution
        name = c.name or "unknown"
        algo_dist[name] = algo_dist.get(name, 0) + 1

        # Component type distribution
        ctype = c.component_type or "unknown"
        type_dist[ctype] = type_dist.get(ctype, 0) + 1

        # NIST level distribution
        level = c.nist_quantum_level
        level_key = f"L{level}" if level >= 0 else "L-1(unknown)"
        nist_dist[level_key] = nist_dist.get(level_key, 0) + 1

        if c.is_quantum_vulnerable:
            vulnerable_count += 1

    quantum_ready_pct = round((1 - vulnerable_count / max(total, 1)) * 100, 1)

    # Count unique assets that have CBOMs
    unique_assets = len(set(c.cbom_id for c in components))
    unique_algos = len(set(c.name for c in components if c.name))

    return {
        "scan_id": str(scan_id),
        "total_assets": unique_assets,
        "total_components": total,
        "unique_algorithms": unique_algos,
        "vulnerable_components": vulnerable_count,
        "quantum_ready_pct": quantum_ready_pct,
        # Frontend expects these field names:
        "by_algorithm": algo_dist,
        "by_type": type_dist,
        "by_nist_level": nist_dist,
        # Also keep original names for backward compat:
        "algorithm_distribution": algo_dist,
        "component_type_distribution": type_dist,
        "nist_level_distribution": nist_dist,
    }


@router.get("/scan/{scan_id}/algorithms")
def get_algorithm_distribution(
    scan_id: UUID,
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Algorithm frequency distribution with quantum vulnerability status."""
    if not check_scan_access(db, scan_id, user):
        raise HTTPException(status_code=404, detail="Scan not found")
    components = db.query(CBOMComponent).filter(CBOMComponent.scan_id == scan_id).all()
    algo_map = {}
    for c in components:
        name = c.name or "unknown"
        if name not in algo_map:
            algo_map[name] = {
                "name": name,
                "count": 0,
                "nist_quantum_level": c.nist_quantum_level,
                "is_quantum_vulnerable": c.is_quantum_vulnerable,
                "component_type": c.component_type,
            }
        algo_map[name]["count"] += 1

    algos = sorted(algo_map.values(), key=lambda x: x["count"], reverse=True)
    return {"algorithms": algos, "total_unique": len(algos)}
