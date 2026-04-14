"""
CBOM API Router — per-asset CBOM, aggregate, export CycloneDX JSON, algorithm distributions.
"""
import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.asset import Asset
from app.models.certificate import Certificate

router = APIRouter()


@router.get("/scan/{scan_id}")
def list_cboms_for_scan(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """List all CBOMs generated for a scan."""
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
    db: Session = Depends(get_db),
):
    """Get CBOM for a specific asset with all components."""
    record = db.query(CBOMRecord).filter(CBOMRecord.asset_id == asset_id).order_by(
        CBOMRecord.generated_at.desc()
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="No CBOM found for this asset")

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
                "component_type": c.component_type,
                "nist_quantum_level": c.nist_quantum_level,
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
    db: Session = Depends(get_db),
):
    """
    Aggregate CBOM statistics for a scan — algorithm distribution,
    quantum readiness breakdown, component type counts.
    """
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

    return {
        "scan_id": str(scan_id),
        "total_components": total,
        "vulnerable_components": vulnerable_count,
        "quantum_ready_pct": quantum_ready_pct,
        "algorithm_distribution": algo_dist,
        "component_type_distribution": type_dist,
        "nist_level_distribution": nist_dist,
    }


@router.get("/scan/{scan_id}/algorithms")
def get_algorithm_distribution(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """Algorithm frequency distribution with quantum vulnerability status."""
    components = db.query(CBOMComponent).filter(
        CBOMComponent.scan_id == scan_id,
        CBOMComponent.component_type == "algorithm"
    ).all()
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

    # Sort by count descending, but put UNKNOWN entries last
    algos = sorted(
        algo_map.values(),
        key=lambda x: (x["name"] == "UNKNOWN", -x["count"])
    )
    return {"algorithms": algos, "total_unique": len(algos)}


@router.get("/scan/{scan_id}/key-lengths")
def get_key_length_distribution(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """Key length distribution for cryptographic components."""
    components = db.query(CBOMComponent).filter(
        CBOMComponent.scan_id == scan_id,
        CBOMComponent.key_length.isnot(None)
    ).all()
    
    length_dist = {}
    for c in components:
        length = c.key_length
        if length:
            length_dist[length] = length_dist.get(length, 0) + 1
    
    return {
        "scan_id": str(scan_id),
        "key_length_distribution": length_dist,
        "total_components": len(components),
    }


@router.get("/certificates/scan/{scan_id}/authorities")
def get_certificate_authorities(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """Top certificate authorities by usage count with PQC readiness status."""
    certs = db.query(Certificate).filter(
        Certificate.scan_id == scan_id,
        Certificate.ca_name.isnot(None)
    ).all()
    
    ca_map = {}
    for c in certs:
        ca_name = c.ca_name or "Unknown"
        if ca_name not in ca_map:
            ca_map[ca_name] = {
                "name": ca_name,
                "count": 0,
                "pqc_ready": c.ca_pqc_ready or False,
            }
        ca_map[ca_name]["count"] += 1
    
    top_cas = sorted(ca_map.values(), key=lambda x: x["count"], reverse=True)
    
    return {
        "scan_id": str(scan_id),
        "top_cas": top_cas[:20],
        "total_certificates": len(certs),
    }


@router.get("/certificates/scan/{scan_id}/expiry-timeline")
def get_certificate_expiry_timeline(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """Certificate expiry timeline for dashboard charts — next 12 months."""
    certs = db.query(Certificate).filter(
        Certificate.scan_id == scan_id,
        Certificate.valid_to.isnot(None)
    ).all()
    
    now = datetime.now(timezone.utc)
    
    # Build 12-month timeline
    timeline = []
    expiring_30_days = 0
    expiring_90_days = 0
    
    for i in range(12):
        month_start = now + timedelta(days=30*i)
        month_end = now + timedelta(days=30*(i+1))
        
        month_certs = [c for c in certs if c.valid_to and month_start <= c.valid_to < month_end]
        critical = [c for c in month_certs if c.valid_to and (c.valid_to - now).days < 30]
        warning = [c for c in month_certs if c.valid_to and 30 <= (c.valid_to - now).days < 90]
        
        timeline.append({
            "month": month_start.strftime("%b %Y"),
            "count": len(month_certs),
            "critical": len(critical),
            "warning": len(warning),
        })
    
    # Count critical and warning certs
    for c in certs:
        if c.valid_to:
            days = (c.valid_to - now).days
            if 0 <= days < 30:
                expiring_30_days += 1
            if 0 <= days < 90:
                expiring_90_days += 1
    
    return {
        "scan_id": str(scan_id),
        "timeline": timeline,
        "total_certificates": len(certs),
        "expiring_30_days": expiring_30_days,
        "expiring_90_days": expiring_90_days,
    }
