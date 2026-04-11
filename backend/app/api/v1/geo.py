"""
GeoIP API Router — IP geolocation endpoints for scan assets.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.models.asset import Asset
from app.models.geo import GeoLocation
from app.models.risk import RiskScore
from app.services.geo_service import geolocate_batch
from app.api.v1.auth import get_optional_user
from app.models.auth import User
from app.models.scan import ScanJob

logger = get_logger("api.geo")
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
def get_geo_locations(scan_id: UUID, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """
    Get all IP geolocations for a scan.
    If geo data doesn't exist yet, resolves and geolocates all assets on-the-fly.
    Returns GeoJSON-compatible FeatureCollection.
    """
    if not check_scan_access(db, scan_id, user):
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Check for existing geo data
    existing = db.query(GeoLocation).filter(GeoLocation.scan_id == scan_id).all()

    if not existing:
        # Resolve on-the-fly from assets
        assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
        if not assets:
            raise HTTPException(status_code=404, detail="No assets for this scan")

        asset_dicts = [
            {"hostname": a.hostname, "ip": a.ip_v4, "asset_id": str(a.id)}
            for a in assets
        ]
        geo_results = geolocate_batch(asset_dicts, max_workers=5)

        # Persist to DB
        for g in geo_results:
            loc = GeoLocation(
                scan_id=scan_id,
                asset_id=g.get("asset_id"),
                hostname=g.get("hostname"),
                ip=g["ip"],
                latitude=g.get("latitude"),
                longitude=g.get("longitude"),
                city=g.get("city"),
                state=g.get("state"),
                country=g.get("country"),
                country_code=g.get("country_code"),
                org=g.get("org"),
                isp=g.get("isp"),
                as_number=str(g.get("as_number", "")) if g.get("as_number") else None,
                source=g.get("source"),
            )
            db.add(loc)
        db.commit()
        existing = db.query(GeoLocation).filter(GeoLocation.scan_id == scan_id).all()

    # Build GeoJSON FeatureCollection
    features = []
    for loc in existing:
        if loc.latitude is not None and loc.longitude is not None:
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [loc.longitude, loc.latitude],
                },
                "properties": {
                    "ip": loc.ip,
                    "hostname": loc.hostname,
                    "city": loc.city,
                    "state": loc.state,
                    "country": loc.country,
                    "country_code": loc.country_code,
                    "org": loc.org,
                    "isp": loc.isp,
                    "as_number": loc.as_number,
                    "asset_id": str(loc.asset_id) if loc.asset_id else None,
                    "source": loc.source,
                },
            })

    return {
        "type": "FeatureCollection",
        "scan_id": str(scan_id),
        "total_locations": len(features),
        "features": features,
    }

@router.get("/scan/{scan_id}/map-data")
def get_map_data(scan_id: UUID, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """
    Get map-ready data: IP, hostname, lat/lon, risk status, asset type.
    Joins geo data with asset and risk data for frontend map visualization.
    """
    if not check_scan_access(db, scan_id, user):
        raise HTTPException(status_code=404, detail="Scan not found")
        
    geo_locs = db.query(GeoLocation).filter(GeoLocation.scan_id == scan_id).all()
    if not geo_locs:
        raise HTTPException(status_code=404, detail="No geo data for this scan. Call GET /geo/scan/{id} first.")

    risks = {str(r.asset_id): r for r in db.query(RiskScore).filter(RiskScore.scan_id == scan_id).all()}
    assets = {str(a.id): a for a in db.query(Asset).filter(Asset.scan_id == scan_id).all()}

    markers = []
    for loc in geo_locs:
        if loc.latitude is None or loc.longitude is None:
            continue

        asset_id = str(loc.asset_id) if loc.asset_id else None
        risk = risks.get(asset_id)
        asset = assets.get(asset_id)

        markers.append({
            "ip": loc.ip,
            "hostname": loc.hostname,
            "lat": loc.latitude,
            "lon": loc.longitude,
            "city": loc.city,
            "country": loc.country,
            "country_code": loc.country_code,
            "org": loc.org,
            "asset_type": asset.asset_type if asset else "unknown",
            "risk_score": risk.quantum_risk_score if risk else None,
            "risk_classification": risk.risk_classification if risk else None,
            "hndl_exposed": risk.hndl_exposed if risk else None,
        })

    # Group by country for summary
    country_summary = {}
    for m in markers:
        cc = m["country_code"] or "??"
        if cc not in country_summary:
            country_summary[cc] = {"country": m["country"], "count": 0, "vulnerable": 0}
        country_summary[cc]["count"] += 1
        if m.get("risk_classification") in ("quantum_vulnerable", "quantum_critical"):
            country_summary[cc]["vulnerable"] += 1

    return {
        "scan_id": str(scan_id),
        "total_markers": len(markers),
        "markers": markers,
        "country_summary": country_summary,
    }
