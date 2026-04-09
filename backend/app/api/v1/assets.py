"""
Assets API Router — paginated asset inventory, search, shadow detection.
"""
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.core.database import get_db
from app.models.asset import Asset, AssetPort
from app.models.certificate import Certificate
from app.models.risk import RiskScore
from app.models.compliance import ComplianceResult

router = APIRouter()


@router.get("/")
def list_assets(
    scan_id: Optional[UUID] = Query(None, description="Filter by scan ID"),
    risk_class: Optional[str] = Query(None, description="Filter by risk classification"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    is_shadow: Optional[bool] = Query(None, description="Filter shadow assets"),
    is_third_party: Optional[bool] = Query(None, description="Filter third-party assets"),
    q: Optional[str] = Query(None, description="Search hostname, IP, or type"),
    sort_by: Optional[str] = Query("hostname", description="Sort field"),
    sort_dir: Optional[str] = Query("asc", description="Sort direction: asc/desc"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    """Paginated, filterable, sortable asset list."""
    query = db.query(Asset)

    if scan_id:
        query = query.filter(Asset.scan_id == scan_id)
    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if is_shadow is not None:
        query = query.filter(Asset.is_shadow == is_shadow)
    if is_third_party is not None:
        query = query.filter(Asset.is_third_party == is_third_party)
    if q:
        search = f"%{q}%"
        query = query.filter(
            or_(
                Asset.hostname.ilike(search),
                Asset.ip_v4.ilike(search),
                Asset.asset_type.ilike(search),
                Asset.hosting_provider.ilike(search),
                Asset.cdn_detected.ilike(search),
            )
        )

    # Join risk for risk_class filter
    if risk_class:
        query = query.join(RiskScore, RiskScore.asset_id == Asset.id).filter(
            RiskScore.risk_classification == risk_class
        )

    # Sorting
    sort_col = getattr(Asset, sort_by, Asset.hostname)
    if sort_dir == "desc":
        query = query.order_by(sort_col.desc())
    else:
        query = query.order_by(sort_col.asc())

    total = query.count()
    assets = query.offset(offset).limit(limit).all()

    items = []
    for a in assets:
        ports = db.query(AssetPort).filter(AssetPort.asset_id == a.id).all()
        risk = db.query(RiskScore).filter(RiskScore.asset_id == a.id).order_by(RiskScore.computed_at.desc()).first()
        items.append({
            "id": str(a.id),
            "scan_id": str(a.scan_id),
            "hostname": a.hostname,
            "url": a.url,
            "ip_v4": a.ip_v4,
            "ip_v6": a.ip_v6,
            "asset_type": a.asset_type,
            "discovery_method": a.discovery_method,
            "is_shadow": a.is_shadow,
            "is_third_party": a.is_third_party,
            "third_party_vendor": a.third_party_vendor,
            "hosting_provider": a.hosting_provider,
            "cdn_detected": a.cdn_detected,
            "waf_detected": a.waf_detected,
            "web_server": a.web_server,
            "tls_version": a.tls_version,
            "confidence_score": a.confidence_score,
            "first_seen_at": str(a.first_seen_at) if a.first_seen_at else None,
            "last_seen_at": str(a.last_seen_at) if a.last_seen_at else None,
            "risk_score": risk.quantum_risk_score if risk else None,
            "risk_classification": risk.risk_classification if risk else None,
            "ports": [{"port": p.port, "protocol": p.protocol, "service_name": p.service_name} for p in ports],
        })

    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/search")
def search_assets(
    q: str = Query(..., min_length=1, description="Search term"),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """Full-text search across hostname, IP, algorithm name, cert fingerprint."""
    search = f"%{q}%"
    assets = db.query(Asset).filter(
        or_(
            Asset.hostname.ilike(search),
            Asset.ip_v4.ilike(search),
            Asset.asset_type.ilike(search),
            Asset.hosting_provider.ilike(search),
        )
    ).limit(limit).all()

    return [
        {
            "id": str(a.id),
            "hostname": a.hostname,
            "ip_v4": a.ip_v4,
            "asset_type": a.asset_type,
            "tls_version": a.tls_version,
        }
        for a in assets
    ]


@router.get("/shadow")
def list_shadow_assets(
    scan_id: Optional[UUID] = Query(None),
    db: Session = Depends(get_db),
):
    """List assets detected as shadow IT (dev/test/staging/legacy subdomains)."""
    query = db.query(Asset).filter(Asset.is_shadow == True)
    if scan_id:
        query = query.filter(Asset.scan_id == scan_id)
    assets = query.all()
    return [
        {
            "id": str(a.id),
            "hostname": a.hostname,
            "ip_v4": a.ip_v4,
            "asset_type": a.asset_type,
            "discovery_method": a.discovery_method,
        }
        for a in assets
    ]


@router.get("/third-party")
def list_third_party_assets(
    scan_id: Optional[UUID] = Query(None),
    db: Session = Depends(get_db),
):
    """List third-party vendor endpoints."""
    query = db.query(Asset).filter(Asset.is_third_party == True)
    if scan_id:
        query = query.filter(Asset.scan_id == scan_id)
    assets = query.all()
    return [
        {
            "id": str(a.id),
            "hostname": a.hostname,
            "third_party_vendor": a.third_party_vendor,
            "tls_version": a.tls_version,
        }
        for a in assets
    ]


@router.get("/{asset_id}")
def get_asset_detail(asset_id: UUID, db: Session = Depends(get_db)):
    """Full asset detail with ports, certificates, risk, and compliance."""
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    ports = db.query(AssetPort).filter(AssetPort.asset_id == asset_id).all()
    certs = db.query(Certificate).filter(Certificate.asset_id == asset_id).all()
    risk = db.query(RiskScore).filter(RiskScore.asset_id == asset_id).order_by(RiskScore.computed_at.desc()).first()
    compliance = db.query(ComplianceResult).filter(ComplianceResult.asset_id == asset_id).order_by(ComplianceResult.computed_at.desc()).first()

    return {
        "id": str(asset.id),
        "scan_id": str(asset.scan_id),
        "hostname": asset.hostname,
        "url": asset.url,
        "ip_v4": asset.ip_v4,
        "ip_v6": asset.ip_v6,
        "asset_type": asset.asset_type,
        "discovery_method": asset.discovery_method,
        "is_shadow": asset.is_shadow,
        "is_third_party": asset.is_third_party,
        "third_party_vendor": asset.third_party_vendor,
        "hosting_provider": asset.hosting_provider,
        "cdn_detected": asset.cdn_detected,
        "waf_detected": asset.waf_detected,
        "web_server": asset.web_server,
        "tls_version": asset.tls_version,
        "auth_mechanisms": asset.auth_mechanisms,
        "jwt_algorithm": asset.jwt_algorithm,
        "confidence_score": asset.confidence_score,
        "first_seen_at": str(asset.first_seen_at) if asset.first_seen_at else None,
        "last_seen_at": str(asset.last_seen_at) if asset.last_seen_at else None,
        "ports": [
            {"port": p.port, "protocol": p.protocol, "service_name": p.service_name, "banner": p.banner}
            for p in ports
        ],
        "certificates": [
            {
                "id": str(c.id),
                "common_name": c.common_name,
                "issuer": c.issuer,
                "ca_name": c.ca_name,
                "key_type": c.key_type,
                "key_length": c.key_length,
                "signature_algorithm": c.signature_algorithm,
                "valid_from": str(c.valid_from) if c.valid_from else None,
                "valid_to": str(c.valid_to) if c.valid_to else None,
                "sha256_fingerprint": c.sha256_fingerprint,
                "is_ct_logged": c.is_ct_logged,
                "nist_quantum_level": c.nist_quantum_level,
                "is_quantum_vulnerable": c.is_quantum_vulnerable,
                "forward_secrecy": c.forward_secrecy,
                "tls_version": c.tls_version,
                "effective_security_expiry": str(c.effective_security_expiry) if c.effective_security_expiry else None,
                "ca_pqc_ready": c.ca_pqc_ready,
                "san_count": c.san_count,
                "is_pinned": c.is_pinned,
                "san_list": c.san_list,
            }
            for c in certs
        ],
        "risk": {
            "quantum_risk_score": risk.quantum_risk_score,
            "risk_classification": risk.risk_classification,
            "mosca_x": risk.mosca_x,
            "mosca_y": risk.mosca_y,
            "hndl_exposed": risk.hndl_exposed,
            "tnfl_risk": risk.tnfl_risk,
            "tnfl_severity": risk.tnfl_severity,
            "factors": [
                {"name": f.factor_name, "score": f.factor_score, "weight": f.factor_weight, "rationale": f.rationale}
                for f in (risk.factors if risk else [])
            ],
        } if risk else None,
        "compliance": {
            "fips_203_deployed": compliance.fips_203_deployed,
            "fips_204_deployed": compliance.fips_204_deployed,
            "fips_205_deployed": compliance.fips_205_deployed,
            "tls_13_enforced": compliance.tls_13_enforced,
            "forward_secrecy": compliance.forward_secrecy,
            "hybrid_mode_active": compliance.hybrid_mode_active,
            "rbi_compliant": compliance.rbi_compliant,
            "sebi_compliant": compliance.sebi_compliant,
            "pci_compliant": compliance.pci_compliant,
            "npci_compliant": compliance.npci_compliant,
            "crypto_agility_score": compliance.crypto_agility_score,
            "compliance_pct": compliance.compliance_pct,
            "checks": compliance.checks_json,
        } if compliance else None,
    }
