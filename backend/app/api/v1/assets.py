"""
Assets API Router — paginated asset inventory, search, shadow detection.
"""
from typing import Optional
from uuid import UUID
from pathlib import Path
from datetime import datetime, timezone
import json
import threading

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, case

from app.core.database import get_db
from app.models.asset import Asset, AssetPort
from app.models.certificate import Certificate
from app.models.risk import RiskScore
from app.models.compliance import ComplianceResult
from app.models.cbom import CBOMRecord, CBOMComponent

router = APIRouter()
_ASSET_TRACE_DIR = Path("backend/data/asset_table_traces")
_ASSET_TRACE_LOCK = threading.Lock()


def _write_asset_table_trace(scan_id: Optional[UUID], endpoint: str, asset_payload: dict) -> None:
    """Append one JSONL trace row for asset-table value lineage."""
    scan_key = str(scan_id) if scan_id else "unscoped"
    trace_path = _ASSET_TRACE_DIR / f"{scan_key}.txt"
    _ASSET_TRACE_DIR.mkdir(parents=True, exist_ok=True)
    with _ASSET_TRACE_LOCK:
        with trace_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(asset_payload, default=str))
            f.write("\n")

def _derive_key_exchange_from_cipher(negotiated_cipher: str | None) -> str | None:
    if not negotiated_cipher:
        return None
    name = negotiated_cipher.upper()
    if "ECDHE" in name:
        return "ECDHE"
    if "DHE" in name:
        return "DHE"
    if name.startswith("TLS_"):
        return "X25519"
    if "RSA" in name:
        return "RSA"
    return negotiated_cipher


def _derive_crypto_transition_state(
    cert_key_type: str | None,
    tls_key_exchange: str | None,
    compliance: ComplianceResult | None,
) -> dict:
    """Expose cert-plane vs KEX-plane posture for frontend clarity."""
    cert_upper = (cert_key_type or "").upper()
    kex_upper = (tls_key_exchange or "").upper()
    classical_markers = ("RSA", "ECDSA", "ECDHE", "DHE", "EC-")
    pqc_markers = ("ML-KEM", "MLKEM", "KYBER", "ML-DSA", "SLH-DSA", "FALCON", "FN-DSA")

    cert_plane = "unknown"
    if cert_upper:
        cert_plane = "pqc" if any(m in cert_upper for m in pqc_markers) else "classical"

    if compliance and compliance.hybrid_mode_active:
        kex_plane = "hybrid_pqc"
    elif kex_upper and any(m in kex_upper for m in ("ML-KEM", "MLKEM", "KYBER")):
        kex_plane = "hybrid_pqc" if any(m in kex_upper for m in ("X25519", "ECDHE", "DHE")) else "pqc"
    elif kex_upper and any(m in kex_upper for m in classical_markers):
        kex_plane = "classical"
    else:
        kex_plane = "unknown"

    if cert_plane == "pqc" and kex_plane in ("pqc", "hybrid_pqc"):
        transition_state = "full_pqc_transition"
    elif cert_plane == "classical" and kex_plane == "hybrid_pqc":
        transition_state = "partial_pqc_transition"
    elif cert_plane == "classical" and kex_plane in ("classical", "unknown"):
        transition_state = "classical_only"
    else:
        transition_state = "unknown"

    return {
        "cert_crypto_plane": cert_plane,
        "kex_crypto_plane": kex_plane,
        "crypto_transition_state": transition_state,
    }


def _resolve_tls_key_exchange(
    db: Session,
    asset_id: UUID,
    cert: Certificate | None,
    compliance: ComplianceResult | None,
) -> str | None:
    """Prefer CBOM key_exchange evidence; fallback to cert-cipher-derived display."""
    cbom_rec = db.query(CBOMRecord).filter(CBOMRecord.asset_id == asset_id).order_by(CBOMRecord.id.desc()).first()
    if cbom_rec:
        kex_comp = db.query(CBOMComponent).filter(
            CBOMComponent.cbom_id == cbom_rec.id,
            CBOMComponent.component_type == "key_exchange",
        ).first()
        if kex_comp and kex_comp.name and kex_comp.name.strip():
            return kex_comp.name

    kex = _derive_key_exchange_from_cipher(cert.negotiated_cipher if cert else None)
    if compliance and (compliance.hybrid_mode_active or compliance.fips_203_deployed):
        return "X25519MLKEM768 (Hybrid)" if compliance.hybrid_mode_active else "ML-KEM Key Exchange"
    return kex


@router.get("")
def list_assets(
    scan_id: Optional[UUID] = Query(None, description="Filter by scan ID"),
    risk_class: Optional[str] = Query(None, description="Filter by risk classification"),
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    is_shadow: Optional[bool] = Query(None, description="Filter shadow assets"),
    is_third_party: Optional[bool] = Query(None, description="Filter third-party assets"),
    q: Optional[str] = Query(None, description="Search hostname, IP, or type"),
    sort_by: Optional[str] = Query("hostname", description="Sort field"),
    sort_dir: Optional[str] = Query("asc", description="Sort direction: asc/desc"),
    limit: int = Query(50, ge=1, le=1000),
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

    # Prioritize assets with non-empty CBOM records first (for CBOM Explorer UX).
    has_populated_cbom = db.query(CBOMRecord.id).filter(
        and_(CBOMRecord.asset_id == Asset.id, CBOMRecord.total_components > 0)
    ).exists()
    query = query.order_by(case((has_populated_cbom, 0), else_=1).asc())

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
        cert = db.query(Certificate).filter(Certificate.asset_id == a.id).first()
        
        cert_expiry_days = None
        if cert and cert.valid_to:
            delta = cert.valid_to - datetime.now(timezone.utc)
            cert_expiry_days = max(0, delta.days)

        compliance = db.query(ComplianceResult).filter(ComplianceResult.asset_id == a.id).order_by(ComplianceResult.computed_at.desc()).first()
        kex = _resolve_tls_key_exchange(db, a.id, cert, compliance)
        posture = _derive_crypto_transition_state(cert.key_type if cert else None, kex, compliance)

        table_trace = {
            "trace_type": "asset_table_columns",
            "endpoint": "list_assets",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "scan_id": str(a.scan_id),
            "asset_id": str(a.id),
            "hostname": a.hostname,
            "fields": {
                "tls_version": {
                    "skipped": True,
                    "reason": "Comes from Asset.tls_version populated by crypto_inspector.save_crypto_results",
                    "source": "assets.tls_version",
                },
                "tls_key_exchange": {
                    "raw": {
                        "compliance_flags": {
                            "hybrid_mode_active": compliance.hybrid_mode_active if compliance else None,
                            "fips_203_deployed": compliance.fips_203_deployed if compliance else None,
                        },
                        "cbom_key_exchange_component": kex if compliance and (compliance.hybrid_mode_active or compliance.fips_203_deployed) else None,
                    },
                    "parsed": kex if compliance and (compliance.hybrid_mode_active or compliance.fips_203_deployed) else None,
                    "source": (
                        "cbom_components.name (component_type=key_exchange) with compliance override"
                        if compliance and (compliance.hybrid_mode_active or compliance.fips_203_deployed)
                        else "SKIPPED: fallback from Certificate.negotiated_cipher comes from crypto_inspector"
                    ),
                    "skipped": False if compliance and (compliance.hybrid_mode_active or compliance.fips_203_deployed) else True,
                },
                "cert_key_type": {
                    "skipped": True,
                    "reason": "Comes from Certificate.key_type populated by crypto_inspector.save_crypto_results",
                    "source": "certificates.key_type",
                },
                "cert_expiry": {
                    "skipped": True,
                    "reason": "Comes from Certificate.valid_to populated by crypto_inspector.save_crypto_results",
                    "source": "certificates.valid_to",
                },
                "fips_203_ml_kem": {
                    "raw": compliance.fips_203_deployed if compliance else None,
                    "parsed": bool(compliance.fips_203_deployed) if compliance else None,
                    "source": "compliance_results.fips_203_deployed",
                },
                "fips_204_ml_dsa": {
                    "raw": compliance.fips_204_deployed if compliance else None,
                    "parsed": bool(compliance.fips_204_deployed) if compliance else None,
                    "source": "compliance_results.fips_204_deployed",
                },
                "fips_205_slh_dsa": {
                    "raw": compliance.fips_205_deployed if compliance else None,
                    "parsed": bool(compliance.fips_205_deployed) if compliance else None,
                    "source": "compliance_results.fips_205_deployed",
                },
                "hybrid_mode": {
                    "raw": compliance.hybrid_mode_active if compliance else None,
                    "parsed": bool(compliance.hybrid_mode_active) if compliance else None,
                    "source": "compliance_results.hybrid_mode_active",
                },
                "classical_deprecation": {
                    "raw": compliance.classical_deprecated if compliance else None,
                    "parsed": bool(compliance.classical_deprecated) if compliance else None,
                    "source": "compliance_results.classical_deprecated",
                },
                "tls_1_3": {
                    "raw": compliance.tls_13_enforced if compliance else None,
                    "parsed": bool(compliance.tls_13_enforced) if compliance else None,
                    "source": "compliance_results.tls_13_enforced",
                },
                "forward_secrecy": {
                    "raw": compliance.forward_secrecy if compliance else None,
                    "parsed": bool(compliance.forward_secrecy) if compliance else None,
                    "source": "compliance_results.forward_secrecy",
                },
            },
        }
        _write_asset_table_trace(a.scan_id, "list_assets", table_trace)

        items.append({
            "id": str(a.id),
            "scan_id": str(a.scan_id),
            "hostname": a.hostname,
            "url": a.url,
            "ip_v4": a.ip_v4,
            "ip_address": a.ip_v4,
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
            "key_exchange": kex,  # backward-compat alias
            "tls_key_exchange": kex,
            "cert_key_type": cert.key_type if cert else None,
            "cert_crypto_plane": posture["cert_crypto_plane"],
            "kex_crypto_plane": posture["kex_crypto_plane"],
            "crypto_transition_state": posture["crypto_transition_state"],
            "cert_expiry": str(cert.valid_to) if cert and cert.valid_to else None,
            "cert_expiry_days": cert_expiry_days,
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

    # Calculate key exchange to display based on cert + compliance
    first_cert = certs[0] if certs else None
    kex = _resolve_tls_key_exchange(db, asset_id, first_cert, compliance)
    posture = _derive_crypto_transition_state(first_cert.key_type if first_cert else None, kex, compliance)

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
        "key_exchange": kex,  # backward-compat alias
        "tls_key_exchange": kex,
        "cert_key_type": first_cert.key_type if first_cert else None,
        "cert_crypto_plane": posture["cert_crypto_plane"],
        "kex_crypto_plane": posture["kex_crypto_plane"],
        "crypto_transition_state": posture["crypto_transition_state"],
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


@router.get("/scan/{scan_id}/type-distribution")
def get_asset_type_distribution(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """Distribution of assets by type for dashboard charts."""
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    
    type_dist = {}
    for a in assets:
        asset_type = a.asset_type or "unknown"
        type_dist[asset_type] = type_dist.get(asset_type, 0) + 1
    
    return {
        "scan_id": str(scan_id),
        "distribution": type_dist,
        "total_assets": len(assets),
    }


@router.get("/scan/{scan_id}/ip-distribution")
def get_ip_version_distribution(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """IP version distribution (IPv4, IPv6, dual-stack) for dashboard charts."""
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    
    ipv4_only = 0
    ipv6_only = 0
    dual_stack = 0
    
    for a in assets:
        has_v4 = bool(a.ip_v4)
        has_v6 = bool(a.ip_v6)
        
        if has_v4 and has_v6:
            dual_stack += 1
        elif has_v4:
            ipv4_only += 1
        elif has_v6:
            ipv6_only += 1
    
    return {
        "scan_id": str(scan_id),
        "ipv4_only": ipv4_only,
        "ipv6_only": ipv6_only,
        "dual_stack": dual_stack,
        "total_assets": len(assets),
    }


@router.get("/dns/scan/{scan_id}/nameservers")
def get_nameserver_records(
    scan_id: UUID,
    db: Session = Depends(get_db),
):
    """Nameserver records for DNS-type assets in the scan."""
    assets = db.query(Asset).filter(
        Asset.scan_id == scan_id,
        Asset.asset_type.in_(["dns_server", "dns", "nameserver"])
    ).all()
    
    nameservers = []
    for a in assets:
        ports = db.query(AssetPort).filter(AssetPort.asset_id == a.id).all()
        ip_addresses = []
        if a.ip_v4:
            ip_addresses.append(a.ip_v4)
        if a.ip_v6:
            ip_addresses.append(a.ip_v6)
        
        nameservers.append({
            "hostname": a.hostname,
            "ns_records": [a.hostname],  # The asset itself is a nameserver
            "ip_addresses": ip_addresses,
        })
    
    return {
        "scan_id": str(scan_id),
        "nameservers": nameservers,
        "total_zones": len(nameservers),
    }
