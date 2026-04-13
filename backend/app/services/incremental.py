"""
Incremental Scanning — Delta detection and data cloning for unchanged assets.

Computes a fingerprint_hash = sha256(ip + tls_version + negotiated_cipher + cert_fingerprint)
for each asset after crypto inspection. On subsequent scans, compares fingerprints with the
most recent prior scan for the same hostname. If unchanged, clones previous crypto/CBOM/risk/
compliance data instead of re-scanning.
"""
import hashlib
from typing import Optional
from uuid import UUID

from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.logging import get_logger
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.risk import RiskScore
from app.models.compliance import ComplianceResult

logger = get_logger("incremental")


def compute_fingerprint(
    ip: str,
    tls_version: str,
    negotiated_cipher: str,
    cert_fingerprint: str,
    key_exchange: str = "",
    has_pqc: bool = False,
) -> str:
    """
    Compute a sha256 fingerprint hash from TLS and cert data.
    Used to detect whether an asset's crypto posture has changed.
    """
    raw = (
        f"{ip or ''}|{tls_version or ''}|{negotiated_cipher or ''}|"
        f"{cert_fingerprint or ''}|{key_exchange or ''}|{int(bool(has_pqc))}"
    )
    return hashlib.sha256(raw.encode()).hexdigest()


def compute_asset_fingerprint(asset: Asset, crypto_fingerprint: dict) -> str:
    """Compute fingerprint from an Asset model + its crypto inspection result."""
    tls = crypto_fingerprint.get("tls", {})
    certs = crypto_fingerprint.get("certificates", [])
    cert_fp = certs[0].get("sha256_fingerprint", "") if certs else ""
    key_exchange = tls.get("key_exchange", "") or ""
    has_pqc = (crypto_fingerprint.get("quantum_summary") or {}).get("has_pqc", False)

    return compute_fingerprint(
        ip=asset.ip_v4 or asset.ip_v6 or "",
        tls_version=tls.get("negotiated_protocol", ""),
        negotiated_cipher=tls.get("negotiated_cipher", ""),
        cert_fingerprint=cert_fp,
        key_exchange=key_exchange,
        has_pqc=has_pqc,
    )


def find_previous_asset(
    hostname: str,
    current_scan_id: UUID,
    db: Session,
) -> Optional[Asset]:
    """
    Find the most recent prior asset with the same hostname from a different scan.
    Returns None if no prior scan exists.
    """
    return (
        db.query(Asset)
        .filter(
            Asset.hostname == hostname,
            Asset.scan_id != current_scan_id,
            Asset.fingerprint_hash.isnot(None),
        )
        .order_by(desc(Asset.last_seen_at))
        .first()
    )


def is_unchanged(
    new_fingerprint: str,
    previous_asset: Asset,
) -> bool:
    """Check if the asset's crypto posture has changed since last scan."""
    if not previous_asset or not previous_asset.fingerprint_hash:
        return False
    return new_fingerprint == previous_asset.fingerprint_hash


def clone_scan_data(
    source_asset_id: UUID,
    target_scan_id: UUID,
    target_asset_id: UUID,
    db: Session,
) -> dict:
    """
    Clone crypto/CBOM/risk/compliance data from a previous asset to a new scan's asset.

    Returns dict with counts of cloned records.
    """
    cloned = {"certificates": 0, "cbom_records": 0, "cbom_components": 0,
              "risk_scores": 0, "compliance_results": 0}

    # Clone certificates
    source_certs = db.query(Certificate).filter(Certificate.asset_id == source_asset_id).all()
    for cert in source_certs:
        new_cert = Certificate(
            scan_id=target_scan_id,
            asset_id=target_asset_id,
            common_name=cert.common_name,
            issuer=cert.issuer,
            ca_name=cert.ca_name,
            valid_from=cert.valid_from,
            valid_to=cert.valid_to,
            key_type=cert.key_type,
            key_length=cert.key_length,
            signature_algorithm=cert.signature_algorithm,
            signature_algorithm_oid=cert.signature_algorithm_oid,
            sha256_fingerprint=cert.sha256_fingerprint,
            san_list=cert.san_list,
            chain_depth=cert.chain_depth,
            chain_valid=cert.chain_valid,
            nist_quantum_level=cert.nist_quantum_level,
            is_quantum_vulnerable=cert.is_quantum_vulnerable,
            is_ct_logged=cert.is_ct_logged,
        )
        db.add(new_cert)
        cloned["certificates"] += 1

    # Clone CBOM records and components
    source_cbom = db.query(CBOMRecord).filter(CBOMRecord.asset_id == source_asset_id).first()
    if source_cbom:
        new_cbom = CBOMRecord(
            scan_id=target_scan_id,
            asset_id=target_asset_id,
            spec_version=source_cbom.spec_version,
            file_path=source_cbom.file_path,
            total_components=source_cbom.total_components,
            vulnerable_components=source_cbom.vulnerable_components,
            quantum_ready_pct=source_cbom.quantum_ready_pct,
        )
        db.add(new_cbom)
        db.flush()
        cloned["cbom_records"] += 1

        source_components = db.query(CBOMComponent).filter(
            CBOMComponent.cbom_id == source_cbom.id
        ).all()
        for comp in source_components:
            new_comp = CBOMComponent(
                cbom_id=new_cbom.id,
                scan_id=target_scan_id,
                name=comp.name,
                component_type=comp.component_type,
                nist_quantum_level=comp.nist_quantum_level,
                is_quantum_vulnerable=comp.is_quantum_vulnerable,
                key_type=comp.key_type,
                key_length=comp.key_length,
                tls_version=comp.tls_version,
                bom_ref=comp.bom_ref,
            )
            db.add(new_comp)
            cloned["cbom_components"] += 1

    # Clone risk scores
    source_risk = db.query(RiskScore).filter(
        RiskScore.asset_id == source_asset_id
    ).order_by(desc(RiskScore.computed_at)).first()
    if source_risk:
        new_risk = RiskScore(
            scan_id=target_scan_id,
            asset_id=target_asset_id,
            quantum_risk_score=source_risk.quantum_risk_score,
            risk_classification=source_risk.risk_classification,
            mosca_x=source_risk.mosca_x,
            mosca_y=source_risk.mosca_y,
            mosca_z_pessimistic=source_risk.mosca_z_pessimistic,
            mosca_z_median=source_risk.mosca_z_median,
            mosca_z_optimistic=source_risk.mosca_z_optimistic,
            hndl_exposed=source_risk.hndl_exposed,
            tnfl_risk=source_risk.tnfl_risk,
            tnfl_severity=source_risk.tnfl_severity,
        )
        db.add(new_risk)
        cloned["risk_scores"] += 1

    # Clone compliance results
    source_compliance = db.query(ComplianceResult).filter(
        ComplianceResult.asset_id == source_asset_id
    ).first()
    if source_compliance:
        new_comp_result = ComplianceResult(
            scan_id=target_scan_id,
            asset_id=target_asset_id,
            fips_203_deployed=source_compliance.fips_203_deployed,
            fips_204_deployed=source_compliance.fips_204_deployed,
            fips_205_deployed=source_compliance.fips_205_deployed,
            tls_13_enforced=source_compliance.tls_13_enforced,
            forward_secrecy=source_compliance.forward_secrecy,
            hybrid_mode_active=source_compliance.hybrid_mode_active,
            classical_deprecated=source_compliance.classical_deprecated,
            cert_key_adequate=source_compliance.cert_key_adequate,
            ct_logged=source_compliance.ct_logged,
            chain_valid=source_compliance.chain_valid,
            rbi_compliant=source_compliance.rbi_compliant,
            sebi_compliant=source_compliance.sebi_compliant,
            pci_compliant=source_compliance.pci_compliant,
            npci_compliant=source_compliance.npci_compliant,
            crypto_agility_score=source_compliance.crypto_agility_score,
            compliance_pct=source_compliance.compliance_pct,
            checks_json=source_compliance.checks_json,
        )
        db.add(new_comp_result)
        cloned["compliance_results"] += 1

    db.commit()

    logger.info(
        f"Cloned scan data for asset {source_asset_id} → {target_asset_id}",
        extra=cloned,
    )
    return cloned
