"""
Compliance Service — FIPS checks, India-specific regulatory compliance, crypto-agility scoring.

Evaluates assets against FIPS 203/204/205, TLS requirements, RBI IT Framework,
SEBI CSCRF, PCI DSS 4.0, NPCI UPI, and computes a crypto-agility score (0-100).
"""
import json
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.compliance import ComplianceResult
from app.models.certificate import Certificate
from app.models.cbom import CBOMRecord, CBOMComponent

logger = logging.getLogger(__name__)

_PQC_OID_PATH = Path(__file__).resolve().parent.parent / "data" / "pqc_oids.json"
with open(_PQC_OID_PATH, encoding="utf-8") as _f:
    PQC_OIDS_FOR_COMPLIANCE: dict = json.load(_f)


def evaluate_compliance(asset_id: str, cbom_data: dict, crypto_data: dict) -> dict:
    """
    Evaluates cryptographic posture against all compliance benchmarks.

    Args:
        asset_id: UUID string of the asset
        cbom_data: Dict with 'components' list from CBOM builder
        crypto_data: Dict with TLS/cert info from crypto inspector
    """
    checks = []
    passed = 0
    failed = 0

    # --- Extract TLS info from crypto_data ---
    tls_data = crypto_data.get("tls", {}) or {}
    negotiated_protocol = tls_data.get("negotiated_protocol", "") or ""
    negotiated_cipher = tls_data.get("negotiated_cipher", "") or ""
    fs = tls_data.get("forward_secrecy", False)
    key_exchange = tls_data.get("key_exchange", "") or ""

    cert_data = crypto_data.get("certificate", {}) or {}
    key_type = cert_data.get("key_type", "") or ""
    key_length = cert_data.get("key_length", 0) or 0
    ct_logged = cert_data.get("ct_logged", False)
    chain_valid = cert_data.get("chain_valid", False)
    signature_algo = cert_data.get("signature_algorithm", "") or ""
    signature_oid = (cert_data.get("signature_algorithm_oid") or "").strip()
    pqc_tls = crypto_data.get("pqc_tls") or {}

    # --- CBOM component scanning ---
    has_mlkem = False
    has_mldsa = False
    has_slhdsa = False
    has_hybrid = False
    has_classical_only = True  # assume true until PQC found

    components = []
    if cbom_data and "components" in cbom_data:
        components = cbom_data["components"]
    for comp in components:
        name = (comp.get("name", "") or "").upper()
        if "ML-KEM" in name:
            has_mlkem = True
            has_classical_only = False
        if "ML-DSA" in name:
            has_mldsa = True
            has_classical_only = False
        if "SLH-DSA" in name or "SPHINCS+" in name:
            has_slhdsa = True
            has_classical_only = False
        if "X25519MLKEM" in name or "X25519+ML-KEM" in name.replace(" ", ""):
            has_hybrid = True
    # Also check negotiated cipher for hybrid
    if "X25519MLKEM" in negotiated_cipher.upper() or "ML-KEM" in key_exchange.upper():
        has_hybrid = True
        has_mlkem = True
        has_classical_only = False

    # PQCscan TLS results (IANA hybrid groups include ML-KEM — FIPS 203 / hybrid columns)
    if pqc_tls.get("hybrid_algorithms"):
        has_hybrid = True
        has_mlkem = True
        has_classical_only = False
    for a in pqc_tls.get("pure_pqc_algorithms") or []:
        au = (a or "").upper()
        if "ML-KEM" in au or "MLKEM" in au or "KYBER" in au:
            has_mlkem = True
            has_classical_only = False

    # Leaf certificate signature OID → FIPS 204 / 205 (CBOM names are usually hostnames)
    if signature_oid:
        for algo_name, info in PQC_OIDS_FOR_COMPLIANCE.items():
            if info.get("oid") != signature_oid:
                continue
            an = algo_name.upper()
            if "ML-DSA" in an:
                has_mldsa = True
                has_classical_only = False
            if "SLH-DSA" in an or "SPHINCS" in an:
                has_slhdsa = True
                has_classical_only = False
            break

    sigu = (signature_algo or "").upper()
    if "ML-DSA" in sigu or "MLDSA" in sigu or "DILITHIUM" in sigu:
        has_mldsa = True
        has_classical_only = False
    if "SLH-DSA" in sigu or "SLHDSA" in sigu or "SPHINCS" in sigu:
        has_slhdsa = True
        has_classical_only = False

    # ─── 1. FIPS 203 (ML-KEM) ───
    if has_mlkem:
        checks.append({"rule": "FIPS 203 (ML-KEM)", "status": "PASS", "msg": "ML-KEM detected in key exchange."})
        passed += 1
    else:
        checks.append({"rule": "FIPS 203 (ML-KEM)", "status": "FAIL", "msg": "No ML-KEM found. Non-compliant with FIPS 203."})
        failed += 1

    # ─── 2. FIPS 204 (ML-DSA) ───
    if has_mldsa:
        checks.append({"rule": "FIPS 204 (ML-DSA)", "status": "PASS", "msg": "ML-DSA detected in signatures."})
        passed += 1
    else:
        checks.append({"rule": "FIPS 204 (ML-DSA)", "status": "FAIL", "msg": "No ML-DSA signature detected. Non-compliant with FIPS 204."})
        failed += 1

    # ─── 3. FIPS 205 (SLH-DSA) ───
    if has_slhdsa:
        checks.append({"rule": "FIPS 205 (SLH-DSA)", "status": "PASS", "msg": "SLH-DSA detected as fallback."})
        passed += 1
    else:
        checks.append({"rule": "FIPS 205 (SLH-DSA)", "status": "FAIL", "msg": "No SLH-DSA detected. Non-compliant with FIPS 205."})
        failed += 1

    # ─── 4. TLS 1.3 Enforced ───
    tls_enforced = "1.3" in negotiated_protocol or "TLSv1.3" in negotiated_protocol
    if tls_enforced:
        checks.append({"rule": "TLS 1.3 Enforcement", "status": "PASS", "msg": "TLS 1.3 actively negotiated."})
        passed += 1
    else:
        checks.append({"rule": "TLS 1.3 Enforcement", "status": "FAIL", "msg": f"Negotiated {negotiated_protocol or 'unknown'}. TLS 1.3 not enforced."})
        failed += 1

    # ─── 5. Forward Secrecy ───
    if fs:
        checks.append({"rule": "Forward Secrecy", "status": "PASS", "msg": "Perfect forward secrecy enabled."})
        passed += 1
    else:
        checks.append({"rule": "Forward Secrecy", "status": "FAIL", "msg": "Key exchange lacks forward secrecy."})
        failed += 1

    # ─── 6. Hybrid Mode Active ───
    if has_hybrid:
        checks.append({"rule": "Hybrid KEM Active", "status": "PASS", "msg": "Classical + PQC hybrid key exchange detected."})
        passed += 1
    else:
        checks.append({"rule": "Hybrid KEM Active", "status": "FAIL", "msg": "No hybrid key exchange detected."})
        failed += 1

    # ─── 7. Classical Deprecated ───
    classical_deprecated = not has_classical_only and has_mlkem and has_mldsa
    if classical_deprecated:
        checks.append({"rule": "Classical Deprecated", "status": "PASS", "msg": "RSA/ECDHE/ECDSA deprecated; PQC in use."})
        passed += 1
    else:
        checks.append({"rule": "Classical Deprecated", "status": "FAIL", "msg": "Classical algorithms still active."})
        failed += 1

    # ─── 8. Certificate Key Adequate (>= 2048 bits) ───
    key_adequate = key_length >= 2048
    if key_adequate:
        checks.append({"rule": "Certificate Key Adequate", "status": "PASS", "msg": f"{key_type}-{key_length} meets minimum key length."})
        passed += 1
    else:
        checks.append({"rule": "Certificate Key Adequate", "status": "FAIL", "msg": f"{key_type}-{key_length} below 2048-bit minimum."})
        failed += 1

    # ─── 9. CT Logged ───
    if ct_logged:
        checks.append({"rule": "Certificate Transparency", "status": "PASS", "msg": "Certificate is CT logged."})
        passed += 1
    else:
        checks.append({"rule": "Certificate Transparency", "status": "FAIL", "msg": "Certificate not CT logged."})
        failed += 1

    # ─── 10. Chain Valid ───
    if chain_valid:
        checks.append({"rule": "Certificate Chain Valid", "status": "PASS", "msg": "Full certificate chain verified."})
        passed += 1
    else:
        checks.append({"rule": "Certificate Chain Valid", "status": "FAIL", "msg": "Certificate chain validation failed or incomplete."})
        failed += 1

    # ─── India-Specific Regulatory Checks ───

    # 11. RBI IT Framework — crypto controls documented (requires TLS 1.2+, key >= 2048)
    rbi_compliant = (key_adequate and ("1.2" in negotiated_protocol or "1.3" in negotiated_protocol or tls_enforced) and fs)
    if rbi_compliant:
        checks.append({"rule": "RBI IT Framework", "status": "PASS", "msg": "Crypto controls meet RBI IT Framework requirements."})
        passed += 1
    else:
        checks.append({"rule": "RBI IT Framework", "status": "FAIL", "msg": "Does not meet RBI IT Framework crypto controls."})
        failed += 1

    # 12. SEBI CSCRF — supply chain crypto inventory (CBOM exists)
    sebi_compliant = len(components) > 0
    if sebi_compliant:
        checks.append({"rule": "SEBI CSCRF", "status": "PASS", "msg": "Cryptographic inventory (CBOM) generated for SEBI CSCRF."})
        passed += 1
    else:
        checks.append({"rule": "SEBI CSCRF", "status": "FAIL", "msg": "No CBOM inventory. Non-compliant with SEBI CSCRF."})
        failed += 1

    # 13. PCI DSS 4.0 — TLS 1.2+ minimum
    pci_compliant = "1.2" in negotiated_protocol or "1.3" in negotiated_protocol or tls_enforced
    if pci_compliant:
        checks.append({"rule": "PCI DSS 4.0", "status": "PASS", "msg": "TLS 1.2+ enforced per PCI DSS 4.0."})
        passed += 1
    else:
        checks.append({"rule": "PCI DSS 4.0", "status": "FAIL", "msg": "TLS version below 1.2. Non-compliant with PCI DSS 4.0."})
        failed += 1

    # 14. NPCI UPI — mTLS required for UPI endpoints
    # If asset is UPI, check for mTLS indicators
    auth_mechs = crypto_data.get("auth_mechanisms", []) or []
    is_upi = crypto_data.get("asset_type", "").lower() in ("upi_gateway", "upi")
    npci_compliant = True  # default pass for non-UPI assets
    if is_upi:
        npci_compliant = "mTLS" in str(auth_mechs) or "mtls" in str(auth_mechs).lower()
    if npci_compliant:
        checks.append({"rule": "NPCI UPI mTLS", "status": "PASS", "msg": "mTLS requirement satisfied (or N/A for non-UPI)."})
        passed += 1
    else:
        checks.append({"rule": "NPCI UPI mTLS", "status": "FAIL", "msg": "UPI endpoint without mTLS. Non-compliant with NPCI guidelines."})
        failed += 1

    pct = round((passed / (passed + failed)) * 100, 2) if (passed + failed) > 0 else 0.0

    return {
        "asset_id": asset_id,
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "compliance_pct": pct,
        "fips_203_deployed": has_mlkem,
        "fips_204_deployed": has_mldsa,
        "fips_205_deployed": has_slhdsa,
        "tls_13_enforced": tls_enforced,
        "forward_secrecy": fs,
        "hybrid_mode_active": has_hybrid,
        "classical_deprecated": classical_deprecated,
        "cert_key_adequate": key_adequate,
        "ct_logged": ct_logged,
        "chain_valid": chain_valid,
        "rbi_compliant": rbi_compliant,
        "sebi_compliant": sebi_compliant,
        "pci_compliant": pci_compliant,
        "npci_compliant": npci_compliant,
    }


def compute_agility_score(asset_data: dict, cert_history: list = None) -> dict:
    """
    Computes crypto-agility score (0-100) based on five factors from 05-ALGORITHM_RESEARCH.md §5.1.

    Factors (20 points each):
    1. Dynamic cipher negotiation
    2. Automated cert renewal (ACME/Let's Encrypt detection)
    3. Automated key rotation
    4. Cryptographic abstraction layer
    5. Documented owner + SLA
    """
    factors = []
    score = 0

    # 1. Dynamic cipher negotiation — check if server supports TLS 1.3 (implying dynamic)
    tls_version = asset_data.get("tls_version", "") or ""
    cipher_negotiation = 20 if "1.3" in tls_version else 10 if "1.2" in tls_version else 0
    factors.append({"factor": "Dynamic Cipher Negotiation", "points": cipher_negotiation, "passed": cipher_negotiation >= 10})
    score += cipher_negotiation

    # 2. Automated cert renewal (Detect Let's Encrypt / short expiry pattern)
    issuer = asset_data.get("cert_issuer", "") or ""
    renewal_pts = 0
    if "let's encrypt" in issuer.lower() or "acme" in issuer.lower():
        renewal_pts = 20
    elif asset_data.get("cert_days_remaining") and asset_data["cert_days_remaining"] < 90:
        renewal_pts = 15  # Short cert lifetime suggests automation
    factors.append({"factor": "Automated Cert Renewal", "points": renewal_pts, "passed": renewal_pts > 0})
    score += renewal_pts

    # 3. Key rotation frequency — compare cert_valid_from to current date
    rotation_pts = 10  # Default: can't determine without historical data
    if cert_history and len(cert_history) >= 2:
        rotation_pts = 20  # Multiple cert versions suggest rotation
    factors.append({"factor": "Key Rotation Frequency", "points": rotation_pts, "passed": rotation_pts >= 10})
    score += rotation_pts

    # 4. Cryptographic abstraction layer (HSM detection, crypto library diversity)
    abstraction_pts = 10  # Default baseline
    if asset_data.get("cdn_detected") or asset_data.get("waf_detected"):
        abstraction_pts = 15  # CDN/WAF implies abstraction layer
    factors.append({"factor": "Crypto Abstraction Layer", "points": abstraction_pts, "passed": abstraction_pts >= 10})
    score += abstraction_pts

    # 5. Documented ownership (manual input — default 10/20 for POC)
    owner_pts = 10
    factors.append({"factor": "Documented Ownership", "points": owner_pts, "passed": True})
    score += owner_pts

    return {
        "agility_score": min(score, 100),
        "factors": factors
    }


def save_compliance_result(
    scan_id: str, asset_id: str,
    compliance_data: dict, agility_data: dict,
    db: Session,
) -> ComplianceResult:
    """Persist compliance evaluation results to database."""
    result = ComplianceResult(
        asset_id=asset_id,
        scan_id=scan_id,
        fips_203_deployed=compliance_data.get("fips_203_deployed", False),
        fips_204_deployed=compliance_data.get("fips_204_deployed", False),
        fips_205_deployed=compliance_data.get("fips_205_deployed", False),
        tls_13_enforced=compliance_data.get("tls_13_enforced", False),
        forward_secrecy=compliance_data.get("forward_secrecy", False),
        hybrid_mode_active=compliance_data.get("hybrid_mode_active", False),
        classical_deprecated=compliance_data.get("classical_deprecated", False),
        cert_key_adequate=compliance_data.get("cert_key_adequate", False),
        ct_logged=compliance_data.get("ct_logged", False),
        chain_valid=compliance_data.get("chain_valid", False),
        rbi_compliant=compliance_data.get("rbi_compliant", False),
        sebi_compliant=compliance_data.get("sebi_compliant", False),
        pci_compliant=compliance_data.get("pci_compliant", False),
        npci_compliant=compliance_data.get("npci_compliant", False),
        crypto_agility_score=agility_data.get("agility_score", 0),
        compliance_pct=compliance_data.get("compliance_pct", 0.0),
        checks_json=compliance_data.get("checks"),
    )
    db.add(result)
    db.flush()
    logger.info(f"Saved compliance result for asset {asset_id}: {compliance_data['compliance_pct']}% compliant, agility={agility_data['agility_score']}")
    return result
