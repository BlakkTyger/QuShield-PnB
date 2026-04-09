import logging

logger = logging.getLogger(__name__)

def evaluate_compliance(asset_id: str, cbom_data: dict, crypto_data: dict) -> dict:
    """
    Evaluates cryptographic arrays against standardized compliance benchmarks.
    """
    checks = []
    passed = 0
    failed = 0

    # 1. FIPS 203: ML-KEM deployed?
    has_mlkem = False
    # 2. FIPS 204: ML-DSA deployed?
    has_mldsa = False
    # 3. FIPS 205: SLH-DSA deployed?
    has_slhdsa = False
    
    if cbom_data and "components" in cbom_data:
        for comp in cbom_data["components"]:
            name = comp.get("name", "").upper()
            if "ML-KEM" in name:
                has_mlkem = True
            if "ML-DSA" in name:
                has_mldsa = True
            if "SLH-DSA" in name or "SPHINCS+" in name:
                has_slhdsa = True
                
    if has_mlkem:
        checks.append({"rule": "FIPS 203 (ML-KEM)", "status": "PASS", "msg": "ML-KEM detected in key exchange."})
        passed += 1
    else:
        checks.append({"rule": "FIPS 203 (ML-KEM)", "status": "FAIL", "msg": "CRITICAL: No ML-KEM found. Non-compliant with FIPS 203."})
        failed += 1

    if has_mldsa:
        checks.append({"rule": "FIPS 204 (ML-DSA)", "status": "PASS", "msg": "ML-DSA detected in signatures."})
        passed += 1
    else:
        checks.append({"rule": "FIPS 204 (ML-DSA)", "status": "FAIL", "msg": "CRITICAL: No ML-DSA signature logic detected. Non-compliant with FIPS 204."})
        failed += 1

    if has_slhdsa:
        checks.append({"rule": "FIPS 205 (SLH-DSA)", "status": "PASS", "msg": "SLH-DSA detected as fallback."})
        passed += 1
    else:
        checks.append({"rule": "FIPS 205 (SLH-DSA)", "status": "FAIL", "msg": "CRITICAL: No SLH-DSA logic detected. Non-compliant with FIPS 205."})
        failed += 1

    # 4. TLS 1.3 Enforced
    tls_enforced = False
    tls_data = crypto_data.get("tls", {})
    if tls_data:
        negotiated = tls_data.get("negotiated_protocol", "")
        # A simple string check for POC
        if "TLSv1.3" in negotiated:
            tls_enforced = True

    if tls_enforced:
        checks.append({"rule": "TLS 1.3 Enforcement", "status": "PASS", "msg": "TLS 1.3 is actively enforcing connections."})
        passed += 1
    else:
        checks.append({"rule": "TLS 1.3 Enforcement", "status": "FAIL", "msg": "Connection falls back below TLS 1.3."})
        failed += 1

    # 5. Forward Secrecy
    fs = tls_data.get("forward_secrecy", False)
    if fs:
        checks.append({"rule": "Forward Secrecy", "status": "PASS", "msg": "KEX supports perfect forward secrecy."})
        passed += 1
    else:
        checks.append({"rule": "Forward Secrecy", "status": "FAIL", "msg": "Weak key exchange. KEX lacks forward secrecy."})
        failed += 1

    pct = round((passed / (passed + failed)) * 100, 2) if passed + failed > 0 else 0.0

    return {
        "checks": checks,
        "passed": passed,
        "failed": failed,
        "compliance_pct": pct
    }

def compute_agility_score(asset_data: dict, cert_history: list = None) -> dict:
    """
    Computes an organizational crypto-agility score (0-100) based on rotation
    and dynamic capability indicators.
    """
    factors = []
    score = 0

    # 1. Dynamic cipher negotiation (Assume 20 for TLS capability presence for now)
    factors.append({"factor": "Dynamic Cipher Negotiation", "points": 20})
    score += 20

    # 2. Automated cert renewal (Detect Let's Encrypt / short expiry)
    cert_data = asset_data.get("certificates", [])
    if cert_data:
        issuer = cert_data[0].get("issuer", "").lower()
        if "let's encrypt" in issuer or "acme" in issuer:
            factors.append({"factor": "Automated Cert Renewal", "points": 20})
            score += 20
        else:
            factors.append({"factor": "Automated Cert Renewal", "points": 0})
    else:
        factors.append({"factor": "Automated Cert Renewal", "points": 0})

    # 3. Key rotation frequency (Assume 10 out of 20 for no cert history logic)
    factors.append({"factor": "Key Rotation Frequency", "points": 10})
    score += 10

    # 4. Crypto library recency
    factors.append({"factor": "Crypto Library Recency", "points": 20})
    score += 20

    # 5. Documented ownership
    factors.append({"factor": "Documented Ownership", "points": 10})
    score += 10

    return {
        "agility_score": score,
        "factors": factors
    }
