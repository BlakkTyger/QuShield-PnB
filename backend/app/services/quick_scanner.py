"""
Quick Scanner — Root-domain-only PQC analysis in 3–8 seconds.

Uses a single stdlib SSL connection (no SSLyze) to extract:
- TLS version, cipher suite, forward secrecy
- Certificate: key type, key length, SAN list, validity, signature algorithm
- NIST quantum level for cipher + cert key
- Risk score (Mosca's theorem)
- Compliance snapshot (TLS 1.3, PCI DSS, SEBI, RBI basic checks)

Returns the complete result synchronously — no DB persistence required.
"""
import ssl
import socket
import time
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448

from app.core.logging import get_logger
from app.services.crypto_inspector import (
    get_nist_quantum_level,
    parse_certificate_chain,
    classify_asset_type,
    detect_pqc,
    NIST_LEVELS,
)
from app.services.risk_engine import (
    compute_mosca,
    MIGRATION_TIME_DEFAULTS,
    SHELF_LIFE_DEFAULTS,
    RISK_CLASSIFICATIONS,
    _classify_risk,
)

logger = get_logger("quick_scanner")


def quick_scan(domain: str, port: int = 443, timeout: int = 8) -> dict:
    """
    Perform a quick PQC analysis of a single domain.

    Single SSL connection → cert parse → NIST levels → risk score → compliance.
    Target latency: 3–8 seconds.

    Args:
        domain: Root domain to scan (e.g., "pnb.bank.in")
        port: TLS port (default 443)
        timeout: Connection timeout in seconds

    Returns:
        Complete analysis dict with tls, certificate, quantum, risk, compliance data.
    """
    start_time = time.time()

    result = {
        "domain": domain,
        "port": port,
        "scan_type": "quick",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tls": None,
        "certificate": None,
        "quantum_assessment": None,
        "risk": None,
        "compliance": None,
        "key_findings": [],
        "duration_ms": 0,
        "error": None,
    }

    # ── Step 1: Single SSL connection ────────────────────────────────────
    tls_data = {}
    cert_chain_pem = []
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                # Negotiated cipher
                cipher_info = ssock.cipher()
                tls_version = ssock.version()

                negotiated_cipher = cipher_info[0] if cipher_info else None
                negotiated_protocol = cipher_info[1] if cipher_info else None

                # Forward secrecy detection
                forward_secrecy = False
                key_exchange = "RSA"
                if negotiated_cipher:
                    if "ECDHE" in negotiated_cipher:
                        forward_secrecy = True
                        key_exchange = "ECDHE"
                    elif "DHE" in negotiated_cipher:
                        forward_secrecy = True
                        key_exchange = "DHE"
                    elif negotiated_cipher.startswith("TLS_"):
                        # TLS 1.3 ciphers imply ECDHE by default
                        forward_secrecy = True
                        key_exchange = "ECDHE"

                tls_data = {
                    "negotiated_protocol": tls_version or negotiated_protocol,
                    "negotiated_cipher": negotiated_cipher,
                    "key_exchange": key_exchange,
                    "forward_secrecy": forward_secrecy,
                }

                # Shared ciphers
                shared = ssock.shared_ciphers()
                cipher_list = []
                if shared:
                    for c in shared:
                        cipher_list.append({
                            "name": c[0],
                            "tls_version": c[1],
                            "key_size": c[2],
                        })
                elif negotiated_cipher:
                    cipher_list.append({
                        "name": negotiated_cipher,
                        "tls_version": tls_version,
                        "key_size": None,
                    })
                tls_data["cipher_suites"] = cipher_list
                tls_data["cipher_count"] = len(cipher_list)

                # Certificate chain
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    cert_obj = x509.load_der_x509_certificate(cert_bin)
                    pem = cert_obj.public_bytes(serialization.Encoding.PEM)
                    cert_chain_pem.append(pem)

        result["tls"] = tls_data

    except Exception as e:
        result["error"] = f"TLS connection failed: {e}"
        result["duration_ms"] = round((time.time() - start_time) * 1000, 1)
        result["key_findings"].append({
            "severity": "critical",
            "title": "TLS Connection Failed",
            "detail": str(e),
        })
        return result

    # ── Step 2: Certificate parsing ──────────────────────────────────────
    cert_info = None
    if cert_chain_pem:
        try:
            chain = parse_certificate_chain(cert_chain_pem)
            if chain:
                leaf = chain[0]
                cert_info = {
                    "common_name": leaf.get("common_name"),
                    "issuer": leaf.get("issuer"),
                    "key_type": leaf.get("key_type"),
                    "key_length": leaf.get("key_length"),
                    "signature_algorithm": leaf.get("signature_algorithm"),
                    "valid_from": leaf.get("valid_from"),
                    "valid_to": leaf.get("valid_to"),
                    "san_list": leaf.get("san_list", []),
                    "san_count": len(leaf.get("san_list", [])),
                    "chain_valid": leaf.get("chain_valid"),
                    "is_ct_logged": leaf.get("is_ct_logged", False),
                    "sha256_fingerprint": leaf.get("sha256_fingerprint"),
                }

                # Days until expiry
                if leaf.get("valid_to"):
                    try:
                        expiry = datetime.fromisoformat(leaf["valid_to"])
                        if expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=timezone.utc)
                        cert_info["days_until_expiry"] = (expiry - datetime.now(timezone.utc)).days
                    except (ValueError, TypeError):
                        cert_info["days_until_expiry"] = None
        except Exception as e:
            logger.warning(f"Cert parse failed for {domain}: {e}")

    result["certificate"] = cert_info

    # ── Step 3: NIST quantum level assessment ────────────────────────────
    vuln_algos = []
    safe_algos = []
    all_levels = []

    # Assess cipher suites
    for cs in tls_data.get("cipher_suites", []):
        level = get_nist_quantum_level(cs["name"])
        if level["is_quantum_vulnerable"]:
            vuln_algos.append(cs["name"])
        else:
            safe_algos.append(cs["name"])
        if level["nist_level"] >= 0:
            all_levels.append(level["nist_level"])

    # Assess certificate key
    if cert_info:
        cert_level = get_nist_quantum_level(
            cert_info.get("key_type", "RSA"),
            cert_info.get("key_length"),
        )
        if cert_level["is_quantum_vulnerable"]:
            vuln_algos.append(f"{cert_info['key_type']}-{cert_info.get('key_length', '?')}")
        else:
            safe_algos.append(f"{cert_info['key_type']}-{cert_info.get('key_length', '?')}")
        if cert_level["nist_level"] >= 0:
            all_levels.append(cert_level["nist_level"])

    quantum_assessment = {
        "is_quantum_vulnerable": len(vuln_algos) > 0,
        "has_pqc": False,
        "lowest_nist_level": min(all_levels) if all_levels else -1,
        "vulnerable_algorithms": list(set(vuln_algos)),
        "safe_algorithms": list(set(safe_algos)),
        "total_algorithms_checked": len(vuln_algos) + len(safe_algos),
    }

    # Quick PQC check — look for PQC markers in cipher names
    pqc_markers = ["MLKEM", "ML_KEM", "KYBER", "X25519MLKEM", "MLDSA", "ML_DSA"]
    for cs in tls_data.get("cipher_suites", []):
        for marker in pqc_markers:
            if marker.upper() in cs["name"].upper():
                quantum_assessment["has_pqc"] = True
                break

    result["quantum_assessment"] = quantum_assessment

    # ── Step 4: Risk score (Mosca's theorem) ─────────────────────────────
    asset_type = classify_asset_type(domain)
    migration_time = MIGRATION_TIME_DEFAULTS.get(asset_type, 1.5)
    shelf_life = SHELF_LIFE_DEFAULTS.get(asset_type, {}).get("shelf_life_years", 5.0)

    mosca = compute_mosca(migration_time, shelf_life)

    # Simplified risk score for quick scan
    risk_points = 0

    # PQC deployment (300 max)
    if quantum_assessment["is_quantum_vulnerable"]:
        risk_points += 300
    # HNDL exposure (250 max)
    if mosca["exposed_pessimistic"]:
        risk_points += 150
        if mosca["exposed_median"]:
            risk_points += 50
            if mosca["exposed_optimistic"]:
                risk_points += 50
    # Crypto agility (150 max) — no agility data in quick scan, use TLS version heuristic
    is_tls13 = "1.3" in (tls_data.get("negotiated_protocol") or "")
    agility_penalty = 75 if is_tls13 else 150
    risk_points += agility_penalty
    # Cert hygiene (100 max)
    cert_penalty = 0
    if cert_info:
        if (cert_info.get("key_length") or 0) < 2048:
            cert_penalty += 50
        if not cert_info.get("is_ct_logged"):
            cert_penalty += 25
        days_exp = cert_info.get("days_until_expiry")
        if isinstance(days_exp, (int, float)) and days_exp < 30:
            cert_penalty += 25
    else:
        cert_penalty = 100
    risk_points += cert_penalty
    # Regulatory (100 max) — forward secrecy check
    if not forward_secrecy:
        risk_points += 100

    risk_points = min(risk_points, 1000)
    risk_classification = _classify_risk(risk_points)

    result["risk"] = {
        "score": risk_points,
        "max_score": 1000,
        "classification": risk_classification,
        "mosca": {
            "migration_time_years": migration_time,
            "data_shelf_life_years": shelf_life,
            "exposed_pessimistic": mosca["exposed_pessimistic"],
            "exposed_median": mosca["exposed_median"],
            "exposed_optimistic": mosca["exposed_optimistic"],
            "years_until_exposure": mosca["years_until_exposure"],
        },
        "asset_type": asset_type,
    }

    # ── Step 5: Compliance snapshot ──────────────────────────────────────
    proto = tls_data.get("negotiated_protocol") or ""
    compliance = {
        "tls_1_3_enforced": "1.3" in proto,
        "forward_secrecy": forward_secrecy,
        "cert_key_adequate": (cert_info.get("key_length") or 0) >= 2048 if cert_info else False,
        "ct_logged": cert_info.get("is_ct_logged", False) if cert_info else False,
        "pci_dss_4_basic": "1.3" in proto or "1.2" in proto,  # PCI requires TLS 1.2+
        "rbi_forward_secrecy": forward_secrecy,
        "sebi_tls_compliant": "1.3" in proto and (cert_info.get("key_length") or 0) >= 2048 if cert_info else False,
        "has_pqc_deployment": quantum_assessment["has_pqc"],
        "fips_203_detected": False,
        "fips_204_detected": False,
        "fips_205_detected": False,
    }

    # Check for FIPS in cipher names
    for cs in tls_data.get("cipher_suites", []):
        name_upper = cs["name"].upper()
        if "MLKEM" in name_upper or "ML_KEM" in name_upper:
            compliance["fips_203_detected"] = True
        if "MLDSA" in name_upper or "ML_DSA" in name_upper:
            compliance["fips_204_detected"] = True
        if "SLHDSA" in name_upper or "SLH_DSA" in name_upper:
            compliance["fips_205_detected"] = True

    checks_passed = sum(1 for v in compliance.values() if v is True)
    checks_total = len(compliance)
    compliance["compliance_pct"] = round(checks_passed / checks_total * 100, 1)

    result["compliance"] = compliance

    # ── Step 6: Key findings ─────────────────────────────────────────────
    findings = []

    if quantum_assessment["is_quantum_vulnerable"]:
        findings.append({
            "severity": "critical",
            "title": f"{cert_info['key_type']}-{cert_info['key_length']} key exchange detected" if cert_info else "Quantum-vulnerable cryptography detected",
            "detail": f"Vulnerable to Shor's algorithm. {len(vuln_algos)} vulnerable algorithm(s) found.",
        })

    if mosca["exposed_pessimistic"]:
        findings.append({
            "severity": "high",
            "title": "HNDL exposure window active",
            "detail": f"Harvest-Now-Decrypt-Later risk: data with {shelf_life}yr shelf life + {migration_time}yr migration exceeds CRQC timeline.",
        })

    if not forward_secrecy:
        findings.append({
            "severity": "high",
            "title": "No forward secrecy detected",
            "detail": "Past TLS sessions can be retroactively decrypted if the server's private key is compromised.",
        })

    if not ("1.3" in proto or "1.2" in proto):
        findings.append({
            "severity": "critical",
            "title": f"Outdated TLS version: {proto}",
            "detail": "TLS 1.0/1.1 is deprecated. PCI DSS 4.0 and RBI require TLS 1.2 minimum.",
        })
    elif "1.3" not in proto:
        findings.append({
            "severity": "medium",
            "title": f"TLS 1.2 only (not 1.3)",
            "detail": "TLS 1.3 provides improved security and performance. Required for SEBI CSCRF compliance.",
        })

    if not quantum_assessment["has_pqc"]:
        findings.append({
            "severity": "medium",
            "title": "No PQC deployment detected",
            "detail": "No FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), or hybrid PQC groups found.",
        })

    if cert_info:
        days_exp = cert_info.get("days_until_expiry")
        if isinstance(days_exp, (int, float)) and days_exp < 30:
            findings.append({
                "severity": "high",
                "title": f"Certificate expiring in {days_exp} days",
                "detail": f"Certificate for {cert_info.get('common_name')} expires on {cert_info.get('valid_to')}.",
            })

    result["key_findings"] = findings

    # ── Finalize ─────────────────────────────────────────────────────────
    result["duration_ms"] = round((time.time() - start_time) * 1000, 1)

    logger.info(
        f"Quick scan complete for {domain}",
        extra={
            "domain": domain,
            "duration_ms": result["duration_ms"],
            "risk_score": risk_points,
            "classification": risk_classification,
            "tls_version": tls_data.get("negotiated_protocol"),
            "findings_count": len(findings),
        },
    )

    return result
