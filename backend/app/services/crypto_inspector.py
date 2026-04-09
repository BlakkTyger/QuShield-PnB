"""
Crypto Inspector — TLS scanning, certificate parsing, PQC detection, and quantum level assignment.

This is the core cryptographic analysis engine of QuShield-PnB.
"""
import hashlib
import json
import ssl
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
import httpx

from app.config import settings, PROJECT_ROOT
from app.core.logging import get_logger
from app.core.timing import timed

logger = get_logger("crypto_inspector")

# Load static data files
_DATA_DIR = PROJECT_ROOT / "backend" / "app" / "data"

def _load_json(name: str) -> dict:
    with open(_DATA_DIR / name) as f:
        return json.load(f)

NIST_LEVELS = _load_json("nist_quantum_levels.json")
PQC_OIDS = _load_json("pqc_oids.json")
SHELF_LIFE = _load_json("data_shelf_life_defaults.json")


# ─── P2.1: TLS Handshake & Cipher Suite Enumeration ─────────────────────────


@timed(service="crypto_inspector")
def scan_tls(hostname: str, port: int = 443, timeout: int = 15) -> dict:
    """
    Perform TLS handshake analysis and cipher suite enumeration.

    Uses Python's ssl module to probe TLS versions and cipher suites,
    falling back to SSLyze for deeper analysis if available.

    Returns dict with tls_versions_supported, cipher_suites, negotiated_cipher,
    key_exchange, forward_secrecy, certificate chain, etc.
    """
    result = {
        "hostname": hostname,
        "port": port,
        "tls_versions_supported": [],
        "cipher_suites": [],
        "negotiated_cipher": None,
        "negotiated_protocol": None,
        "key_exchange": None,
        "forward_secrecy": False,
        "certificate_chain_pem": [],
        "server_name": None,
        "error": None,
    }

    # Try SSLyze first for comprehensive scanning
    sslyze_result = None
    try:
        sslyze_result = _scan_with_sslyze(hostname, port, timeout)
        # If SSLyze returned results with cipher suites, use them
        if sslyze_result.get("cipher_suites") and len(sslyze_result["cipher_suites"]) > 0:
            return sslyze_result
        else:
            logger.warning(
                f"SSLyze returned empty cipher suites for {hostname}:{port}, falling back to stdlib",
                extra={"hostname": hostname, "port": port},
            )
    except Exception as sslyze_err:
        logger.warning(
            f"SSLyze scan failed for {hostname}:{port}, falling back to stdlib: {sslyze_err}",
            extra={"hostname": hostname, "port": port, "sslyze_error": str(sslyze_err)},
        )

    # Fallback: stdlib ssl module
    try:
        result = _scan_with_stdlib(hostname, port, timeout)
        # Merge SSLyze cert chain (richer — has full chain with intermediates)
        if sslyze_result and sslyze_result.get("certificate_chain_pem"):
            result["certificate_chain_pem"] = sslyze_result["certificate_chain_pem"]
    except Exception as e:
        result["error"] = str(e)
        logger.error(f"TLS scan failed for {hostname}:{port}: {e}")

    return result


def _scan_with_sslyze(hostname: str, port: int, timeout: int) -> dict:
    """Use SSLyze for comprehensive TLS scanning."""
    from sslyze import (
        Scanner,
        ServerScanRequest,
        ServerNetworkLocation,
        ScanCommand,
    )

    result = {
        "hostname": hostname,
        "port": port,
        "tls_versions_supported": [],
        "cipher_suites": [],
        "negotiated_cipher": None,
        "negotiated_protocol": None,
        "key_exchange": None,
        "forward_secrecy": False,
        "certificate_chain_pem": [],
        "server_name": None,
        "error": None,
    }

    location = ServerNetworkLocation(hostname=hostname, port=port)
    request = ServerScanRequest(
        server_location=location,
        scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.TLS_1_0_CIPHER_SUITES,
            ScanCommand.TLS_1_1_CIPHER_SUITES,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        },
    )

    scanner = Scanner()
    scanner.queue_scans([request])

    for scan_result in scanner.get_results():
        # Check for connectivity errors
        if scan_result.connectivity_error_trace:
            result["error"] = "Connectivity error"
            return result

        # Cipher suites by TLS version
        tls_version_map = {
            ScanCommand.TLS_1_0_CIPHER_SUITES: "TLSv1.0",
            ScanCommand.TLS_1_1_CIPHER_SUITES: "TLSv1.1",
            ScanCommand.TLS_1_2_CIPHER_SUITES: "TLSv1.2",
            ScanCommand.TLS_1_3_CIPHER_SUITES: "TLSv1.3",
        }

        for cmd, version_name in tls_version_map.items():
            try:
                cmd_result = scan_result.scan_result.scan_commands_results.get(cmd)
                if cmd_result is None:
                    continue
                accepted = cmd_result.accepted_cipher_suites
                if accepted:
                    result["tls_versions_supported"].append(version_name)
                    for cs in accepted:
                        cipher_name = cs.cipher_suite.name
                        result["cipher_suites"].append({
                            "name": cipher_name,
                            "tls_version": version_name,
                            "key_size": getattr(cs.cipher_suite, 'key_size', None),
                        })
            except Exception:
                continue

        # Certificate chain
        try:
            cert_result = scan_result.scan_result.scan_commands_results.get(
                ScanCommand.CERTIFICATE_INFO
            )
            if cert_result:
                for deployment in cert_result.certificate_deployments:
                    for cert in deployment.received_certificate_chain:
                        pem = cert.public_bytes(serialization.Encoding.PEM)
                        result["certificate_chain_pem"].append(pem)

                    # Negotiated cipher from the leaf
                    if deployment.received_certificate_chain:
                        leaf = deployment.received_certificate_chain[0]
                        result["server_name"] = _get_cn(leaf)
        except Exception:
            pass

        # Determine negotiated cipher and forward secrecy from best TLS version
        if result["cipher_suites"]:
            # Pick the first cipher from the highest TLS version
            best = result["cipher_suites"][-1]  # last added = highest version
            result["negotiated_cipher"] = best["name"]
            result["negotiated_protocol"] = best["tls_version"]

            # Check forward secrecy
            fs_prefixes = ("TLS_", "ECDHE_", "DHE_")
            result["forward_secrecy"] = any(
                cs["name"].startswith(p) for p in fs_prefixes
                for cs in result["cipher_suites"]
                if cs["tls_version"] in ("TLSv1.2", "TLSv1.3")
            )

            # Key exchange
            for cs in result["cipher_suites"]:
                name = cs["name"]
                if "ECDHE" in name:
                    result["key_exchange"] = "ECDHE"
                    break
                elif "DHE" in name:
                    result["key_exchange"] = "DHE"
                    break
                elif "RSA" in name:
                    result["key_exchange"] = "RSA"

    logger.info(
        f"TLS scan complete for {hostname}:{port}",
        extra={
            "hostname": hostname,
            "tls_versions": result["tls_versions_supported"],
            "cipher_count": len(result["cipher_suites"]),
            "negotiated": result["negotiated_cipher"],
            "forward_secrecy": result["forward_secrecy"],
        },
    )

    return result


def _scan_with_stdlib(hostname: str, port: int, timeout: int) -> dict:
    """Fallback TLS scan using Python's ssl module."""
    result = {
        "hostname": hostname,
        "port": port,
        "tls_versions_supported": [],
        "cipher_suites": [],
        "negotiated_cipher": None,
        "negotiated_protocol": None,
        "key_exchange": None,
        "forward_secrecy": False,
        "certificate_chain_pem": [],
        "server_name": None,
        "error": None,
    }

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    with socket.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            # Get negotiated cipher
            cipher_info = ssock.cipher()
            if cipher_info:
                result["negotiated_cipher"] = cipher_info[0]
                result["negotiated_protocol"] = cipher_info[1]

            # Get TLS version
            tls_version = ssock.version()
            if tls_version:
                result["tls_versions_supported"].append(tls_version)

            # Get certificate chain as PEM
            cert_bin = ssock.getpeercert(binary_form=True)
            if cert_bin:
                from cryptography.x509 import load_der_x509_certificate
                cert = load_der_x509_certificate(cert_bin)
                pem = cert.public_bytes(serialization.Encoding.PEM)
                result["certificate_chain_pem"].append(pem)
                result["server_name"] = _get_cn(cert)

            # Check for forward secrecy
            if result["negotiated_cipher"]:
                name = result["negotiated_cipher"]
                result["forward_secrecy"] = "ECDHE" in name or "DHE" in name or name.startswith("TLS_")
                if "ECDHE" in name:
                    result["key_exchange"] = "ECDHE"
                elif "DHE" in name:
                    result["key_exchange"] = "DHE"
                else:
                    result["key_exchange"] = "RSA"

            # Get all supported ciphers
            shared_ciphers = ssock.shared_ciphers()
            if shared_ciphers:
                for c in shared_ciphers:
                    result["cipher_suites"].append({
                        "name": c[0],
                        "tls_version": c[1],
                        "key_size": c[2],
                    })
            elif result["negotiated_cipher"]:
                # shared_ciphers() returned None — at minimum include the negotiated cipher
                result["cipher_suites"].append({
                    "name": result["negotiated_cipher"],
                    "tls_version": result["negotiated_protocol"] or tls_version,
                    "key_size": None,
                })

    return result


def _get_cn(cert) -> str:
    """Extract common name from an x509 certificate."""
    try:
        for attr in cert.subject:
            if attr.oid == x509.oid.NameOID.COMMON_NAME:
                return attr.value
    except Exception:
        pass
    return ""


# ─── P2.2: Certificate Chain Parsing ────────────────────────────────────────


@timed(service="crypto_inspector")
def parse_certificate(cert_pem: bytes) -> dict:
    """
    Parse a PEM-encoded certificate and extract all relevant fields.

    Returns dict with: common_name, san_list, issuer, ca_name, key_type,
    key_length, signature_algorithm, signature_algorithm_oid, valid_from,
    valid_to, sha256_fingerprint, is_self_signed, chain_depth.
    """
    cert = x509.load_pem_x509_certificate(cert_pem)

    # Key type and length
    pub_key = cert.public_key()
    key_type, key_length = _detect_key_type(pub_key)

    # Signature algorithm
    sig_algo = cert.signature_algorithm_oid.dotted_string
    sig_algo_name = _normalize_sig_algo(cert.signature_hash_algorithm, key_type)

    # SAN (Subject Alternative Names)
    san_list = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san_list = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    # SHA-256 fingerprint
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()

    # Check CT SCT (Certificate Transparency)
    is_ct_logged = False
    try:
        cert.extensions.get_extension_for_class(
            x509.PrecertificateSignedCertificateTimestamps
        )
        is_ct_logged = True
    except x509.ExtensionNotFound:
        pass

    # Issuer info
    issuer_cn = ""
    for attr in cert.issuer:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            issuer_cn = attr.value
            break

    issuer_org = ""
    for attr in cert.issuer:
        if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
            issuer_org = attr.value
            break

    # Subject CN
    subject_cn = ""
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            subject_cn = attr.value
            break

    # Self-signed check
    is_self_signed = cert.issuer == cert.subject

    result = {
        "common_name": subject_cn,
        "san_list": san_list,
        "issuer": issuer_cn,
        "ca_name": issuer_org,
        "key_type": key_type,
        "key_length": key_length,
        "signature_algorithm": sig_algo_name,
        "signature_algorithm_oid": sig_algo,
        "valid_from": cert.not_valid_before_utc.isoformat(),
        "valid_to": cert.not_valid_after_utc.isoformat(),
        "sha256_fingerprint": fingerprint,
        "is_ct_logged": is_ct_logged,
        "is_self_signed": is_self_signed,
        "days_until_expiry": (cert.not_valid_after_utc - datetime.now(timezone.utc)).days,
    }

    logger.debug(
        f"Parsed cert: {subject_cn} ({key_type}-{key_length})",
        extra={
            "common_name": subject_cn,
            "key_type": key_type,
            "key_length": key_length,
            "days_until_expiry": result["days_until_expiry"],
        },
    )

    return result


def _detect_key_type(pub_key) -> tuple[str, int]:
    """Detect the public key type and length."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        return "RSA", pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve = pub_key.curve.name
        return f"EC-{curve}", pub_key.key_size
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448", 456
    else:
        return "Unknown", 0


def _normalize_sig_algo(hash_algo, key_type: str) -> str:
    """Normalize signature algorithm name."""
    if hash_algo is None:
        # Could be Ed25519 or PQC (no separate hash)
        if "Ed25519" in key_type:
            return "Ed25519"
        return "Unknown"

    hash_name = hash_algo.name.upper()
    if "RSA" in key_type:
        return f"RSA-{hash_name}"
    elif "EC" in key_type:
        return f"ECDSA-{hash_name}"
    return hash_name


@timed(service="crypto_inspector")
def parse_certificate_chain(chain_pems: list[bytes]) -> list[dict]:
    """
    Parse a full certificate chain.

    Returns list of parsed certs with chain_position field:
    0=leaf, 1+=intermediate, last=root (if self-signed).
    """
    if not chain_pems:
        return []

    parsed = []
    for i, pem in enumerate(chain_pems):
        cert_data = parse_certificate(pem)
        cert_data["chain_depth"] = i
        if i == 0:
            cert_data["chain_position"] = "leaf"
        elif cert_data.get("is_self_signed"):
            cert_data["chain_position"] = "root"
        else:
            cert_data["chain_position"] = "intermediate"
        parsed.append(cert_data)

    # Validate chain order
    chain_valid = True
    for i in range(len(parsed) - 1):
        if parsed[i].get("issuer") != parsed[i + 1].get("common_name"):
            chain_valid = False
            break

    for cert in parsed:
        cert["chain_valid"] = chain_valid

    logger.info(
        f"Parsed certificate chain: {len(parsed)} certs, valid={chain_valid}",
        extra={
            "chain_depth": len(parsed),
            "chain_valid": chain_valid,
            "leaf_cn": parsed[0]["common_name"] if parsed else None,
        },
    )

    return parsed


# ─── P2.3: NIST Quantum Security Level Assignment ───────────────────────────


def get_nist_quantum_level(algorithm: str, key_length: int = None) -> dict:
    """
    Look up the NIST quantum security level for a cryptographic algorithm.

    Returns: {"nist_level": int, "is_quantum_vulnerable": bool, "quantum_status": str}
    """
    normalized = _normalize_algorithm_name(algorithm)

    # Direct lookup
    if normalized in NIST_LEVELS:
        entry = NIST_LEVELS[normalized]
        return {
            "nist_level": entry["nist_level"],
            "is_quantum_vulnerable": entry["quantum_vulnerable"],
            "quantum_status": entry["status"],
            "matched_as": normalized,
        }

    # Try with key length suffix
    if key_length:
        with_length = f"{normalized}-{key_length}"
        if with_length in NIST_LEVELS:
            entry = NIST_LEVELS[with_length]
            return {
                "nist_level": entry["nist_level"],
                "is_quantum_vulnerable": entry["quantum_vulnerable"],
                "quantum_status": entry["status"],
                "matched_as": with_length,
            }

    # Partial matching for common patterns
    for known_algo, entry in NIST_LEVELS.items():
        if known_algo.lower() in normalized.lower() or normalized.lower() in known_algo.lower():
            return {
                "nist_level": entry["nist_level"],
                "is_quantum_vulnerable": entry["quantum_vulnerable"],
                "quantum_status": entry["status"],
                "matched_as": known_algo,
            }

    # Unknown
    return {
        "nist_level": -1,
        "is_quantum_vulnerable": True,  # Assume vulnerable if unknown
        "quantum_status": "unknown",
        "matched_as": None,
    }


def _normalize_algorithm_name(name: str) -> str:
    """Normalize TLS cipher suite names to our algorithm naming convention."""
    # Common TLS 1.3 cipher suite names
    mappings = {
        "TLS_AES_256_GCM_SHA384": "AES-256-GCM",
        "TLS_AES_128_GCM_SHA256": "AES-128-GCM",
        "TLS_CHACHA20_POLY1305_SHA256": "ChaCha20-Poly1305",
        "TLS_AES_128_CCM_SHA256": "AES-128-GCM",
        "ECDHE-RSA-AES256-GCM-SHA384": "ECDHE-RSA",
        "ECDHE-ECDSA-AES256-GCM-SHA384": "ECDHE-ECDSA",
        "ECDHE-RSA-AES128-GCM-SHA256": "ECDHE-RSA",
        "ECDHE-ECDSA-AES128-GCM-SHA256": "ECDHE-ECDSA",
        "DHE-RSA-AES256-GCM-SHA384": "DHE-RSA",
        "DES-CBC3-SHA": "3DES-CBC",
        "RC4-SHA": "RC4",
        "RC4-MD5": "RC4",
    }

    if name in mappings:
        return mappings[name]

    # Extract main algorithm patterns
    name_upper = name.upper()
    if "AES_256_GCM" in name_upper or "AES256-GCM" in name_upper:
        return "AES-256-GCM"
    if "AES_128_GCM" in name_upper or "AES128-GCM" in name_upper:
        return "AES-128-GCM"
    if "CHACHA20" in name_upper:
        return "ChaCha20-Poly1305"
    if "AES_256_CBC" in name_upper or "AES256-CBC" in name_upper:
        return "AES-256-CBC"
    if "3DES" in name_upper or "DES-CBC3" in name_upper:
        return "3DES-CBC"
    if "RC4" in name_upper:
        return "RC4"

    # Key exchange detection
    if name_upper.startswith("ECDHE"):
        if "ECDSA" in name_upper:
            return "ECDHE-ECDSA"
        return "ECDHE-RSA"
    if name_upper.startswith("DHE"):
        return "DHE-RSA"

    return name


# ─── P2.4: PQC Detection ────────────────────────────────────────────────────


@timed(service="crypto_inspector")
def detect_pqc(hostname: str, port: int = 443) -> dict:
    """
    Detect Post-Quantum Cryptography deployment on a host.

    Layer 1: Check certificate signature OID against PQC OID table.
    Layer 2: Check TLS key exchange groups for PQC support (limited without oqs-provider).

    Returns dict with pqc_key_exchange, pqc_signature, algorithms found, detection method.
    """
    result = {
        "pqc_key_exchange": False,
        "pqc_signature": False,
        "pqc_algorithms_found": [],
        "detection_method": "oid_check",
        "note": None,
    }

    # Build reverse OID lookup
    oid_to_algo = {}
    for algo_name, info in PQC_OIDS.items():
        oid_to_algo[info["oid"]] = algo_name

    # Layer 1: Check cert signature OIDs
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    cert = x509.load_der_x509_certificate(cert_bin)
                    sig_oid = cert.signature_algorithm_oid.dotted_string

                    if sig_oid in oid_to_algo:
                        algo = oid_to_algo[sig_oid]
                        result["pqc_signature"] = True
                        result["pqc_algorithms_found"].append(algo)

                # Layer 2: Check negotiated cipher for PQC key exchange
                cipher_info = ssock.cipher()
                if cipher_info:
                    cipher_name = cipher_info[0]
                    pqc_kex_markers = ["MLKEM", "ML_KEM", "KYBER", "X25519MLKEM"]
                    for marker in pqc_kex_markers:
                        if marker.upper() in cipher_name.upper():
                            result["pqc_key_exchange"] = True
                            result["pqc_algorithms_found"].append(cipher_name)

    except Exception as e:
        result["note"] = f"PQC detection error: {str(e)}"

    if not result["pqc_key_exchange"] and not result["pqc_signature"]:
        result["note"] = (
            "No PQC detected. Full PQC key exchange detection requires "
            "OpenSSL 3.5+ with oqs-provider. OID-based signature check completed."
        )

    logger.info(
        f"PQC detection for {hostname}:{port}",
        extra={
            "hostname": hostname,
            "pqc_signature": result["pqc_signature"],
            "pqc_key_exchange": result["pqc_key_exchange"],
            "algorithms_found": result["pqc_algorithms_found"],
        },
    )

    return result


# ─── P2.5: API Auth Fingerprinting ──────────────────────────────────────────


@timed(service="crypto_inspector")
def detect_api_auth(url: str) -> dict:
    """
    Detect authentication mechanisms from a URL endpoint.

    Checks for OIDC, JWT, mTLS, API key patterns.
    """
    result = {
        "auth_mechanisms": [],
        "jwt_algorithm": None,
        "oidc_endpoint": None,
        "note": None,
    }

    try:
        # Check for OIDC discovery
        base_url = url.rstrip("/")
        oidc_url = f"{base_url}/.well-known/openid-configuration"

        with httpx.Client(timeout=10, verify=False) as client:
            # Test OIDC
            try:
                resp = client.get(oidc_url, follow_redirects=True)
                if resp.status_code == 200:
                    try:
                        oidc_data = resp.json()
                        if "issuer" in oidc_data:
                            result["auth_mechanisms"].append("OIDC")
                            result["oidc_endpoint"] = oidc_url
                            # Check signing algs
                            algs = oidc_data.get("id_token_signing_alg_values_supported", [])
                            if algs:
                                result["jwt_algorithm"] = algs[0]
                    except Exception:
                        pass
            except Exception:
                pass

            # Check main URL for auth headers
            try:
                resp = client.get(base_url, follow_redirects=True)
                www_auth = resp.headers.get("www-authenticate", "")
                if "bearer" in www_auth.lower():
                    if "JWT" not in result["auth_mechanisms"]:
                        result["auth_mechanisms"].append("Bearer")
                if resp.headers.get("x-api-key") or "api-key" in resp.headers.get("www-authenticate", "").lower():
                    result["auth_mechanisms"].append("API-Key")
            except Exception:
                pass

    except Exception as e:
        result["note"] = f"Auth detection error: {str(e)}"

    logger.debug(
        f"Auth detection for {url}",
        extra={"url": url, "mechanisms": result["auth_mechanisms"]},
    )

    return result


# ─── Certificate Intelligence Enhancements ──────────────────────────────────

# Load CA PQC readiness data
_CA_PQC_READINESS = _load_json("ca_pqc_readiness.json")

# CRQC arrival year (pessimistic scenario) — used for effective expiry
_CRQC_PESSIMISTIC_YEAR = 2029


def compute_effective_security_expiry(
    valid_to: datetime,
    key_type: str,
    key_length: int | None = None,
) -> dict:
    """
    Compute CRQC-adjusted effective security expiry.

    Returns the earlier of:
      - The certificate's calendar expiry date
      - The estimated date at which the cert's key becomes quantum-breakable

    This is per 02-OUTPUTS.md Module 7: "effective security remaining".
    """
    from datetime import datetime, timezone

    crqc_date = datetime(_CRQC_PESSIMISTIC_YEAR, 1, 1, tzinfo=timezone.utc)

    # Check if key type is quantum-vulnerable
    level_info = get_nist_quantum_level(key_type, key_length)
    is_vulnerable = level_info.get("is_quantum_vulnerable", True)

    if is_vulnerable:
        effective_expiry = min(valid_to, crqc_date) if valid_to else crqc_date
    else:
        effective_expiry = valid_to  # PQC key — no CRQC adjustment needed

    effective_remaining_days = (effective_expiry - datetime.now(timezone.utc)).days if effective_expiry else None

    return {
        "effective_expiry": effective_expiry.isoformat() if effective_expiry else None,
        "calendar_expiry": valid_to.isoformat() if valid_to else None,
        "crqc_adjusted": is_vulnerable,
        "effective_remaining_days": effective_remaining_days,
        "limited_by": "crqc" if (is_vulnerable and valid_to and crqc_date < valid_to) else "calendar",
    }


def lookup_ca_pqc_readiness(ca_name: str | None) -> dict:
    """
    Look up whether the issuing CA has committed to issuing PQC certificates.

    Uses static data from ca_pqc_readiness.json.
    Per 02-OUTPUTS.md Module 2.2: "Certificate Authority PQC Readiness".
    """
    if not ca_name:
        return _CA_PQC_READINESS.get("Unknown", {})

    # Fuzzy match CA name against known CAs
    ca_lower = ca_name.lower()
    for key, info in _CA_PQC_READINESS.items():
        if key.lower() in ca_lower or ca_lower in key.lower():
            return info
        # Also check the full name
        if info.get("name", "").lower() in ca_lower:
            return info

    return _CA_PQC_READINESS.get("Unknown", {})


def analyze_multi_san_exposure(san_list: list | None) -> dict:
    """
    Analyze Multi-SAN exposure — one certificate covering many subdomains.

    Per 02-OUTPUTS.md Module 2.2: "Multi-SAN Exposure: One certificate
    covering many subdomains — breach of the key = breach of all."
    """
    if not san_list:
        return {"san_count": 0, "unique_domains": 0, "is_multi_san": False, "risk_note": None}

    san_count = len(san_list)

    # Extract unique base domains from SANs
    unique_domains = set()
    for san in san_list:
        parts = san.strip("*.").split(".")
        if len(parts) >= 2:
            unique_domains.add(".".join(parts[-2:]))

    is_multi_san = san_count > 5
    risk_note = None
    if san_count > 20:
        risk_note = f"CRITICAL: Certificate covers {san_count} SANs across {len(unique_domains)} domains. Key compromise affects all."
    elif san_count > 10:
        risk_note = f"HIGH: Certificate covers {san_count} SANs. Consider separate certificates per service."
    elif san_count > 5:
        risk_note = f"MEDIUM: Certificate covers {san_count} SANs. Monitor key rotation."

    return {
        "san_count": san_count,
        "unique_domains": len(unique_domains),
        "is_multi_san": is_multi_san,
        "risk_note": risk_note,
        "domains": list(unique_domains),
    }


@timed(service="crypto_inspector")
def detect_certificate_pinning(hostname: str, port: int = 443) -> dict:
    """
    Detect certificate pinning headers (HPKP, Expect-CT, Expect-Staple).

    Per 02-OUTPUTS.md Module 7: "Certificate Pinning Detector — banks with
    mobile apps that pin certificates face an additional migration barrier."
    """
    result = {
        "hpkp_detected": False,
        "expect_ct_detected": False,
        "expect_staple_detected": False,
        "is_pinned": False,
        "pinning_headers": {},
        "migration_note": None,
    }

    try:
        with httpx.Client(verify=False, timeout=10.0) as client:
            resp = client.get(f"https://{hostname}:{port}", follow_redirects=True)
            headers = dict(resp.headers)

            # Check HPKP (HTTP Public Key Pinning)
            hpkp = headers.get("public-key-pins") or headers.get("public-key-pins-report-only")
            if hpkp:
                result["hpkp_detected"] = True
                result["pinning_headers"]["public-key-pins"] = hpkp

            # Check Expect-CT
            expect_ct = headers.get("expect-ct")
            if expect_ct:
                result["expect_ct_detected"] = True
                result["pinning_headers"]["expect-ct"] = expect_ct

            # Check Expect-Staple
            expect_staple = headers.get("expect-staple")
            if expect_staple:
                result["expect_staple_detected"] = True
                result["pinning_headers"]["expect-staple"] = expect_staple

            result["is_pinned"] = result["hpkp_detected"] or result["expect_ct_detected"]

            if result["is_pinned"]:
                result["migration_note"] = (
                    "Pinning-Blocked: Pinned certificates cannot be silently replaced with PQC certs "
                    "without mobile app updates. Flag as migration-blocked."
                )

    except Exception as e:
        logger.debug(f"Pinning detection failed for {hostname}: {e}")

    return result


# ─── Infrastructure Fingerprinting ──────────────────────────────────────────

# CDN/WAF detection patterns
_CDN_PATTERNS = {
    "Akamai": ["akamai", "akadns", "edgekey", "edgesuite", "akamaiedge", "akamaihd"],
    "Cloudflare": ["cloudflare", "cf-ray", "cf-cache-status"],
    "Incapsula/Imperva": ["incapsula", "imperva", "incap_ses", "visid_incap"],
    "AWS CloudFront": ["cloudfront", "x-amz-cf"],
    "Azure CDN": ["azure", "msedge", "afd", "azureedge"],
    "Fastly": ["fastly", "x-fastly"],
    "Google Cloud CDN": ["ghs.googlehosted.com", "google", "ghs.google"],
    "StackPath": ["stackpath", "highwinds"],
}

_WAF_PATTERNS = {
    "F5 BIG-IP": ["bigip", "big-ip", "f5"],
    "Citrix NetScaler": ["netscaler", "citrix", "ns-"],
    "Fortinet FortiWeb": ["fortiweb", "fortigate"],
    "Barracuda": ["barracuda", "barra"],
    "AWS WAF": ["awswaf", "x-amzn-waf"],
    "Cloudflare WAF": ["cloudflare"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "Radware": ["radware", "appwall"],
}

_HOSTING_PATTERNS = {
    "AWS": ["amazonaws.com", "aws", "x-amz"],
    "Azure": ["azure", "microsoft", "msedge", "windows.net"],
    "Google Cloud": ["google", "gcp", "googleapis"],
    "NIC India": ["nic.in", "gov.in", "nicsi"],
    "CtrlS": ["ctrls"],
    "Netmagic/NTT": ["netmagic", "ntt"],
    "Tata Communications": ["tatacommunications", "tatacomm"],
    "BSNL": ["bsnl"],
    "Sify": ["sify"],
}


@timed(service="crypto_inspector")
def detect_hosting_and_cdn(hostname: str, port: int = 443) -> dict:
    """
    Detect hosting provider, CDN, and WAF from HTTP response headers.

    Per 02-OUTPUTS.md Module 1.1: "Hosting Entity", "Internet-Exposed",
    "TLS Termination Point".
    """
    result = {
        "hosting_provider": None,
        "cdn_detected": None,
        "waf_detected": None,
        "server_header": None,
        "via_header": None,
        "powered_by": None,
        "is_behind_proxy": False,
        "http2_supported": False,
        "response_headers_raw": {},
    }

    try:
        # Try HTTP/2 first, fall back to HTTP/1.1
        try:
            client = httpx.Client(verify=False, timeout=10.0, http2=True)
        except Exception:
            client = httpx.Client(verify=False, timeout=10.0)
        with client:
            resp = client.get(f"https://{hostname}:{port}", follow_redirects=True)
            headers = dict(resp.headers)

            result["server_header"] = headers.get("server")
            result["via_header"] = headers.get("via")
            result["powered_by"] = headers.get("x-powered-by")
            result["http2_supported"] = str(resp.http_version) == "HTTP/2"

            # Store key headers for analysis
            for key in headers:
                k = key.lower()
                if any(x in k for x in ["server", "via", "x-", "cf-", "ak-", "set-cookie"]):
                    result["response_headers_raw"][key] = headers[key]

            # Combine all header values for pattern matching
            all_values = " ".join(str(v).lower() for v in headers.values())
            all_keys = " ".join(k.lower() for k in headers.keys())
            search_text = all_values + " " + all_keys

            # Detect CDN
            for cdn_name, patterns in _CDN_PATTERNS.items():
                if any(p in search_text for p in patterns):
                    result["cdn_detected"] = cdn_name
                    result["is_behind_proxy"] = True
                    break

            # Detect WAF
            for waf_name, patterns in _WAF_PATTERNS.items():
                if any(p in search_text for p in patterns):
                    result["waf_detected"] = waf_name
                    break

            # Detect hosting provider
            for host_name, patterns in _HOSTING_PATTERNS.items():
                if any(p in search_text for p in patterns):
                    result["hosting_provider"] = host_name
                    break

            # Fallback: use server header for hosting detection
            if not result["hosting_provider"] and result["server_header"]:
                server = result["server_header"].lower()
                if "nginx" in server:
                    result["hosting_provider"] = "Self-hosted (nginx)"
                elif "apache" in server:
                    result["hosting_provider"] = "Self-hosted (Apache)"
                elif "iis" in server:
                    result["hosting_provider"] = "Self-hosted (IIS)"

    except Exception as e:
        logger.debug(f"Hosting/CDN detection failed for {hostname}: {e}")

    logger.debug(
        f"Infrastructure fingerprint for {hostname}",
        extra={
            "hosting": result["hosting_provider"],
            "cdn": result["cdn_detected"],
            "waf": result["waf_detected"],
            "http2": result["http2_supported"],
        },
    )

    return result


# ─── Asset Type Classification ──────────────────────────────────────────────

# Keywords for asset type classification from hostname patterns
_ASSET_TYPE_PATTERNS = {
    "internet_banking": ["netbanking", "onlinebanking", "ibanking", "ebanking", "online", "retail"],
    "mobile_banking": ["mobile", "mbanking", "app", "mobilebanking"],
    "upi_gateway": ["upi", "npci", "imps", "bhim"],
    "swift_endpoint": ["swift", "fin", "stp"],
    "api_gateway": ["api", "gateway", "connect", "integration", "middleware"],
    "payment_gateway": ["pay", "payment", "pg", "merchant", "checkout"],
    "corporate_banking": ["corporate", "corp", "wholesale", "b2b", "trade"],
    "admin_portal": ["admin", "manage", "mgmt", "cms", "internal"],
    "mail_server": ["mail", "smtp", "mx", "exchange", "webmail"],
    "dns_server": ["ns1", "ns2", "ns3", "dns"],
    "cdn_edge": ["cdn", "static", "assets", "media", "img"],
    "cbs_interface": ["finacle", "bancs", "flexcube", "cbs"],
}


def classify_asset_type(hostname: str, ports: list | None = None) -> str:
    """
    Classify an asset's type based on hostname patterns and open ports.

    Returns asset type string for persistence to Asset model.
    Per 02-OUTPUTS.md Module 1.1: "Asset Class".
    """
    hostname_lower = hostname.lower()

    # Check hostname patterns
    for asset_type, patterns in _ASSET_TYPE_PATTERNS.items():
        if any(p in hostname_lower for p in patterns):
            return asset_type

    # Port-based heuristics
    if ports:
        port_nums = [p.get("port") if isinstance(p, dict) else p for p in ports]
        if 25 in port_nums or 587 in port_nums:
            return "mail_server"
        if 53 in port_nums:
            return "dns_server"

    # Default: if it's www or root domain with 443
    if hostname_lower.startswith("www.") or "." not in hostname_lower.split(".", 1)[-1].split(".")[0]:
        return "internet_banking"

    return "web_server"


# ─── P2.6: Combined Full Crypto Inspection ──────────────────────────────────


@timed(service="crypto_inspector")
def inspect_asset(hostname: str, port: int = 443) -> dict:
    """
    Full cryptographic inspection of a single asset.

    Runs: TLS scan → cert chain parse → quantum level assignment → PQC detection → auth fingerprint.
    Returns unified CryptoFingerprint dict.
    """
    fingerprint = {
        "hostname": hostname,
        "port": port,
        "tls": None,
        "certificates": [],
        "pqc": None,
        "auth": None,
        "cert_intelligence": None,
        "pinning": None,
        "infrastructure": None,
        "asset_type": None,
        "quantum_summary": {
            "lowest_nist_level": -1,
            "has_vulnerable_crypto": True,
            "has_pqc": False,
            "vulnerable_algorithms": [],
            "safe_algorithms": [],
        },
        "error": None,
    }

    # Step 1: TLS scan
    tls_result = {}  # ensure tls_result is always defined
    try:
        tls_result = scan_tls(hostname, port)
        fingerprint["tls"] = {
            "versions_supported": tls_result["tls_versions_supported"],
            "cipher_suites": tls_result["cipher_suites"],
            "negotiated_cipher": tls_result["negotiated_cipher"],
            "negotiated_protocol": tls_result["negotiated_protocol"],
            "key_exchange": tls_result["key_exchange"],
            "forward_secrecy": tls_result["forward_secrecy"],
        }
    except Exception as e:
        fingerprint["error"] = f"TLS scan failed: {e}"
        logger.error(f"TLS scan failed for {hostname}: {e}")

    # Step 2: Certificate chain parsing
    if tls_result.get("certificate_chain_pem"):
        try:
            chain = parse_certificate_chain(tls_result["certificate_chain_pem"])
            fingerprint["certificates"] = chain
        except Exception as e:
            logger.error(f"Cert chain parse failed for {hostname}: {e}")

    # Step 3: NIST quantum level for each cipher & cert
    vuln_algos = []
    safe_algos = []
    all_levels = []

    for cs in fingerprint.get("tls", {}).get("cipher_suites", []):
        level = get_nist_quantum_level(cs["name"])
        cs["quantum"] = level
        if level["is_quantum_vulnerable"]:
            vuln_algos.append(cs["name"])
        else:
            safe_algos.append(cs["name"])
        if level["nist_level"] >= 0:
            all_levels.append(level["nist_level"])

    for cert in fingerprint.get("certificates", []):
        level = get_nist_quantum_level(cert["key_type"], cert.get("key_length"))
        cert["quantum"] = level
        if level["is_quantum_vulnerable"]:
            vuln_algos.append(f"{cert['key_type']}-{cert.get('key_length', '?')}")
        else:
            safe_algos.append(f"{cert['key_type']}-{cert.get('key_length', '?')}")
        if level["nist_level"] >= 0:
            all_levels.append(level["nist_level"])

    fingerprint["quantum_summary"]["vulnerable_algorithms"] = list(set(vuln_algos))
    fingerprint["quantum_summary"]["safe_algorithms"] = list(set(safe_algos))
    fingerprint["quantum_summary"]["lowest_nist_level"] = min(all_levels) if all_levels else -1
    fingerprint["quantum_summary"]["has_vulnerable_crypto"] = len(vuln_algos) > 0

    # Step 4: PQC detection
    try:
        pqc_result = detect_pqc(hostname, port)
        fingerprint["pqc"] = pqc_result
        fingerprint["quantum_summary"]["has_pqc"] = pqc_result["pqc_signature"] or pqc_result["pqc_key_exchange"]
    except Exception as e:
        logger.error(f"PQC detection failed for {hostname}: {e}")

    # Step 5: API auth fingerprinting
    try:
        url = f"https://{hostname}"
        auth_result = detect_api_auth(url)
        fingerprint["auth"] = auth_result
    except Exception as e:
        logger.debug(f"Auth detection skipped for {hostname}: {e}")

    # Step 6: Certificate intelligence enhancements
    cert_intel = []
    for cert in fingerprint.get("certificates", []):
        intel = {}
        # Effective security expiry (CRQC-adjusted)
        if cert.get("valid_to"):
            valid_to_dt = datetime.fromisoformat(cert["valid_to"]) if isinstance(cert["valid_to"], str) else cert["valid_to"]
            intel["effective_expiry"] = compute_effective_security_expiry(
                valid_to_dt, cert.get("key_type", "RSA"), cert.get("key_length")
            )
        # CA PQC readiness
        intel["ca_readiness"] = lookup_ca_pqc_readiness(cert.get("ca_name") or cert.get("issuer"))
        # Multi-SAN exposure
        intel["san_exposure"] = analyze_multi_san_exposure(cert.get("san_list"))
        cert_intel.append(intel)
    fingerprint["cert_intelligence"] = cert_intel

    # Step 7: Certificate pinning detection
    try:
        fingerprint["pinning"] = detect_certificate_pinning(hostname, port)
    except Exception as e:
        logger.debug(f"Pinning detection skipped for {hostname}: {e}")

    # Step 8: Infrastructure fingerprinting (hosting, CDN, WAF)
    try:
        fingerprint["infrastructure"] = detect_hosting_and_cdn(hostname, port)
    except Exception as e:
        logger.debug(f"Infrastructure detection skipped for {hostname}: {e}")

    # Step 9: Asset type classification
    fingerprint["asset_type"] = classify_asset_type(hostname)

    logger.info(
        f"Crypto inspection complete for {hostname}",
        extra={
            "hostname": hostname,
            "tls_versions": fingerprint.get("tls", {}).get("versions_supported", []),
            "cert_count": len(fingerprint["certificates"]),
            "vulnerable_algos": len(vuln_algos),
            "safe_algos": len(safe_algos),
            "has_pqc": fingerprint["quantum_summary"]["has_pqc"],
            "asset_type": fingerprint["asset_type"],
            "cdn": (fingerprint.get("infrastructure") or {}).get("cdn_detected"),
            "hosting": (fingerprint.get("infrastructure") or {}).get("hosting_provider"),
        },
    )

    return fingerprint


def inspect_assets_batch(
    assets: list[dict],
    max_concurrent: int = 10,
) -> list[dict]:
    """
    Inspect multiple assets concurrently.

    Args:
        assets: List of dicts with at least "hostname" key
        max_concurrent: Max concurrent scans

    Returns:
        List of CryptoFingerprint dicts (None for failed assets)
    """
    results = [None] * len(assets)

    with ThreadPoolExecutor(max_workers=max_concurrent) as pool:
        future_to_idx = {}
        for i, asset in enumerate(assets):
            hostname = asset.get("hostname", "")
            port = asset.get("port", 443)
            future = pool.submit(inspect_asset, hostname, port)
            future_to_idx[future] = i

        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            hostname = assets[idx].get("hostname", "?")
            try:
                results[idx] = future.result()
                logger.info(f"[{idx+1}/{len(assets)}] Inspected {hostname}")
            except Exception as e:
                logger.error(f"[{idx+1}/{len(assets)}] Failed {hostname}: {e}")
                results[idx] = {"hostname": hostname, "error": str(e)}

    return results


# ─── P2.7: Persistence ──────────────────────────────────────────────────────


@timed(service="crypto_inspector")
def save_crypto_results(
    scan_id: str,
    asset_id: str,
    fingerprint: dict,
    db,
) -> list:
    """
    Save crypto inspection results to the database.

    Creates Certificate records for each cert in the chain.
    Updates the Asset record with TLS version info.
    """
    import uuid
    from app.models.certificate import Certificate
    from app.models.asset import Asset

    saved_certs = []

    # Get cert intelligence data for cross-referencing
    cert_intel_list = fingerprint.get("cert_intelligence") or []
    pinning_data = fingerprint.get("pinning") or {}

    # Save certificates
    for i, cert_data in enumerate(fingerprint.get("certificates", [])):
        # Cross-reference cert intelligence data
        cert_intel = cert_intel_list[i] if i < len(cert_intel_list) else {}
        effective_expiry_info = cert_intel.get("effective_expiry", {})
        ca_readiness = cert_intel.get("ca_readiness", {})
        san_exposure = cert_intel.get("san_exposure", {})

        # Parse effective_security_expiry datetime
        effective_expiry_dt = None
        if effective_expiry_info.get("effective_expiry"):
            try:
                effective_expiry_dt = datetime.fromisoformat(effective_expiry_info["effective_expiry"])
            except (ValueError, TypeError):
                pass

        cert = Certificate(
            asset_id=uuid.UUID(asset_id) if isinstance(asset_id, str) else asset_id,
            scan_id=uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id,
            common_name=cert_data.get("common_name"),
            san_list=cert_data.get("san_list"),
            issuer=cert_data.get("issuer"),
            ca_name=cert_data.get("ca_name"),
            key_type=cert_data.get("key_type"),
            key_length=cert_data.get("key_length"),
            signature_algorithm=cert_data.get("signature_algorithm"),
            signature_algorithm_oid=cert_data.get("signature_algorithm_oid"),
            valid_from=datetime.fromisoformat(cert_data["valid_from"]) if cert_data.get("valid_from") else None,
            valid_to=datetime.fromisoformat(cert_data["valid_to"]) if cert_data.get("valid_to") else None,
            sha256_fingerprint=cert_data.get("sha256_fingerprint"),
            is_ct_logged=cert_data.get("is_ct_logged", False),
            nist_quantum_level=cert_data.get("quantum", {}).get("nist_level", -1),
            is_quantum_vulnerable=cert_data.get("quantum", {}).get("is_quantum_vulnerable", True),
            chain_depth=cert_data.get("chain_depth", 0),
            chain_valid=cert_data.get("chain_valid"),
            forward_secrecy=fingerprint.get("tls", {}).get("forward_secrecy"),
            negotiated_cipher=fingerprint.get("tls", {}).get("negotiated_cipher"),
            tls_version=fingerprint.get("tls", {}).get("negotiated_protocol"),
            # New cert intelligence fields
            effective_security_expiry=effective_expiry_dt,
            ca_pqc_ready=ca_readiness.get("pqc_roadmap_published", False),
            san_count=san_exposure.get("san_count", 1),
            is_pinned=pinning_data.get("is_pinned", False),
        )
        db.add(cert)
        saved_certs.append(cert)

    # Update asset with TLS + infrastructure info
    asset = db.query(Asset).filter(
        Asset.id == (uuid.UUID(asset_id) if isinstance(asset_id, str) else asset_id)
    ).first()
    if asset:
        tls_data = fingerprint.get("tls", {})
        asset.tls_version = tls_data.get("negotiated_protocol")

        # Infrastructure enrichment
        infra = fingerprint.get("infrastructure") or {}
        if infra.get("hosting_provider"):
            asset.hosting_provider = infra["hosting_provider"]
        if infra.get("cdn_detected"):
            asset.cdn_detected = infra["cdn_detected"]
        if infra.get("waf_detected"):
            asset.waf_detected = infra["waf_detected"]
        if infra.get("server_header"):
            asset.web_server = infra["server_header"]

        # Asset type classification
        if fingerprint.get("asset_type"):
            asset.asset_type = fingerprint["asset_type"]

    db.commit()

    logger.info(
        f"Saved {len(saved_certs)} certificates for asset {asset_id}",
        extra={
            "scan_id": scan_id,
            "asset_id": asset_id,
            "certs_saved": len(saved_certs),
        },
    )

    return saved_certs
