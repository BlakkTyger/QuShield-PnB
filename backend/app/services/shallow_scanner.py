"""
Shallow Scanner — DNS/CT discovery + top-N TLS crypto analysis in 30–90 seconds.

Uses crt.sh (Certificate Transparency) + DNS resolution for subdomain discovery.
No Go binary, no port scanning, no SSLyze, no pinning/auth/CDN detection.
Scans top-N subdomains using stdlib ssl for fast TLS + cert analysis.
"""
import ssl
import socket
import time
import hashlib
import json
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

import httpx

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from app.core.logging import get_logger
from app.services.crypto_inspector import (
    get_nist_quantum_level,
    parse_certificate_chain,
    classify_asset_type,
    NIST_LEVELS,
)
from app.services.risk_engine import (
    compute_mosca,
    MIGRATION_TIME_DEFAULTS,
    SHELF_LIFE_DEFAULTS,
    _classify_risk,
)



logger = get_logger("shallow_scanner")

# Maximum subdomains to scan via TLS
DEFAULT_TOP_N = 10
CRT_SH_TIMEOUT = 8
DNS_TIMEOUT = 3
TLS_TIMEOUT = 8


# ─── Discovery: crt.sh + DNS ────────────────────────────────────────────────

def discover_subdomains_ct(domain: str, timeout: int = CRT_SH_TIMEOUT) -> list[str]:
    """
    Discover subdomains via Certificate Transparency logs (crt.sh).

    Returns deduplicated list of subdomains.
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        with httpx.Client(timeout=timeout, verify=True) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                entries = resp.json()
                for entry in entries:
                    name = entry.get("name_value", "")
                    # crt.sh returns newline-separated names for multi-SAN certs
                    for n in name.split("\n"):
                        n = n.strip().lower()
                        if n and n.endswith(f".{domain}") or n == domain:
                            # Skip wildcards
                            if not n.startswith("*"):
                                subdomains.add(n)
            else:
                logger.warning(f"crt.sh returned {resp.status_code} for {domain}")
    except Exception as e:
        logger.warning(f"crt.sh query failed for {domain}: {e}")

    # Always include root domain
    subdomains.add(domain)

    logger.info(f"CT discovery for {domain}: {len(subdomains)} unique subdomains")
    return sorted(subdomains)


# Common banking subdomain prefixes for brute-force fallback
_COMMON_PREFIXES = [
    "www", "mail", "webmail", "remote", "vpn", "owa", "autodiscover",
    "ftp", "api", "cdn", "m", "mobile", "app", "portal", "secure",
    "login", "sso", "auth", "gateway", "ns1", "ns2", "ns3", "ns4",
    "dns", "mx", "smtp", "imap", "pop", "relay",
    "netbanking", "onlinebanking", "ebanking", "inet", "internet",
    "corporate", "retail", "treasury", "swift", "neft", "rtgs",
    "upi", "bhim", "imps", "cms", "trade", "forex",
    "digitallending", "home", "blog", "careers", "support",
    "dev", "staging", "test", "uat", "sandbox",
]


def discover_subdomains_brute(domain: str) -> list[str]:
    """
    Discover subdomains via DNS brute-force with common banking prefixes.
    Fallback when crt.sh is unavailable or returns limited results.
    """
    candidates = [f"{prefix}.{domain}" for prefix in _COMMON_PREFIXES]
    candidates.append(domain)
    return candidates


def discover_subdomains(domain: str, ct_timeout: int = CRT_SH_TIMEOUT) -> list[str]:
    """
    Combined subdomain discovery: crt.sh CT logs + DNS brute-force fallback.
    """
    ct_subs = discover_subdomains_ct(domain, ct_timeout)

    # If CT returned very few results, supplement with brute-force
    if len(ct_subs) < 5:
        logger.info(f"CT returned only {len(ct_subs)} subdomains, adding brute-force prefixes")
        brute_subs = discover_subdomains_brute(domain)
        combined = set(ct_subs) | set(brute_subs)
        logger.info(f"Combined discovery: {len(combined)} candidates for {domain}")
        return sorted(combined)

    return ct_subs


def resolve_dns(hostname: str, timeout: float = DNS_TIMEOUT) -> Optional[str]:
    """Resolve hostname to IP. Returns IP or None if unresolvable."""
    try:
        socket.setdefaulttimeout(timeout)
        ip = socket.gethostbyname(hostname)
        return ip
    except (socket.gaierror, socket.timeout, OSError):
        return None


def resolve_subdomains_parallel(
    subdomains: list[str], max_workers: int = 20
) -> list[dict]:
    """
    Resolve all subdomains in parallel. Returns list of {hostname, ip} for live ones.
    """
    live = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {pool.submit(resolve_dns, h): h for h in subdomains}
        for future in as_completed(future_map):
            hostname = future_map[future]
            try:
                ip = future.result()
                if ip:
                    live.append({"hostname": hostname, "ip": ip})
            except Exception:
                pass

    logger.info(f"DNS resolution: {len(live)}/{len(subdomains)} subdomains are live")
    return live


# ─── Lightweight TLS Scan ────────────────────────────────────────────────────

def _scan_tls_light(hostname: str, port: int = 443, timeout: int = TLS_TIMEOUT) -> dict:
    """
    Lightweight TLS scan using stdlib ssl only.
    Returns TLS data + raw cert PEM for parsing.
    """
    result = {
        "hostname": hostname,
        "port": port,
        "tls": None,
        "cert_pem": None,
        "error": None,
    }

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher_info = ssock.cipher()
                tls_version = ssock.version()

                negotiated_cipher = cipher_info[0] if cipher_info else None
                negotiated_protocol = cipher_info[1] if cipher_info else None

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
                        forward_secrecy = True
                        key_exchange = "ECDHE"

                cipher_suites = []
                shared = ssock.shared_ciphers()
                if shared:
                    for c in shared:
                        cipher_suites.append({
                            "name": c[0],
                            "tls_version": c[1],
                            "key_size": c[2],
                        })
                elif negotiated_cipher:
                    cipher_suites.append({
                        "name": negotiated_cipher,
                        "tls_version": tls_version,
                        "key_size": None,
                    })

                result["tls"] = {
                    "negotiated_protocol": tls_version or negotiated_protocol,
                    "negotiated_cipher": negotiated_cipher,
                    "key_exchange": key_exchange,
                    "forward_secrecy": forward_secrecy,
                    "cipher_suites": cipher_suites,
                }

                # Get cert
                cert_bin = ssock.getpeercert(binary_form=True)
                if cert_bin:
                    cert_obj = x509.load_der_x509_certificate(cert_bin)
                    pem = cert_obj.public_bytes(serialization.Encoding.PEM)
                    result["cert_pem"] = pem

    except Exception as e:
        result["error"] = str(e)

    return result


# ─── Per-Asset Analysis ──────────────────────────────────────────────────────

def _analyze_asset(hostname: str, ip: str, port: int = 443) -> dict:
    """
    Full shallow analysis of a single asset: TLS + cert + quantum + risk + compliance.
    """
    asset = {
        "hostname": hostname,
        "ip": ip,
        "port": port,
        "tls": None,
        "certificate": None,
        "quantum_assessment": None,
        "risk": None,
        "compliance": None,
        "error": None,
    }

    # TLS scan
    scan_result = _scan_tls_light(hostname, port)
    if scan_result["error"]:
        asset["error"] = scan_result["error"]
        return asset

    asset["tls"] = scan_result["tls"]

    # Parse certificate
    cert_info = None
    if scan_result["cert_pem"]:
        try:
            chain = parse_certificate_chain([scan_result["cert_pem"]])
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
                    "san_count": len(leaf.get("san_list", [])),
                    "chain_valid": leaf.get("chain_valid"),
                    "sha256_fingerprint": leaf.get("sha256_fingerprint"),
                }
                if leaf.get("valid_to"):
                    try:
                        expiry = datetime.fromisoformat(leaf["valid_to"])
                        if expiry.tzinfo is None:
                            expiry = expiry.replace(tzinfo=timezone.utc)
                        cert_info["days_until_expiry"] = (expiry - datetime.now(timezone.utc)).days
                    except (ValueError, TypeError):
                        pass
        except Exception as e:
            logger.debug(f"Cert parse failed for {hostname}: {e}")

    asset["certificate"] = cert_info

    # NIST quantum assessment
    tls_data = scan_result["tls"] or {}
    vuln_algos = []
    safe_algos = []

    for cs in tls_data.get("cipher_suites", []):
        level = get_nist_quantum_level(cs["name"])
        if level["is_quantum_vulnerable"]:
            vuln_algos.append(cs["name"])
        else:
            safe_algos.append(cs["name"])

    if cert_info:
        cert_level = get_nist_quantum_level(
            cert_info.get("key_type", "RSA"),
            cert_info.get("key_length"),
        )
        if cert_level["is_quantum_vulnerable"]:
            vuln_algos.append(f"{cert_info['key_type']}-{cert_info.get('key_length', '?')}")
        else:
            safe_algos.append(f"{cert_info['key_type']}-{cert_info.get('key_length', '?')}")

    asset["quantum_assessment"] = {
        "is_quantum_vulnerable": len(vuln_algos) > 0,
        "vulnerable_count": len(set(vuln_algos)),
        "safe_count": len(set(safe_algos)),
    }

    # Risk (Mosca)
    asset_type = classify_asset_type(hostname)
    migration_time = MIGRATION_TIME_DEFAULTS.get(asset_type, 1.5)
    shelf_life = SHELF_LIFE_DEFAULTS.get(asset_type, {}).get("shelf_life_years", 5.0)
    mosca = compute_mosca(migration_time, shelf_life)

    risk_points = 0
    if len(vuln_algos) > 0:
        risk_points += 300
    if mosca["exposed_pessimistic"]:
        risk_points += 150
        if mosca["exposed_median"]:
            risk_points += 50
            if mosca["exposed_optimistic"]:
                risk_points += 50
    is_tls13 = "1.3" in (tls_data.get("negotiated_protocol") or "")
    risk_points += 75 if is_tls13 else 150
    if not tls_data.get("forward_secrecy"):
        risk_points += 100
    risk_points = min(risk_points, 1000)

    asset["risk"] = {
        "score": risk_points,
        "classification": _classify_risk(risk_points),
        "asset_type": asset_type,
        "mosca_exposed": mosca["exposed_pessimistic"],
    }

    # Compliance snapshot
    proto = tls_data.get("negotiated_protocol") or ""
    fs = tls_data.get("forward_secrecy", False)
    key_ok = (cert_info.get("key_length") or 0) >= 2048 if cert_info else False
    asset["compliance"] = {
        "tls_1_3": "1.3" in proto,
        "forward_secrecy": fs,
        "pci_compliant": "1.3" in proto or "1.2" in proto,
        "sebi_compliant": "1.3" in proto and key_ok,
        "rbi_compliant": fs,
    }

    return asset


# ─── Main Shallow Scan ──────────────────────────────────────────────────────

def shallow_scan(
    domain: str,
    top_n: int = DEFAULT_TOP_N,
    port: int = 443,
    max_workers: int = 10,
) -> dict:
    """
    Perform a shallow scan: CT discovery + DNS resolution + TLS analysis on top-N subdomains.

    Args:
        domain: Root domain to scan
        top_n: Maximum subdomains to TLS-scan (default 10)
        port: TLS port
        max_workers: Concurrent TLS scans

    Returns:
        Complete shallow scan result with discovery + per-asset analysis + summary.
    """
    start_time = time.time()

    result = {
        "domain": domain,
        "scan_type": "shallow",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "discovery": None,
        "assets": [],
        "summary": None,
        "duration_ms": 0,
        "error": None,
    }

    # Phase 1: Subdomain discovery (CT + brute-force fallback)
    logger.info(f"[shallow] Phase 1: Subdomain discovery for {domain}")
    t0 = time.time()
    subdomains = discover_subdomains(domain)
    discovery_ms = round((time.time() - t0) * 1000, 1)

    # Phase 2: DNS resolution
    logger.info(f"[shallow] Phase 2: DNS resolution for {len(subdomains)} subdomains")
    t0 = time.time()
    live_assets = resolve_subdomains_parallel(subdomains)
    dns_ms = round((time.time() - t0) * 1000, 1)

    result["discovery"] = {
        "total_subdomains_found": len(subdomains),
        "live_subdomains": len(live_assets),
        "discovery_ms": discovery_ms,
        "dns_resolution_ms": dns_ms,
        "scanned_count": min(top_n, len(live_assets)),
    }

    if not live_assets:
        result["error"] = f"No live subdomains found for {domain}"
        result["duration_ms"] = round((time.time() - start_time) * 1000, 1)
        return result

    # Phase 3: TLS scan top-N subdomains
    scan_targets = live_assets[:top_n]
    logger.info(f"[shallow] Phase 3: TLS scan on {len(scan_targets)} subdomains")
    t0 = time.time()

    assets_results = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_analyze_asset, a["hostname"], a["ip"], port): a
            for a in scan_targets
        }
        for future in as_completed(futures):
            target = futures[future]
            try:
                asset_result = future.result()
                assets_results.append(asset_result)
            except Exception as e:
                logger.error(f"Shallow scan failed for {target['hostname']}: {e}")
                assets_results.append({
                    "hostname": target["hostname"],
                    "ip": target["ip"],
                    "error": str(e),
                })

    tls_ms = round((time.time() - t0) * 1000, 1)

    # Sort by risk score (highest first)
    assets_results.sort(
        key=lambda a: a.get("risk", {}).get("score", 0) if a.get("risk") else 0,
        reverse=True,
    )
    result["assets"] = assets_results

    # Summary
    successful = [a for a in assets_results if a.get("tls") and not a.get("error")]
    vulnerable = [a for a in successful if a.get("quantum_assessment", {}).get("is_quantum_vulnerable")]
    tls13_count = sum(1 for a in successful if a.get("compliance", {}).get("tls_1_3"))
    fs_count = sum(1 for a in successful if a.get("compliance", {}).get("forward_secrecy"))

    risk_scores = [a["risk"]["score"] for a in successful if a.get("risk")]
    avg_risk = round(sum(risk_scores) / max(len(risk_scores), 1), 1)

    result["summary"] = {
        "total_subdomains_discovered": len(subdomains),
        "live_subdomains": len(live_assets),
        "scanned": len(scan_targets),
        "successful_scans": len(successful),
        "failed_scans": len(scan_targets) - len(successful),
        "quantum_vulnerable": len(vulnerable),
        "tls_1_3_count": tls13_count,
        "forward_secrecy_count": fs_count,
        "avg_risk_score": avg_risk,
        "avg_risk_classification": _classify_risk(int(avg_risk)),
        "timing": {
            "discovery_ms": discovery_ms,
            "dns_ms": dns_ms,
            "tls_scan_ms": tls_ms,
        },
    }

    result["duration_ms"] = round((time.time() - start_time) * 1000, 1)

    logger.info(
        f"Shallow scan complete for {domain}: {len(successful)} assets in {result['duration_ms']:.0f}ms",
        extra={
            "domain": domain,
            "subdomains": len(subdomains),
            "scanned": len(scan_targets),
            "vulnerable": len(vulnerable),
            "avg_risk": avg_risk,
        },
    )

    return result
