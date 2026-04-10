"""
CBOM Builder — CycloneDX 1.6 Cryptographic Bill of Materials generator.

Transforms crypto inspection results into standards-compliant CycloneDX CBOMs
with full NIST quantum security level annotations.
"""
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cyclonedx.model.bom import Bom
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoMode,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesCipherSuite,
    ProtocolPropertiesType,
)
from cyclonedx.model.dependency import Dependency
from cyclonedx.output.json import JsonV1Dot6

from app.config import settings, PROJECT_ROOT
from app.core.logging import get_logger
from app.core.timing import timed

logger = get_logger("cbom_builder")


# ─── Algorithm Classification Tables ────────────────────────────────────────

# Map cipher suite name patterns → (CryptoPrimitive, key_size_str, mode)
_ALGO_CLASSIFICATION = {
    "AES-256-GCM": (CryptoPrimitive.BLOCK_CIPHER, "256", CryptoFunction.ENCRYPT),
    "AES-128-GCM": (CryptoPrimitive.BLOCK_CIPHER, "128", CryptoFunction.ENCRYPT),
    "AES-256-CBC": (CryptoPrimitive.BLOCK_CIPHER, "256", CryptoFunction.ENCRYPT),
    "AES-128-CBC": (CryptoPrimitive.BLOCK_CIPHER, "128", CryptoFunction.ENCRYPT),
    "ChaCha20-Poly1305": (CryptoPrimitive.STREAM_CIPHER, "256", CryptoFunction.ENCRYPT),
    "3DES-CBC": (CryptoPrimitive.BLOCK_CIPHER, "168", CryptoFunction.ENCRYPT),
    "RC4": (CryptoPrimitive.STREAM_CIPHER, "128", CryptoFunction.ENCRYPT),
    "RSA": (CryptoPrimitive.PKE, None, CryptoFunction.ENCRYPT),
    "ECDHE": (CryptoPrimitive.KEY_AGREE, None, CryptoFunction.KEYGEN),
    "DHE": (CryptoPrimitive.KEY_AGREE, None, CryptoFunction.KEYGEN),
    "ECDSA": (CryptoPrimitive.SIGNATURE, None, CryptoFunction.SIGN),
    "Ed25519": (CryptoPrimitive.SIGNATURE, "256", CryptoFunction.SIGN),
    "SHA-256": (CryptoPrimitive.HASH, "256", CryptoFunction.DIGEST),
    "SHA-384": (CryptoPrimitive.HASH, "384", CryptoFunction.DIGEST),
    "SHA-512": (CryptoPrimitive.HASH, "512", CryptoFunction.DIGEST),
    "ML-KEM": (CryptoPrimitive.KEM, None, CryptoFunction.ENCAPSULATE),
    "ML-DSA": (CryptoPrimitive.SIGNATURE, None, CryptoFunction.SIGN),
}


def _classify_algorithm(name: str) -> tuple:
    """Classify a cipher/algorithm name into CycloneDX crypto primitives."""
    name_upper = name.upper()
    for pattern, classification in _ALGO_CLASSIFICATION.items():
        if pattern.upper() in name_upper:
            return classification
    return (CryptoPrimitive.UNKNOWN, None, CryptoFunction.UNKNOWN)


def _get_nist_level_for_component(algo_name: str, quantum_data: dict = None) -> Optional[int]:
    """Get NIST quantum security level, using pre-computed quantum data if available."""
    if quantum_data and quantum_data.get("nist_level", -1) >= 0:
        return quantum_data["nist_level"]
    # Fallback: call the quantum level function
    from app.services.crypto_inspector import get_nist_quantum_level
    result = get_nist_quantum_level(algo_name)
    if result["nist_level"] >= 0:
        return result["nist_level"]
    return None


# ─── Cipher Suite Decomposition ──────────────────────────────────────────────

# TLS 1.3 cipher suites: name only encodes symmetric + MAC.
# Key exchange comes from supported_groups, auth from certificate.
_TLS13_DECOMP = {
    "TLS_AES_256_GCM_SHA384":       {"symmetric": "AES-256-GCM",      "mac": "SHA-384"},
    "TLS_AES_128_GCM_SHA256":       {"symmetric": "AES-128-GCM",      "mac": "SHA-256"},
    "TLS_CHACHA20_POLY1305_SHA256": {"symmetric": "ChaCha20-Poly1305", "mac": "SHA-256"},
    "TLS_AES_128_CCM_SHA256":       {"symmetric": "AES-128-CCM",      "mac": "SHA-256"},
    "TLS_AES_128_CCM_8_SHA256":     {"symmetric": "AES-128-CCM-8",    "mac": "SHA-256"},
}

# TLS 1.2 cipher suites: fully decomposable from name.
# Format: {KE}(-{AUTH})?-WITH-{SYMMETRIC}-{MAC}  or OpenSSL format
_TLS12_PATTERNS = {
    # OpenSSL names (most common)
    "ECDHE-RSA-AES256-GCM-SHA384":    {"key_exchange": "ECDHE", "authentication": "RSA",   "symmetric": "AES-256-GCM",      "mac": "SHA-384"},
    "ECDHE-RSA-AES128-GCM-SHA256":    {"key_exchange": "ECDHE", "authentication": "RSA",   "symmetric": "AES-128-GCM",      "mac": "SHA-256"},
    "ECDHE-ECDSA-AES256-GCM-SHA384":  {"key_exchange": "ECDHE", "authentication": "ECDSA", "symmetric": "AES-256-GCM",      "mac": "SHA-384"},
    "ECDHE-ECDSA-AES128-GCM-SHA256":  {"key_exchange": "ECDHE", "authentication": "ECDSA", "symmetric": "AES-128-GCM",      "mac": "SHA-256"},
    "ECDHE-RSA-CHACHA20-POLY1305":    {"key_exchange": "ECDHE", "authentication": "RSA",   "symmetric": "ChaCha20-Poly1305", "mac": "AEAD"},
    "ECDHE-ECDSA-CHACHA20-POLY1305":  {"key_exchange": "ECDHE", "authentication": "ECDSA", "symmetric": "ChaCha20-Poly1305", "mac": "AEAD"},
    "ECDHE-RSA-AES256-SHA384":        {"key_exchange": "ECDHE", "authentication": "RSA",   "symmetric": "AES-256-CBC",      "mac": "SHA-384"},
    "ECDHE-RSA-AES128-SHA256":        {"key_exchange": "ECDHE", "authentication": "RSA",   "symmetric": "AES-128-CBC",      "mac": "SHA-256"},
    "DHE-RSA-AES256-GCM-SHA384":      {"key_exchange": "DHE",   "authentication": "RSA",   "symmetric": "AES-256-GCM",      "mac": "SHA-384"},
    "DHE-RSA-AES128-GCM-SHA256":      {"key_exchange": "DHE",   "authentication": "RSA",   "symmetric": "AES-128-GCM",      "mac": "SHA-256"},
    "AES256-GCM-SHA384":              {"key_exchange": "RSA",   "authentication": "RSA",   "symmetric": "AES-256-GCM",      "mac": "SHA-384"},
    "AES128-GCM-SHA256":              {"key_exchange": "RSA",   "authentication": "RSA",   "symmetric": "AES-128-GCM",      "mac": "SHA-256"},
    "DES-CBC3-SHA":                   {"key_exchange": "RSA",   "authentication": "RSA",   "symmetric": "3DES-CBC",         "mac": "SHA-1"},
    "RC4-SHA":                        {"key_exchange": "RSA",   "authentication": "RSA",   "symmetric": "RC4",              "mac": "SHA-1"},
}


def decompose_cipher_suite(
    cipher_name: str,
    key_exchange_hint: str = None,
    cert_key_type: str = None,
) -> dict:
    """
    Decompose a TLS cipher suite name into its constituent components.

    TLS 1.3: symmetric + MAC from name; KE from supported_groups hint; auth from cert.
    TLS 1.2: fully decomposable from the cipher suite name.

    Args:
        cipher_name: Full cipher suite name (e.g., "TLS_AES_256_GCM_SHA384")
        key_exchange_hint: KE algorithm from TLS negotiation (e.g., "ECDHE", "X25519MLKEM768")
        cert_key_type: Certificate key type for auth (e.g., "RSA", "ECDSA")

    Returns dict with key_exchange, authentication, symmetric, mac.
    """
    # Check TLS 1.3 table
    if cipher_name in _TLS13_DECOMP:
        d = _TLS13_DECOMP[cipher_name].copy()
        d["key_exchange"] = key_exchange_hint or "ECDHE"
        d["authentication"] = cert_key_type or "RSA"
        d["tls_version"] = "1.3"
        return d

    # Check TLS 1.2 exact match
    if cipher_name in _TLS12_PATTERNS:
        d = _TLS12_PATTERNS[cipher_name].copy()
        d["tls_version"] = "1.2"
        return d

    # Heuristic decomposition for unknown cipher names
    result = {
        "key_exchange": "unknown",
        "authentication": "unknown",
        "symmetric": "unknown",
        "mac": "unknown",
        "tls_version": "unknown",
    }

    name = cipher_name.upper()

    # TLS 1.3 pattern: starts with TLS_
    if name.startswith("TLS_"):
        result["tls_version"] = "1.3"
        result["key_exchange"] = key_exchange_hint or "ECDHE"
        result["authentication"] = cert_key_type or "RSA"
        if "AES_256_GCM" in name:
            result["symmetric"] = "AES-256-GCM"
        elif "AES_128_GCM" in name:
            result["symmetric"] = "AES-128-GCM"
        elif "CHACHA20" in name:
            result["symmetric"] = "ChaCha20-Poly1305"
        if "SHA384" in name:
            result["mac"] = "SHA-384"
        elif "SHA256" in name:
            result["mac"] = "SHA-256"
        return result

    # TLS 1.2 heuristic
    result["tls_version"] = "1.2"
    if "ECDHE" in name:
        result["key_exchange"] = "ECDHE"
    elif "DHE" in name:
        result["key_exchange"] = "DHE"
    else:
        result["key_exchange"] = "RSA"

    if "ECDSA" in name:
        result["authentication"] = "ECDSA"
    else:
        result["authentication"] = "RSA"

    if "AES256-GCM" in name or "AES_256_GCM" in name:
        result["symmetric"] = "AES-256-GCM"
    elif "AES128-GCM" in name or "AES_128_GCM" in name:
        result["symmetric"] = "AES-128-GCM"
    elif "CHACHA20" in name:
        result["symmetric"] = "ChaCha20-Poly1305"
    elif "AES256" in name:
        result["symmetric"] = "AES-256-CBC"
    elif "AES128" in name:
        result["symmetric"] = "AES-128-CBC"
    elif "3DES" in name or "DES-CBC3" in name:
        result["symmetric"] = "3DES-CBC"
    elif "RC4" in name:
        result["symmetric"] = "RC4"

    if "SHA384" in name:
        result["mac"] = "SHA-384"
    elif "SHA256" in name:
        result["mac"] = "SHA-256"
    elif "SHA" in name:
        result["mac"] = "SHA-1"
    if "GCM" in name or "CHACHA20" in name:
        result["mac"] = "AEAD"

    return result


# ─── P3.1: CycloneDX BOM Assembly ───────────────────────────────────────────


@timed(service="cbom_builder")
def build_cbom(asset_id: str, crypto_fingerprint: dict) -> dict:
    """
    Build a CycloneDX 1.6 CBOM from a crypto fingerprint.

    Creates components for:
    - Each cipher suite detected (type: CRYPTOGRAPHIC_ASSET, assetType: algorithm)
    - Each certificate in the chain (type: CRYPTOGRAPHIC_ASSET, assetType: certificate)
    - The TLS protocol configuration (type: CRYPTOGRAPHIC_ASSET, assetType: protocol)

    Returns dict with: cbom_json (str), components (list), stats (dict)
    """
    bom = Bom()
    components_meta = []  # Track metadata for our records
    algorithm_refs = {}  # name → BomRef for dependency tracking
    vulnerable_count = 0
    safe_count = 0

    hostname = crypto_fingerprint.get("hostname", "unknown")
    tls_data = crypto_fingerprint.get("tls") or {}
    certs_data = crypto_fingerprint.get("certificates") or []
    quantum_summary = crypto_fingerprint.get("quantum_summary") or {}

    # ── 1. Cipher Suite Algorithm Components ──────────────────────────────

    seen_algos = set()
    cipher_suite_refs = []

    for cs in tls_data.get("cipher_suites") or []:
        cs_name = cs.get("name", "")
        if cs_name in seen_algos:
            continue
        seen_algos.add(cs_name)

        primitive, param_set, crypto_func = _classify_algorithm(cs_name)
        quantum_data = cs.get("quantum", {})
        nist_level = _get_nist_level_for_component(cs_name, quantum_data)
        is_vulnerable = quantum_data.get("is_quantum_vulnerable", True)

        algo_props = AlgorithmProperties(
            primitive=primitive,
            parameter_set_identifier=param_set or str(cs.get("key_size", "")),
            nist_quantum_security_level=nist_level,
            crypto_functions=[crypto_func] if crypto_func != CryptoFunction.UNKNOWN else None,
        )

        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=algo_props,
        )

        bom_ref = BomRef(value=f"crypto-algo-{cs_name}-{asset_id[:8]}")
        comp = Component(
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            name=cs_name,
            bom_ref=bom_ref,
            crypto_properties=crypto_props,
            description=f"Cipher suite: {cs_name} ({cs.get('tls_version', 'unknown')})",
        )
        bom.components.add(comp)
        algorithm_refs[cs_name] = bom_ref
        cipher_suite_refs.append(bom_ref)

        if is_vulnerable:
            vulnerable_count += 1
        else:
            safe_count += 1

        # Decompose cipher suite into constituent algorithms
        kex_hint = tls_data.get("key_exchange")
        cert_key = None
        if certs_data:
            cert_key = certs_data[0].get("key_type")
        decomposed = decompose_cipher_suite(cs_name, kex_hint, cert_key)

        components_meta.append({
            "name": cs_name,
            "type": "algorithm",
            "tls_version": cs.get("tls_version"),
            "nist_level": nist_level,
            "is_vulnerable": is_vulnerable,
            "bom_ref": str(bom_ref),
            "decomposition": decomposed,
        })

    # ── 2. Key Exchange Algorithm Component ───────────────────────────────

    kex = tls_data.get("key_exchange")
    if kex and kex not in seen_algos:
        seen_algos.add(kex)
        primitive, param_set, crypto_func = _classify_algorithm(kex)
        from app.services.crypto_inspector import get_nist_quantum_level
        kex_quantum = get_nist_quantum_level(kex)
        nist_level = kex_quantum["nist_level"] if kex_quantum["nist_level"] >= 0 else None

        algo_props = AlgorithmProperties(
            primitive=primitive,
            nist_quantum_security_level=nist_level,
            crypto_functions=[CryptoFunction.KEYGEN],
        )
        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.ALGORITHM,
            algorithm_properties=algo_props,
        )
        bom_ref = BomRef(value=f"crypto-kex-{kex}-{asset_id[:8]}")
        comp = Component(
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            name=f"{kex} Key Exchange",
            bom_ref=bom_ref,
            crypto_properties=crypto_props,
            description=f"Key exchange algorithm: {kex}",
        )
        bom.components.add(comp)
        algorithm_refs[kex] = bom_ref

        if kex_quantum["is_quantum_vulnerable"]:
            vulnerable_count += 1
        else:
            safe_count += 1

        components_meta.append({
            "name": kex,
            "type": "key_exchange",
            "nist_level": nist_level,
            "is_vulnerable": kex_quantum["is_quantum_vulnerable"],
            "bom_ref": str(bom_ref),
        })

    # ── 3. Certificate Components ─────────────────────────────────────────

    cert_refs = []
    for i, cert_data in enumerate(certs_data):
        cn = cert_data.get("common_name", f"cert-{i}")
        key_type = cert_data.get("key_type", "Unknown")
        key_length = cert_data.get("key_length", 0)
        sig_algo = cert_data.get("signature_algorithm", "Unknown")

        # Parse dates
        not_before = None
        not_after = None
        try:
            if cert_data.get("valid_from"):
                not_before = datetime.fromisoformat(cert_data["valid_from"])
            if cert_data.get("valid_to"):
                not_after = datetime.fromisoformat(cert_data["valid_to"])
        except (ValueError, TypeError):
            pass

        # Create signature algorithm ref if it exists
        sig_ref = algorithm_refs.get(sig_algo)

        cert_props = CertificateProperties(
            subject_name=cn,
            issuer_name=cert_data.get("issuer", ""),
            not_valid_before=not_before,
            not_valid_after=not_after,
            signature_algorithm_ref=sig_ref,
            certificate_format="X.509",
        )

        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.CERTIFICATE,
            certificate_properties=cert_props,
        )

        bom_ref = BomRef(value=f"crypto-cert-{i}-{asset_id[:8]}")
        position = cert_data.get("chain_position", "unknown")
        comp = Component(
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            name=f"{cn} ({position})",
            bom_ref=bom_ref,
            crypto_properties=crypto_props,
            description=f"X.509 certificate: {cn} | {key_type}-{key_length} | Issuer: {cert_data.get('issuer', 'unknown')}",
        )
        bom.components.add(comp)
        cert_refs.append(bom_ref)

        quantum_data = cert_data.get("quantum", {})
        is_vuln = quantum_data.get("is_quantum_vulnerable", True)
        if is_vuln:
            vulnerable_count += 1
        else:
            safe_count += 1

        components_meta.append({
            "name": cn,
            "type": "certificate",
            "chain_position": position,
            "key_type": key_type,
            "key_length": key_length,
            "signature_algorithm": sig_algo,
            "nist_level": quantum_data.get("nist_level", -1),
            "is_vulnerable": is_vuln,
            "days_until_expiry": cert_data.get("days_until_expiry"),
            "bom_ref": str(bom_ref),
        })

    # ── 4. TLS Protocol Component ─────────────────────────────────────────

    if tls_data.get("versions_supported"):
        # Build cipher suite list for the protocol
        cs_entries = []
        for cs_name in seen_algos:
            ref = algorithm_refs.get(cs_name)
            cs_entry = ProtocolPropertiesCipherSuite(
                name=cs_name,
                algorithms=[ref] if ref else None,
            )
            cs_entries.append(cs_entry)

        tls_version = tls_data.get("versions_supported", ["unknown"])[-1]

        protocol_props = ProtocolProperties(
            type=ProtocolPropertiesType.TLS,
            version=tls_version,
            cipher_suites=cs_entries if cs_entries else None,
            crypto_refs=[ref for ref in algorithm_refs.values()],
        )
        crypto_props = CryptoProperties(
            asset_type=CryptoAssetType.PROTOCOL,
            protocol_properties=protocol_props,
        )

        bom_ref = BomRef(value=f"crypto-protocol-tls-{asset_id[:8]}")
        comp = Component(
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            name=f"TLS {tls_version} ({hostname})",
            bom_ref=bom_ref,
            crypto_properties=crypto_props,
            description=f"TLS protocol configuration for {hostname}:{crypto_fingerprint.get('port', 443)}",
        )
        bom.components.add(comp)

        components_meta.append({
            "name": f"TLS {tls_version}",
            "type": "protocol",
            "tls_version": tls_version,
            "cipher_count": len(cs_entries),
            "forward_secrecy": tls_data.get("forward_secrecy", False),
            "bom_ref": str(bom_ref),
        })

    # ── 5. Serialize ──────────────────────────────────────────────────────

    output = JsonV1Dot6(bom)
    cbom_json = output.output_as_string()

    total_components = len(components_meta)
    stats = {
        "total_components": total_components,
        "algorithm_components": sum(1 for c in components_meta if c["type"] in ("algorithm", "key_exchange")),
        "certificate_components": sum(1 for c in components_meta if c["type"] == "certificate"),
        "protocol_components": sum(1 for c in components_meta if c["type"] == "protocol"),
        "vulnerable_count": vulnerable_count,
        "safe_count": safe_count,
        "quantum_ready_pct": round(safe_count / max(vulnerable_count + safe_count, 1) * 100, 1),
        "json_size_bytes": len(cbom_json.encode("utf-8")),
    }

    logger.info(
        f"CBOM built for {hostname}: {total_components} components",
        extra={
            "hostname": hostname,
            "asset_id": asset_id,
            **stats,
        },
    )

    return {
        "cbom_json": cbom_json,
        "components": components_meta,
        "stats": stats,
    }


# ─── P3.2: CBOM File Storage ────────────────────────────────────────────────


@timed(service="cbom_builder")
def save_cbom(scan_id: str, asset_id: str, cbom_json: str) -> str:
    """
    Save CBOM JSON to filesystem.

    Writes to: data/cbom/{scan_id}/{asset_id}.cdx.json
    Returns the file path.
    """
    cbom_dir = PROJECT_ROOT / "data" / "cbom" / scan_id
    cbom_dir.mkdir(parents=True, exist_ok=True)

    file_path = cbom_dir / f"{asset_id}.cdx.json"
    file_path.write_text(cbom_json, encoding="utf-8")

    file_size = file_path.stat().st_size
    logger.info(
        f"CBOM saved: {file_path}",
        extra={
            "scan_id": scan_id,
            "asset_id": asset_id,
            "file_path": str(file_path),
            "file_size_bytes": file_size,
        },
    )

    return str(file_path)


@timed(service="cbom_builder")
def save_cbom_to_db(
    scan_id: str,
    asset_id: str,
    cbom_data: dict,
    file_path: str,
    db,
) -> tuple:
    """
    Save CBOM metadata and components to the database.

    Creates:
    - CBOMRecord (metadata row referencing the JSON file)
    - CBOMComponent rows (one per component, for fast DB queries)

    Returns tuple of (CBOMRecord, list[CBOMComponent]).
    """
    import uuid as uuid_mod
    from app.models.cbom import CBOMRecord, CBOMComponent

    stats = cbom_data.get("stats", {})
    components = cbom_data.get("components", [])

    # Create CBOMRecord
    record = CBOMRecord(
        scan_id=uuid_mod.UUID(scan_id) if isinstance(scan_id, str) else scan_id,
        asset_id=uuid_mod.UUID(asset_id) if isinstance(asset_id, str) else asset_id,
        spec_version="1.6",
        file_path=file_path,
        total_components=stats.get("total_components", 0),
        vulnerable_components=stats.get("vulnerable_count", 0),
        quantum_ready_pct=stats.get("quantum_ready_pct", 0.0),
    )
    db.add(record)
    db.flush()  # get record.id

    # Create CBOMComponent rows
    saved_components = []
    for comp in components:
        db_comp = CBOMComponent(
            cbom_id=record.id,
            scan_id=uuid_mod.UUID(scan_id) if isinstance(scan_id, str) else scan_id,
            name=comp.get("name", ""),
            component_type=comp.get("type", "unknown"),
            nist_quantum_level=comp.get("nist_level", -1) if comp.get("nist_level") is not None else -1,
            is_quantum_vulnerable=comp.get("is_vulnerable", True),
            key_type=comp.get("key_type"),
            key_length=comp.get("key_length"),
            tls_version=comp.get("tls_version"),
            bom_ref=comp.get("bom_ref"),
        )
        db.add(db_comp)
        saved_components.append(db_comp)

    db.commit()

    logger.info(
        f"CBOM saved to DB: {record.id} with {len(saved_components)} components",
        extra={
            "cbom_id": str(record.id),
            "scan_id": scan_id,
            "asset_id": asset_id,
            "component_count": len(saved_components),
        },
    )

    return record, saved_components


# ─── P3.3: CBOM Aggregate (Org-Wide) ────────────────────────────────────────


@timed(service="cbom_builder")
def build_aggregate_cbom(scan_id: str, db) -> dict:
    """
    Build an org-wide aggregate CBOM from all per-asset CBOMs in a scan.

    Queries all CBOMComponent rows for the scan, deduplicates algorithms,
    and produces summary statistics.
    """
    import uuid as uuid_mod
    from app.models.cbom import CBOMRecord, CBOMComponent

    scan_uuid = uuid_mod.UUID(scan_id) if isinstance(scan_id, str) else scan_id

    # Get all components for this scan
    components = db.query(CBOMComponent).filter(
        CBOMComponent.scan_id == scan_uuid
    ).all()

    # Get all records for asset count
    records = db.query(CBOMRecord).filter(
        CBOMRecord.scan_id == scan_uuid
    ).all()

    # Deduplicate algorithms by name
    seen = {}
    for comp in components:
        key = comp.name
        if key not in seen:
            seen[key] = {
                "name": comp.name,
                "type": comp.component_type,
                "nist_level": comp.nist_quantum_level,
                "is_vulnerable": comp.is_quantum_vulnerable,
                "key_type": comp.key_type,
                "key_length": comp.key_length,
                "asset_count": 1,
            }
        else:
            seen[key]["asset_count"] += 1

    deduplicated = list(seen.values())

    # Statistics
    total_assets = len(records)
    total_components = len(deduplicated)
    vulnerable_components = sum(1 for c in deduplicated if c["is_vulnerable"])
    safe_components = total_components - vulnerable_components
    aggregate_pct = round(safe_components / max(total_components, 1) * 100, 1)

    # NIST level distribution
    level_dist = {}
    for c in deduplicated:
        level = c.get("nist_level", -1)
        level_dist[level] = level_dist.get(level, 0) + 1

    aggregate = {
        "scan_id": scan_id,
        "total_assets": total_assets,
        "total_components_raw": len(components),
        "total_components_deduplicated": total_components,
        "vulnerable_components": vulnerable_components,
        "safe_components": safe_components,
        "quantum_ready_pct": aggregate_pct,
        "nist_level_distribution": level_dist,
        "components": deduplicated,
    }

    # Add serialized JSON for orchestrator saving
    aggregate["cbom_json"] = json.dumps(aggregate, indent=2)

    logger.info(
        f"Aggregate CBOM for scan {scan_id}: {total_assets} assets, "
        f"{total_components} unique components, {vulnerable_components} vulnerable",
        extra={
            "scan_id": scan_id,
            "total_assets": total_assets,
            "total_components": total_components,
            "vulnerable": vulnerable_components,
            "quantum_ready_pct": aggregate_pct,
        },
    )

    return aggregate


# ─── P3.4: CVE Cross-Referencing ────────────────────────────────────────────

# In-memory cache for CVE lookups (same version → same CVEs)
_cve_cache: dict[str, list[dict]] = {}


@timed(service="cbom_builder")
def lookup_cves(library_name: str, version: str) -> list[dict]:
    """
    Query NVD API v2 for CVEs matching a crypto library + version.

    Rate limited: max 5 req/30s without API key.
    Results are cached in memory.

    Returns list of {cve_id, severity, description}.
    """
    import httpx
    import time

    cache_key = f"{library_name}:{version}"
    if cache_key in _cve_cache:
        return _cve_cache[cache_key]

    cves = []
    try:
        search_term = f"{library_name} {version}"
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": search_term,
            "resultsPerPage": 10,
        }

        with httpx.Client(timeout=15) as client:
            resp = client.get(url, params=params)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id", "")

                    # Get severity from CVSS
                    severity = "UNKNOWN"
                    metrics = cve.get("metrics", {})
                    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                        metric_list = metrics.get(metric_key, [])
                        if metric_list:
                            severity = metric_list[0].get("cvssData", {}).get(
                                "baseSeverity", "UNKNOWN"
                            )
                            break

                    # Get description
                    desc = ""
                    for d in cve.get("descriptions", []):
                        if d.get("lang") == "en":
                            desc = d.get("value", "")[:200]
                            break

                    cves.append({
                        "cve_id": cve_id,
                        "severity": severity,
                        "description": desc,
                    })

                logger.info(
                    f"CVE lookup: {library_name} {version} → {len(cves)} CVEs found",
                    extra={
                        "library": library_name,
                        "version": version,
                        "cve_count": len(cves),
                    },
                )
            elif resp.status_code == 403:
                logger.warning(f"NVD rate limited for {search_term}")
            else:
                logger.warning(f"NVD returned {resp.status_code} for {search_term}")

    except Exception as e:
        logger.warning(
            f"CVE lookup failed for {library_name} {version}: {e}",
            extra={"library": library_name, "version": version, "error": str(e)},
        )

    _cve_cache[cache_key] = cves
    return cves
