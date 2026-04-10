"""
Standalone tests for Phase 8 Wave 1 features:
- HQC detection (NIST levels + PQC OIDs)
- FN-DSA/FALCON detection (NIST levels + PQC OIDs)
- JWT algorithm deep parsing
- Vendor PQC readiness expansion
"""
import json
import os
import sys
import base64

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.crypto_inspector import (
    get_nist_quantum_level,
    parse_jwt_algorithm,
    _extract_jwts_from_text,
    _JWT_QUANTUM_MAP,
)


# ─── Track B: HQC Detection Tests ──────────────────────────────────────────


def test_hqc_128_nist_level():
    """HQC-128 should map to NIST Level 1."""
    result = get_nist_quantum_level("HQC-128")
    assert result["nist_level"] == 1
    assert result["is_quantum_vulnerable"] is False
    assert result["quantum_status"] == "pqc_draft"
    print(f"  ✅ HQC-128 → Level {result['nist_level']}, vulnerable={result['is_quantum_vulnerable']}")


def test_hqc_192_nist_level():
    """HQC-192 should map to NIST Level 3."""
    result = get_nist_quantum_level("HQC-192")
    assert result["nist_level"] == 3
    assert result["is_quantum_vulnerable"] is False
    print(f"  ✅ HQC-192 → Level {result['nist_level']}")


def test_hqc_256_nist_level():
    """HQC-256 should map to NIST Level 5."""
    result = get_nist_quantum_level("HQC-256")
    assert result["nist_level"] == 5
    assert result["is_quantum_vulnerable"] is False
    print(f"  ✅ HQC-256 → Level {result['nist_level']}")


def test_hqc_oid_in_pqc_oids():
    """HQC draft OIDs should be present in pqc_oids.json."""
    data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "data")
    with open(os.path.join(data_dir, "pqc_oids.json")) as f:
        oids = json.load(f)

    assert "HQC-128" in oids
    assert "HQC-192" in oids
    assert "HQC-256" in oids
    assert oids["HQC-128"]["type"] == "kem"
    assert oids["HQC-128"]["draft"] is True
    print(f"  ✅ HQC OIDs present: HQC-128={oids['HQC-128']['oid']}, HQC-192={oids['HQC-192']['oid']}, HQC-256={oids['HQC-256']['oid']}")


# ─── Track C: FN-DSA (FALCON) Detection Tests ──────────────────────────────


def test_fndsa_512_nist_level():
    """FN-DSA-512 should map to NIST Level 1."""
    result = get_nist_quantum_level("FN-DSA-512")
    assert result["nist_level"] == 1
    assert result["is_quantum_vulnerable"] is False
    assert result["quantum_status"] == "pqc_draft"
    print(f"  ✅ FN-DSA-512 → Level {result['nist_level']}, vulnerable={result['is_quantum_vulnerable']}")


def test_fndsa_1024_nist_level():
    """FN-DSA-1024 should map to NIST Level 5."""
    result = get_nist_quantum_level("FN-DSA-1024")
    assert result["nist_level"] == 5
    assert result["is_quantum_vulnerable"] is False
    print(f"  ✅ FN-DSA-1024 → Level {result['nist_level']}")


def test_fndsa_oid_in_pqc_oids():
    """FN-DSA draft OIDs should be present in pqc_oids.json."""
    data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "data")
    with open(os.path.join(data_dir, "pqc_oids.json")) as f:
        oids = json.load(f)

    assert "FN-DSA-512" in oids
    assert "FN-DSA-1024" in oids
    assert oids["FN-DSA-512"]["type"] == "signature"
    assert oids["FN-DSA-512"]["draft"] is True
    assert "FIPS 206" in oids["FN-DSA-512"]["fips"]
    print(f"  ✅ FN-DSA OIDs present: FN-DSA-512={oids['FN-DSA-512']['oid']}, FN-DSA-1024={oids['FN-DSA-1024']['oid']}")


# ─── Track G: JWT Algorithm Deep Parsing Tests ─────────────────────────────


def _make_jwt(header_dict: dict, payload: str = '{"sub":"test"}') -> str:
    """Helper to create a JWT-like token from a header dict."""
    header_b64 = base64.urlsafe_b64encode(json.dumps(header_dict).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")
    sig_b64 = base64.urlsafe_b64encode(b"fake_signature").decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def test_jwt_parse_hs256():
    """HS256 JWT should be quantum-resistant (symmetric)."""
    token = _make_jwt({"alg": "HS256", "typ": "JWT"})
    result = parse_jwt_algorithm(token)
    assert result["alg"] == "HS256"
    assert result["quantum_vulnerable"] is False
    assert result["nist_level"] == 1
    assert result["family"] == "HMAC"
    assert result["key_type"] == "symmetric"
    print(f"  ✅ HS256 → Level {result['nist_level']}, vulnerable={result['quantum_vulnerable']}, family={result['family']}")


def test_jwt_parse_rs256():
    """RS256 JWT should be quantum-vulnerable (RSA)."""
    token = _make_jwt({"alg": "RS256", "typ": "JWT"})
    result = parse_jwt_algorithm(token)
    assert result["alg"] == "RS256"
    assert result["quantum_vulnerable"] is True
    assert result["nist_level"] == 0
    assert result["family"] == "RSA"
    print(f"  ✅ RS256 → Level {result['nist_level']}, vulnerable={result['quantum_vulnerable']}, family={result['family']}")


def test_jwt_parse_es256():
    """ES256 JWT should be quantum-vulnerable (ECDSA)."""
    token = _make_jwt({"alg": "ES256", "typ": "JWT"})
    result = parse_jwt_algorithm(token)
    assert result["alg"] == "ES256"
    assert result["quantum_vulnerable"] is True
    assert result["family"] == "ECDSA"
    print(f"  ✅ ES256 → Level {result['nist_level']}, vulnerable={result['quantum_vulnerable']}")


def test_jwt_parse_eddsa():
    """EdDSA JWT should be quantum-vulnerable."""
    token = _make_jwt({"alg": "EdDSA", "typ": "JWT"})
    result = parse_jwt_algorithm(token)
    assert result["alg"] == "EdDSA"
    assert result["quantum_vulnerable"] is True
    assert result["family"] == "EdDSA"
    print(f"  ✅ EdDSA → Level {result['nist_level']}, vulnerable={result['quantum_vulnerable']}")


def test_jwt_parse_mldsa():
    """ML-DSA-65 JWT should be quantum-safe (PQC)."""
    token = _make_jwt({"alg": "ML-DSA-65", "typ": "JWT"})
    result = parse_jwt_algorithm(token)
    assert result["alg"] == "ML-DSA-65"
    assert result["quantum_vulnerable"] is False
    assert result["nist_level"] == 3
    assert result["family"] == "ML-DSA"
    assert result["key_type"] == "pqc"
    print(f"  ✅ ML-DSA-65 → Level {result['nist_level']}, vulnerable={result['quantum_vulnerable']}, family={result['family']}")


def test_jwt_parse_fndsa():
    """FN-DSA-512 JWT should be quantum-safe (PQC)."""
    token = _make_jwt({"alg": "FN-DSA-512", "typ": "JWT"})
    result = parse_jwt_algorithm(token)
    assert result["alg"] == "FN-DSA-512"
    assert result["quantum_vulnerable"] is False
    assert result["nist_level"] == 1
    assert result["family"] == "FN-DSA"
    print(f"  ✅ FN-DSA-512 → Level {result['nist_level']}, vulnerable={result['quantum_vulnerable']}")


def test_jwt_parse_none_alg():
    """'none' algorithm JWT should be flagged as insecure."""
    token = _make_jwt({"alg": "none", "typ": "JWT"})
    result = parse_jwt_algorithm(token)
    assert result["alg"] == "none"
    assert result["quantum_vulnerable"] is True
    assert result["family"] == "none"
    print(f"  ✅ none → vulnerable=True, family=none")


def test_jwt_parse_with_kid():
    """JWT with kid field should extract it."""
    token = _make_jwt({"alg": "RS256", "typ": "JWT", "kid": "key-123"})
    result = parse_jwt_algorithm(token)
    assert result["kid"] == "key-123"
    assert result["typ"] == "JWT"
    print(f"  ✅ kid=key-123 extracted correctly")


def test_jwt_parse_empty_token():
    """Empty token should return error."""
    result = parse_jwt_algorithm("")
    assert result["parse_error"] is not None
    print(f"  ✅ Empty token → error: {result['parse_error']}")


def test_jwt_parse_invalid_token():
    """Non-JWT string should return error."""
    result = parse_jwt_algorithm("not-a-jwt-token")
    assert result["parse_error"] is not None
    print(f"  ✅ Invalid token → error: {result['parse_error']}")


def test_jwt_parse_bearer_prefix():
    """JWT with Bearer prefix should still parse."""
    token = _make_jwt({"alg": "HS256", "typ": "JWT"})
    bearer_token = f"Bearer {token}"
    result = parse_jwt_algorithm(bearer_token)
    assert result["alg"] == "HS256"
    print(f"  ✅ Bearer prefix handled → alg={result['alg']}")


def test_extract_jwts_from_text():
    """Should extract JWT tokens from arbitrary text."""
    jwt1 = _make_jwt({"alg": "RS256"})
    text = f"cookie=abc; token={jwt1}; path=/"
    found = _extract_jwts_from_text(text)
    assert len(found) >= 1
    print(f"  ✅ Extracted {len(found)} JWT(s) from text")


def test_jwt_quantum_map_completeness():
    """All common JWT algorithms should be in the quantum map."""
    required = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
                 "PS256", "PS384", "PS512", "ES256", "ES384", "ES512",
                 "EdDSA", "none"]
    for alg in required:
        assert alg in _JWT_QUANTUM_MAP, f"Missing {alg} from _JWT_QUANTUM_MAP"
    print(f"  ✅ All {len(required)} standard JWT algorithms mapped")


# ─── Track F: Vendor PQC Readiness Tests ────────────────────────────────────


def test_vendor_readiness_count():
    """Should have 15+ vendors in readiness data."""
    data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "data")
    with open(os.path.join(data_dir, "vendor_readiness.json")) as f:
        vendors = json.load(f)

    assert len(vendors) >= 15, f"Expected 15+ vendors, got {len(vendors)}"
    print(f"  ✅ {len(vendors)} vendors in readiness data")


def test_vendor_readiness_required_fields():
    """Each vendor should have all required fields."""
    data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "data")
    with open(os.path.join(data_dir, "vendor_readiness.json")) as f:
        vendors = json.load(f)

    required_fields = {"vendor", "product", "category", "pqc_roadmap_published",
                       "pqc_support_status", "target_version", "algorithms_supported",
                       "hybrid_support", "risk_if_delayed", "last_updated"}

    for v in vendors:
        missing = required_fields - set(v.keys())
        assert not missing, f"Vendor '{v.get('vendor')}' missing fields: {missing}"

    print(f"  ✅ All {len(vendors)} vendors have required fields")


def test_vendor_readiness_new_vendors():
    """New vendors (Apache, HAProxy, Let's Encrypt, Microsoft, Google, Cloudflare, SWIFT) should be present."""
    data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "data")
    with open(os.path.join(data_dir, "vendor_readiness.json")) as f:
        vendors = json.load(f)

    vendor_names = {v["vendor"] for v in vendors}
    new_vendors = {"Apache", "HAProxy", "Let's Encrypt", "Microsoft", "Google", "Cloudflare", "SWIFT"}
    missing = new_vendors - vendor_names
    assert not missing, f"Missing new vendors: {missing}"
    print(f"  ✅ All 7 new vendors present: {new_vendors & vendor_names}")


def test_vendor_categories():
    """Vendors should span multiple categories."""
    data_dir = os.path.join(os.path.dirname(__file__), "..", "..", "app", "data")
    with open(os.path.join(data_dir, "vendor_readiness.json")) as f:
        vendors = json.load(f)

    categories = {v["category"] for v in vendors}
    assert len(categories) >= 6, f"Expected 6+ categories, got {len(categories)}: {categories}"
    print(f"  ✅ {len(categories)} vendor categories: {categories}")


# ─── Hybrid Entry Tests ─────────────────────────────────────────────────────


def test_hybrid_nist_levels():
    """All hybrid PQC entries should have correct NIST levels."""
    hybrids = {
        "SecP256r1MLKEM768": 3,
        "SecP384r1MLKEM1024": 5,
        "X25519Kyber768": 3,
        "X448MLKEM1024": 5,
    }
    for name, expected_level in hybrids.items():
        result = get_nist_quantum_level(name)
        assert result["nist_level"] == expected_level, f"{name}: expected Level {expected_level}, got {result['nist_level']}"
        assert result["is_quantum_vulnerable"] is False
    print(f"  ✅ All {len(hybrids)} hybrid entries verified")


# ─── Runner ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        # HQC
        ("HQC-128 NIST Level", test_hqc_128_nist_level),
        ("HQC-192 NIST Level", test_hqc_192_nist_level),
        ("HQC-256 NIST Level", test_hqc_256_nist_level),
        ("HQC OIDs in pqc_oids.json", test_hqc_oid_in_pqc_oids),
        # FN-DSA
        ("FN-DSA-512 NIST Level", test_fndsa_512_nist_level),
        ("FN-DSA-1024 NIST Level", test_fndsa_1024_nist_level),
        ("FN-DSA OIDs in pqc_oids.json", test_fndsa_oid_in_pqc_oids),
        # JWT
        ("JWT parse HS256", test_jwt_parse_hs256),
        ("JWT parse RS256", test_jwt_parse_rs256),
        ("JWT parse ES256", test_jwt_parse_es256),
        ("JWT parse EdDSA", test_jwt_parse_eddsa),
        ("JWT parse ML-DSA-65", test_jwt_parse_mldsa),
        ("JWT parse FN-DSA-512", test_jwt_parse_fndsa),
        ("JWT parse 'none'", test_jwt_parse_none_alg),
        ("JWT parse with kid", test_jwt_parse_with_kid),
        ("JWT parse empty", test_jwt_parse_empty_token),
        ("JWT parse invalid", test_jwt_parse_invalid_token),
        ("JWT parse Bearer prefix", test_jwt_parse_bearer_prefix),
        ("JWT extract from text", test_extract_jwts_from_text),
        ("JWT quantum map completeness", test_jwt_quantum_map_completeness),
        # Vendor
        ("Vendor count ≥15", test_vendor_readiness_count),
        ("Vendor required fields", test_vendor_readiness_required_fields),
        ("Vendor new additions", test_vendor_readiness_new_vendors),
        ("Vendor categories", test_vendor_categories),
        # Hybrid
        ("Hybrid NIST levels", test_hybrid_nist_levels),
    ]

    print(f"\n{'='*60}")
    print(f"Phase 8 Wave 1 — Standalone Tests ({len(tests)} tests)")
    print(f"{'='*60}")

    passed = 0
    failed = 0
    for name, test_fn in tests:
        try:
            print(f"\n🧪 {name}:")
            test_fn()
            passed += 1
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            failed += 1

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'='*60}")

    sys.exit(0 if failed == 0 else 1)
