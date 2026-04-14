#!/usr/bin/env python3
"""
Standalone test for testssl_service.py — tests the JSON parser
against realistic sample data (no live network needed).
Run: python -m tests.standalone.test_testssl_service
"""
import sys
import os
import json

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.testssl_service import (
    parse_testssl_json,
    _classify_finding,
    _severity_label,
    _compute_grade,
)

# ─── Realistic sample findings (mimics testssl.sh --jsonfile-pretty output) ────

SAMPLE_FINDINGS = [
    {"id": "scanTime", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "Scan took 45 seconds"},
    {"id": "engine_problem", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "WARN", "finding": "No engine or GOST support"},
    # Protocols
    {"id": "SSLv2", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not offered"},
    {"id": "SSLv3", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not offered"},
    {"id": "TLS1", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "TLS1_1", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "LOW", "finding": "offered (deprecated)"},
    {"id": "TLS1_2", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "offered"},
    {"id": "TLS1_3", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "offered (final)"},
    {"id": "ALPN_HTTP2", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "h2 offered"},
    {"id": "NPN", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "h2 offered"},
    # Ciphers
    {"id": "cipher_x1301", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "TLS_AES_128_GCM_SHA256"},
    {"id": "cipher_x1302", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "TLS_AES_256_GCM_SHA384"},
    {"id": "cipher_x1303", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "TLS_CHACHA20_POLY1305_SHA256"},
    {"id": "cipher_xc02c", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "ECDHE-ECDSA-AES256-GCM-SHA384"},
    {"id": "cipher_xc013", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "MEDIUM", "finding": "ECDHE-RSA-AES128-SHA (weak hash)"},
    {"id": "cipherorder_TLS1_2", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "cipher order: server"},
    # Certificates
    {"id": "cert_commonName", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "*.google.com"},
    {"id": "cert_keySize", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "EC 256 bits (P-256)"},
    {"id": "cert_signatureAlgorithm", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "SHA256withECDSA"},
    {"id": "cert_validFrom", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "2024-12-02 08:36:00"},
    {"id": "cert_validTo", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "2025-02-24 08:35:59"},
    {"id": "cert_caIssuers", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "WR2"},
    {"id": "cert_chain_of_trust", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "passed"},
    {"id": "cert_trust", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "trusted"},
    {"id": "OCSP_stapling", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "offered"},
    {"id": "cert_subjectAltName", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "*.google.com, *.googleapis.com"},
    {"id": "intermediate_cert_notAfter", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "2036-01-01 00:00:00"},
    {"id": "CT_log", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "yes (certificate)"},
    # Vulnerabilities
    {"id": "heartbleed", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "CCS", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "ticketbleed", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "ROBOT", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "secure_renego", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "supported"},
    {"id": "secure_client_renego", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "CRIME_TLS", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "BREACH", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "HIGH", "finding": "potentially NOT ok, uses gzip HTTP compression", "cve": "CVE-2013-3587", "cwe": "CWE-310"},
    {"id": "POODLE_SSL", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "fallback_SCSV", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "supported"},
    {"id": "SWEET32", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "FREAK", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "DROWN", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "LOGJAM", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "BEAST", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "LUCKY13", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "winshock", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "not vulnerable"},
    {"id": "RC4", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "no RC4 ciphers detected"},
    # Headers
    {"id": "HSTS", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "max-age=31536000"},
    {"id": "HPKP", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "No HPKP header"},
    {"id": "banner_server", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "gws"},
    {"id": "X-Frame-Options", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "MEDIUM", "finding": "SAMEORIGIN"},
    {"id": "X-Content-Type-Options", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "nosniff"},
    {"id": "Content-Security-Policy", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "WARN", "finding": "not offered"},
    {"id": "Referrer-Policy", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "not offered"},
    # Forward Secrecy
    {"id": "FS_ciphers", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "OK", "finding": "ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305"},
    {"id": "FS_ECDHE_curves", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "prime256v1 X25519"},
    # Server Preferences
    {"id": "server_defaults_cipher_order", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "server"},
    {"id": "server_defaults_negotiated", "ip": "142.250.80.46/142.250.80.46", "port": "443", "severity": "INFO", "finding": "TLS 1.3, ECDHE-ECDSA-AES256-GCM-SHA384"},
]

# ─── Tests ─────────────────────────────────────────────────────────────────────

def test_classify_finding():
    print("Testing _classify_finding...")
    assert _classify_finding("SSLv2") == "protocols"
    assert _classify_finding("TLS1_3") == "protocols"
    assert _classify_finding("heartbleed") == "vulnerabilities"
    assert _classify_finding("BREACH") == "vulnerabilities"
    assert _classify_finding("ROBOT") == "vulnerabilities"
    assert _classify_finding("cert_keySize") == "certificates"
    assert _classify_finding("intermediate_cert_notAfter") == "certificates"
    assert _classify_finding("OCSP_stapling") == "certificates"
    assert _classify_finding("CT_log") == "certificates"
    assert _classify_finding("HSTS") == "headers"
    assert _classify_finding("X-Frame-Options") == "headers"
    assert _classify_finding("banner_server") == "headers"
    assert _classify_finding("cipher_x1301") == "ciphers"
    assert _classify_finding("cipherorder_TLS1_2") == "ciphers"
    assert _classify_finding("FS_ciphers") == "forward_secrecy"
    assert _classify_finding("server_defaults_cipher_order") == "server_preferences"
    assert _classify_finding("random_unknown_thing") == "other"
    print("  ✓ All classification tests passed")


def test_severity_label():
    print("Testing _severity_label...")
    assert _severity_label("OK") == "OK"
    assert _severity_label("HIGH") == "HIGH"
    assert _severity_label("CRITICAL") == "CRITICAL"
    assert _severity_label("WARN") == "WARN"
    assert _severity_label("INFO") == "INFO"
    assert _severity_label("NOT OK") == "HIGH"
    assert _severity_label("FATAL ERROR") == "CRITICAL"
    assert _severity_label("something_else") == "INFO"
    print("  ✓ All severity label tests passed")


def test_compute_grade():
    print("Testing _compute_grade...")
    assert _compute_grade({"OK": 50}) == "A"
    assert _compute_grade({"OK": 50, "LOW": 3}) == "B"
    assert _compute_grade({"OK": 50, "MEDIUM": 1}) == "B"
    assert _compute_grade({"OK": 50, "MEDIUM": 5}) == "C"
    assert _compute_grade({"OK": 50, "HIGH": 1}) == "C"
    assert _compute_grade({"OK": 50, "HIGH": 3}) == "D"
    assert _compute_grade({"OK": 50, "CRITICAL": 1}) == "F"
    print("  ✓ All grade computation tests passed")


def test_parse_testssl_json():
    print("Testing parse_testssl_json with sample data...")
    result = parse_testssl_json(SAMPLE_FINDINGS)

    # Basic structure
    assert "grade" in result
    assert "severity_counts" in result
    assert "total_findings" in result
    assert "protocol_support" in result
    assert "vuln_status" in result
    assert "cipher_strength" in result
    assert "sections" in result
    assert "all_findings" in result

    # scanTime and engine_problem should be excluded
    all_ids = {f["id"] for f in result["all_findings"]}
    assert "scanTime" not in all_ids
    assert "engine_problem" not in all_ids

    # Protocol support
    ps = result["protocol_support"]
    assert ps["SSLv2"]["offered"] is False
    assert ps["SSLv3"]["offered"] is False
    assert ps["TLS1_2"]["offered"] is True
    assert ps["TLS1_3"]["offered"] is True
    print(f"  Protocol support: {json.dumps(ps, indent=2)[:200]}...")

    # Vulnerabilities
    vs = result["vuln_status"]
    assert vs["heartbleed"]["vulnerable"] is False
    assert vs["BREACH"]["vulnerable"] is True
    assert vs["BREACH"]["cve"] == "CVE-2013-3587"
    print(f"  Vuln status keys: {list(vs.keys())}")

    # Severity counts
    sc = result["severity_counts"]
    print(f"  Severity counts: {sc}")
    assert sc.get("HIGH", 0) >= 1  # BREACH is HIGH

    # Grade — with 1 HIGH, should be C
    assert result["grade"] == "C", f"Expected C, got {result['grade']}"
    print(f"  Grade: {result['grade']}")

    # Cipher strength
    cs = result["cipher_strength"]
    print(f"  Cipher strength: {cs}")
    assert cs["strong"] > 0  # multiple OK ciphers

    # Sections populated
    sections = result["sections"]
    assert len(sections["protocols"]) >= 6
    assert len(sections["vulnerabilities"]) >= 10
    assert len(sections["certificates"]) >= 5
    assert len(sections["ciphers"]) >= 4
    assert len(sections["headers"]) >= 3
    assert len(sections["forward_secrecy"]) >= 1

    print(f"  Total findings: {result['total_findings']}")
    print(f"  Sections: { {k: len(v) for k, v in sections.items()} }")
    print("  ✓ All parse tests passed")


def test_empty_input():
    print("Testing parse_testssl_json with empty input...")
    result = parse_testssl_json([])
    assert result["grade"] == "A"
    assert result["total_findings"] == 0
    assert all(len(v) == 0 for v in result["sections"].values())
    print("  ✓ Empty input test passed")


def test_scan_meta_only():
    print("Testing parse_testssl_json with meta-only input...")
    result = parse_testssl_json([
        {"id": "scanTime", "ip": "/", "port": "443", "severity": "INFO", "finding": "10 seconds"},
        {"id": "engine_problem", "ip": "/", "port": "443", "severity": "WARN", "finding": "No engine"},
    ])
    assert result["total_findings"] == 0
    assert result["grade"] == "A"
    print("  ✓ Meta-only input test passed")


if __name__ == "__main__":
    print("=" * 60)
    print("testssl_service.py — Standalone Tests")
    print("=" * 60)
    test_classify_finding()
    test_severity_label()
    test_compute_grade()
    test_parse_testssl_json()
    test_empty_input()
    test_scan_meta_only()
    print("=" * 60)
    print("ALL TESTS PASSED ✓")
    print("=" * 60)
