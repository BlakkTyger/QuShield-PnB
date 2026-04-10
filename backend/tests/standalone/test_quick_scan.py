#!/usr/bin/env python3
"""
Standalone test for Quick Scan service.

Tests quick_scan() against real banking domains to verify:
- Completes in <8 seconds
- Returns correct structure
- Produces meaningful risk scores and findings
"""
import sys
import os
import json
import time

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.quick_scanner import quick_scan


def test_quick_scan_pnb():
    """Test quick scan against PNB."""
    print("=" * 60)
    print("TEST: Quick Scan — pnb.bank.in")
    print("=" * 60)

    start = time.time()
    result = quick_scan("pnb.bank.in")
    elapsed = time.time() - start

    print(f"\nDuration: {result['duration_ms']:.0f}ms (wall: {elapsed*1000:.0f}ms)")
    print(f"Error: {result.get('error')}")

    # Structure checks
    assert result["scan_type"] == "quick", "scan_type should be 'quick'"
    assert result["domain"] == "pnb.bank.in", "domain mismatch"
    assert result["error"] is None, f"Unexpected error: {result['error']}"

    # TLS data
    tls = result["tls"]
    assert tls is not None, "TLS data missing"
    assert tls["negotiated_cipher"] is not None, "No negotiated cipher"
    assert tls["negotiated_protocol"] is not None, "No negotiated protocol"
    print(f"\nTLS: {tls['negotiated_protocol']} / {tls['negotiated_cipher']}")
    print(f"Forward secrecy: {tls['forward_secrecy']}")
    print(f"Key exchange: {tls['key_exchange']}")
    print(f"Cipher count: {tls['cipher_count']}")

    # Certificate
    cert = result["certificate"]
    assert cert is not None, "Certificate data missing"
    assert cert["key_type"] is not None, "No cert key type"
    assert cert["key_length"] is not None and cert["key_length"] > 0, "No cert key length"
    print(f"\nCert: {cert['common_name']}")
    print(f"Key: {cert['key_type']}-{cert['key_length']}")
    print(f"Issuer: {cert['issuer']}")
    print(f"SAN count: {cert['san_count']}")
    print(f"Days until expiry: {cert['days_until_expiry']}")
    print(f"Signature: {cert['signature_algorithm']}")

    # Quantum assessment
    qa = result["quantum_assessment"]
    assert qa is not None, "Quantum assessment missing"
    print(f"\nQuantum vulnerable: {qa['is_quantum_vulnerable']}")
    print(f"Has PQC: {qa['has_pqc']}")
    print(f"Lowest NIST level: {qa['lowest_nist_level']}")
    print(f"Vulnerable algos: {len(qa['vulnerable_algorithms'])}")
    print(f"Safe algos: {len(qa['safe_algorithms'])}")

    # Risk
    risk = result["risk"]
    assert risk is not None, "Risk data missing"
    assert 0 <= risk["score"] <= 1000, f"Risk score out of range: {risk['score']}"
    print(f"\nRisk: {risk['score']}/1000 — {risk['classification']}")
    print(f"Asset type: {risk['asset_type']}")
    print(f"Mosca exposed (pessimistic): {risk['mosca']['exposed_pessimistic']}")

    # Compliance
    comp = result["compliance"]
    assert comp is not None, "Compliance data missing"
    print(f"\nCompliance: {comp['compliance_pct']}%")
    print(f"  TLS 1.3: {comp['tls_1_3_enforced']}")
    print(f"  Forward secrecy: {comp['forward_secrecy']}")
    print(f"  PCI DSS basic: {comp['pci_dss_4_basic']}")
    print(f"  SEBI TLS: {comp['sebi_tls_compliant']}")
    print(f"  Has PQC: {comp['has_pqc_deployment']}")

    # Key findings
    print(f"\nKey findings ({len(result['key_findings'])}):")
    for f in result["key_findings"]:
        print(f"  [{f['severity'].upper()}] {f['title']}")

    # Timing check
    assert elapsed < 8.0, f"Quick scan too slow: {elapsed:.1f}s (target: <8s)"

    print(f"\n✅ PASS — {elapsed*1000:.0f}ms (target: <8000ms)")
    return result


def test_quick_scan_multiple():
    """Test quick scan against multiple domains."""
    domains = ["pnb.bank.in", "sbi.bank.in", "hdfc.bank.in"]
    results = {}

    print("\n" + "=" * 60)
    print("TEST: Quick Scan — Multiple Domains")
    print("=" * 60)

    for domain in domains:
        try:
            r = quick_scan(domain)
            results[domain] = r
            status = "✅" if r["error"] is None else "❌"
            score = r["risk"]["score"] if r["risk"] else "N/A"
            ms = r["duration_ms"]
            print(f"  {status} {domain}: {score}/1000 in {ms:.0f}ms")
        except Exception as e:
            print(f"  ❌ {domain}: EXCEPTION — {e}")
            results[domain] = {"error": str(e)}

    print(f"\n{'Domain':<20} {'Risk':>6} {'Class':<20} {'TLS':>8} {'Time':>8}")
    print("-" * 65)
    for domain, r in results.items():
        if r.get("risk"):
            print(f"{domain:<20} {r['risk']['score']:>6} {r['risk']['classification']:<20} {(r['tls'] or {}).get('negotiated_protocol', 'N/A'):>8} {r['duration_ms']:>7.0f}ms")

    print(f"\n✅ Multi-domain test complete")
    return results


if __name__ == "__main__":
    test_quick_scan_pnb()
    print()
    test_quick_scan_multiple()
