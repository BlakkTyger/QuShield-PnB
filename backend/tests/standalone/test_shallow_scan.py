#!/usr/bin/env python3
"""
Standalone test for Shallow Scanner service.

Tests shallow_scan() against a real banking domain to verify:
- CT discovery finds subdomains
- DNS resolution works in parallel
- TLS scans complete on top-N subdomains
- Total time < 90 seconds
"""
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.shallow_scanner import (
    discover_subdomains_ct,
    resolve_subdomains_parallel,
    shallow_scan,
)


def test_ct_discovery():
    """Test crt.sh subdomain discovery."""
    print("=" * 60)
    print("TEST: CT Discovery — pnb.bank.in")
    print("=" * 60)

    start = time.time()
    subs = discover_subdomains_ct("pnb.bank.in")
    elapsed = time.time() - start

    print(f"Found {len(subs)} subdomains in {elapsed*1000:.0f}ms")
    assert len(subs) >= 1, "Should find at least the root domain"
    assert "pnb.bank.in" in subs, "Root domain should be in results"

    # Show first 15
    for s in subs[:15]:
        print(f"  {s}")
    if len(subs) > 15:
        print(f"  ... and {len(subs) - 15} more")

    print(f"\n✅ PASS — {len(subs)} subdomains in {elapsed*1000:.0f}ms")
    return subs


def test_dns_resolution(subdomains):
    """Test parallel DNS resolution."""
    print("\n" + "=" * 60)
    print(f"TEST: DNS Resolution — {len(subdomains)} subdomains")
    print("=" * 60)

    start = time.time()
    live = resolve_subdomains_parallel(subdomains)
    elapsed = time.time() - start

    print(f"Live: {len(live)}/{len(subdomains)} in {elapsed*1000:.0f}ms")
    for a in live[:10]:
        print(f"  {a['hostname']} → {a['ip']}")
    if len(live) > 10:
        print(f"  ... and {len(live) - 10} more")

    assert len(live) >= 1, "At least root domain should resolve"
    print(f"\n✅ PASS — {len(live)} live hosts in {elapsed*1000:.0f}ms")
    return live


def test_shallow_scan_full():
    """Test full shallow scan pipeline."""
    print("\n" + "=" * 60)
    print("TEST: Full Shallow Scan — pnb.bank.in")
    print("=" * 60)

    start = time.time()
    result = shallow_scan("pnb.bank.in", top_n=10)
    elapsed = time.time() - start

    print(f"\nDuration: {result['duration_ms']:.0f}ms (wall: {elapsed*1000:.0f}ms)")
    print(f"Error: {result.get('error')}")

    # Discovery
    d = result["discovery"]
    print(f"\nDiscovery:")
    print(f"  CT subdomains: {d['total_subdomains_found']}")
    print(f"  Live subdomains: {d['live_subdomains']}")
    print(f"  Scanned: {d['scanned_count']}")
    print(f"  Discovery: {d['discovery_ms']:.0f}ms, DNS: {d['dns_resolution_ms']:.0f}ms")

    # Assets
    print(f"\nAssets ({len(result['assets'])}):")
    for a in result["assets"]:
        if a.get("risk"):
            proto = (a.get("tls") or {}).get("negotiated_protocol", "?")
            print(f"  {a['hostname']:<35} {a['risk']['score']:>4}/1000 ({a['risk']['classification']:<20}) TLS={proto}")
        else:
            print(f"  {a['hostname']:<35} ERROR: {a.get('error', 'unknown')}")

    # Summary
    s = result["summary"]
    print(f"\nSummary:")
    print(f"  Vulnerable: {s['quantum_vulnerable']}/{s['successful_scans']}")
    print(f"  TLS 1.3: {s['tls_1_3_count']}")
    print(f"  Forward secrecy: {s['forward_secrecy_count']}")
    print(f"  Avg risk: {s['avg_risk_score']}/1000 — {s['avg_risk_classification']}")

    # Timing
    t = s["timing"]
    print(f"\nTiming:")
    print(f"  Discovery: {t['discovery_ms']:.0f}ms")
    print(f"  DNS: {t['dns_ms']:.0f}ms")
    print(f"  TLS scan: {t['tls_scan_ms']:.0f}ms")
    print(f"  Total: {result['duration_ms']:.0f}ms")

    # Assertions
    assert result["error"] is None, f"Unexpected error: {result['error']}"
    assert len(result["assets"]) > 0, "Should have at least 1 asset"
    assert result["summary"]["successful_scans"] > 0, "Should have at least 1 successful scan"
    assert elapsed < 90, f"Shallow scan too slow: {elapsed:.1f}s (target: <90s)"

    print(f"\n✅ PASS — {elapsed*1000:.0f}ms (target: <90000ms)")
    return result


if __name__ == "__main__":
    subs = test_ct_discovery()
    live = test_dns_resolution(subs)
    test_shallow_scan_full()
