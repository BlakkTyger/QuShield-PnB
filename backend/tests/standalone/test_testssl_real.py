#!/usr/bin/env python3
"""
Test testssl_service parser against REAL testssl.sh JSON output.
Run inside Docker:  docker exec qushield_backend python3 -m tests.standalone.test_testssl_real
"""
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.testssl_service import (
    parse_testssl_json,
    _flatten_pretty_json,
    _classify_finding,
)

DEBUG_DIR = "/app/data/testssl"

def test_flatten_and_parse(json_path: str):
    """Load a --jsonfile-pretty JSON, flatten, and parse."""
    print(f"\n{'='*70}")
    print(f"Testing: {json_path}")
    print(f"{'='*70}")

    with open(json_path) as f:
        raw = json.load(f)

    print(f"  JSON type: {type(raw).__name__}")
    if isinstance(raw, dict):
        print(f"  Top-level keys: {list(raw.keys())}")

        # Flatten
        findings = _flatten_pretty_json(raw)
        print(f"  Flattened findings: {len(findings)}")

        if len(findings) == 0:
            print("  ERROR: No findings extracted!")
            return False

        # Show unique finding IDs
        all_ids = [f.get("id", "") for f in findings]
        unique_ids = sorted(set(all_ids))
        print(f"  Unique IDs ({len(unique_ids)}):")
        for fid in unique_ids[:30]:
            section = _classify_finding(fid)
            sev = next((f.get("severity", "?") for f in findings if f.get("id") == fid), "?")
            print(f"    {fid:40s} -> {section:20s} (sev={sev})")
        if len(unique_ids) > 30:
            print(f"    ... and {len(unique_ids)-30} more")

        # Parse
        summary = parse_testssl_json(findings)
        print(f"\n  --- PARSED SUMMARY ---")
        print(f"  Grade: {summary['grade']}")
        print(f"  Total findings: {summary['total_findings']}")
        print(f"  Severity counts: {summary['severity_counts']}")
        print(f"  Sections:")
        for section, items in summary["sections"].items():
            print(f"    {section}: {len(items)} items")
            for item in items[:3]:
                print(f"      [{item['severity']:8s}] {item['id']:35s} {item['finding'][:80]}")
            if len(items) > 3:
                print(f"      ... and {len(items)-3} more")

        print(f"\n  Protocol support:")
        for proto, info in summary.get("protocol_support", {}).items():
            print(f"    {proto}: offered={info['offered']}, detail={info['detail'][:60]}")

        print(f"\n  Vulnerabilities:")
        for vuln_id, info in summary.get("vuln_status", {}).items():
            status = "VULNERABLE" if info["vulnerable"] else "OK"
            print(f"    {vuln_id:25s}: {status:12s} {info.get('cve', '')}")

        print(f"\n  Cipher strength: {summary.get('cipher_strength', {})}")

        # Assertions
        assert summary["total_findings"] > 0, "Expected > 0 findings"
        assert summary["grade"] in ("A", "A+", "B", "C", "D", "F"), f"Unexpected grade: {summary['grade']}"
        assert len(summary["sections"]["protocols"]) > 0, "Expected protocol findings"
        assert len(summary["sections"]["vulnerabilities"]) > 0, "Expected vulnerability findings"

        print(f"\n  ✓ ALL ASSERTIONS PASSED")
        return True
    elif isinstance(raw, list):
        print(f"  Already flat list: {len(raw)} items")
        summary = parse_testssl_json(raw)
        print(f"  Grade: {summary['grade']}, findings: {summary['total_findings']}")
        return summary["total_findings"] > 0
    else:
        print(f"  ERROR: Unexpected type {type(raw)}")
        return False


if __name__ == "__main__":
    # Find all debug JSON files
    files = []
    if os.path.isdir(DEBUG_DIR):
        for fname in sorted(os.listdir(DEBUG_DIR)):
            if fname.endswith(".json") and "raw" in fname:
                files.append(os.path.join(DEBUG_DIR, fname))

    if not files:
        print(f"No debug JSON files found in {DEBUG_DIR}")
        print("Run testssl.sh first: /app/testssl.sh/testssl.sh --jsonfile-pretty /app/data/testssl/debug_<host>.json <host>")
        sys.exit(1)

    passed = 0
    failed = 0
    for fpath in files:
        try:
            if test_flatten_and_parse(fpath):
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  EXCEPTION: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*70}")
    print(f"RESULTS: {passed} passed, {failed} failed out of {len(files)} files")
    print(f"{'='*70}")
    sys.exit(0 if failed == 0 else 1)
