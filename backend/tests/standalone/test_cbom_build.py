"""
Standalone tests for the CBOM Builder.

Tests CycloneDX 1.6 CBOM generation, file storage, DB persistence,
aggregate CBOM, and CVE lookup.
"""
import pytest
import json
import sys
import os
import uuid

# Ensure backend path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# ─── P3.1: CBOM Build Tests ─────────────────────────────────────────────────

class TestCBOMBuild:
    """Test CycloneDX 1.6 CBOM generation."""

    def test_build_cbom_from_mock(self):
        """Build CBOM from a mock crypto fingerprint (RSA-2048 + AES-256-GCM + TLS 1.2)."""
        from app.services.cbom_builder import build_cbom

        mock_fp = {
            "hostname": "test.example.com",
            "port": 443,
            "tls": {
                "versions_supported": ["TLSv1.2"],
                "cipher_suites": [
                    {
                        "name": "ECDHE-RSA-AES256-GCM-SHA384",
                        "tls_version": "TLSv1.2",
                        "key_size": 256,
                        "quantum": {
                            "nist_level": 0,
                            "is_quantum_vulnerable": True,
                            "quantum_status": "vulnerable",
                        },
                    },
                    {
                        "name": "AES-256-GCM",
                        "tls_version": "TLSv1.2",
                        "key_size": 256,
                        "quantum": {
                            "nist_level": 5,
                            "is_quantum_vulnerable": False,
                            "quantum_status": "safe",
                        },
                    },
                ],
                "negotiated_cipher": "ECDHE-RSA-AES256-GCM-SHA384",
                "negotiated_protocol": "TLSv1.2",
                "key_exchange": "ECDHE",
                "forward_secrecy": True,
            },
            "certificates": [
                {
                    "common_name": "test.example.com",
                    "issuer": "DigiCert Global Root CA",
                    "chain_position": "leaf",
                    "key_type": "RSA",
                    "key_length": 2048,
                    "signature_algorithm": "RSA-SHA256",
                    "valid_from": "2025-01-01T00:00:00+00:00",
                    "valid_to": "2026-12-31T23:59:59+00:00",
                    "days_until_expiry": 267,
                    "quantum": {
                        "nist_level": 0,
                        "is_quantum_vulnerable": True,
                    },
                },
            ],
            "quantum_summary": {
                "lowest_nist_level": 0,
                "has_vulnerable_crypto": True,
                "has_pqc": False,
            },
        }

        asset_id = str(uuid.uuid4())
        result = build_cbom(asset_id, mock_fp)

        print(f"\n{'='*60}")
        print(f"CBOM Build: mock crypto fingerprint")
        print(f"  Components: {result['stats']['total_components']}")
        print(f"  Algorithms: {result['stats']['algorithm_components']}")
        print(f"  Certificates: {result['stats']['certificate_components']}")
        print(f"  Protocols: {result['stats']['protocol_components']}")
        print(f"  Vulnerable: {result['stats']['vulnerable_count']}")
        print(f"  Safe: {result['stats']['safe_count']}")
        print(f"  Quantum Ready: {result['stats']['quantum_ready_pct']}%")
        print(f"  JSON Size: {result['stats']['json_size_bytes']} bytes")
        print(f"{'='*60}")

        # Assertions per plan
        assert result["stats"]["total_components"] >= 3, \
            f"Expected 3+ components, got {result['stats']['total_components']}"
        assert result["cbom_json"], "CBOM JSON should not be empty"

        # Verify valid JSON
        parsed = json.loads(result["cbom_json"])
        assert parsed["bomFormat"] == "CycloneDX"
        assert parsed["specVersion"] == "1.6"
        assert len(parsed["components"]) >= 3

        # Check quantum levels in components
        for comp_meta in result["components"]:
            if comp_meta["name"] == "AES-256-GCM":
                assert comp_meta["nist_level"] == 5, "AES-256-GCM should be NIST level 5"
            if comp_meta["name"] == "ECDHE-RSA-AES256-GCM-SHA384":
                assert comp_meta["nist_level"] == 0, "ECDHE-RSA cipher should be level 0 (vulnerable)"

        # Print component details
        for comp_meta in result["components"]:
            print(f"  [{comp_meta['type']}] {comp_meta['name']}: "
                  f"NIST={comp_meta.get('nist_level', 'N/A')}, "
                  f"vulnerable={comp_meta.get('is_vulnerable', 'N/A')}")

    def test_build_cbom_from_real_scan(self):
        """Build CBOM from a real crypto inspection of pnb.bank.in."""
        from app.services.crypto_inspector import inspect_asset
        from app.services.cbom_builder import build_cbom

        fp = inspect_asset("pnb.bank.in")
        assert fp["error"] is None, f"Inspection error: {fp['error']}"

        asset_id = str(uuid.uuid4())
        result = build_cbom(asset_id, fp)

        print(f"\n{'='*60}")
        print(f"CBOM Build: pnb.bank.in (real scan)")
        print(f"  Total Components: {result['stats']['total_components']}")
        print(f"  Vulnerable: {result['stats']['vulnerable_count']}")
        print(f"  Safe: {result['stats']['safe_count']}")
        print(f"  Quantum Ready: {result['stats']['quantum_ready_pct']}%")
        print(f"  JSON Size: {result['stats']['json_size_bytes']} bytes")
        for comp_meta in result["components"]:
            print(f"    [{comp_meta['type']}] {comp_meta['name']}")
        print(f"{'='*60}")

        assert result["stats"]["total_components"] >= 2, \
            "Expected at least 2 components (cipher + cert)"

        # Verify valid CycloneDX JSON
        parsed = json.loads(result["cbom_json"])
        assert parsed["bomFormat"] == "CycloneDX"
        assert parsed["specVersion"] == "1.6"


# ─── P3.2: CBOM File Storage Tests ──────────────────────────────────────────

class TestCBOMStorage:
    """Test CBOM file and DB persistence."""

    def test_save_cbom_to_file(self):
        """Save CBOM JSON to filesystem and verify."""
        from app.services.cbom_builder import build_cbom, save_cbom

        mock_fp = _make_mock_fingerprint()
        asset_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())

        result = build_cbom(asset_id, mock_fp)
        file_path = save_cbom(scan_id, asset_id, result["cbom_json"])

        print(f"\n  CBOM saved to: {file_path}")

        assert os.path.exists(file_path), f"CBOM file not found: {file_path}"

        # Verify contents are valid JSON
        with open(file_path) as f:
            data = json.load(f)
        assert data["bomFormat"] == "CycloneDX"
        print(f"  File size: {os.path.getsize(file_path)} bytes, valid CycloneDX JSON")

        # Cleanup
        os.remove(file_path)
        os.rmdir(os.path.dirname(file_path))

    def test_save_cbom_to_db(self):
        """Save CBOM metadata and components to database."""
        from app.services.cbom_builder import build_cbom, save_cbom, save_cbom_to_db
        from app.core.database import SessionLocal, init_db
        from app.services.asset_manager import create_scan_job, save_discovered_assets
        from app.models.cbom import CBOMRecord, CBOMComponent

        init_db()
        db = SessionLocal()

        try:
            # Create scan + asset
            scan = create_scan_job(targets=["test-cbom.example.com"], db=db)
            mock_assets = [{
                "hostname": "test-cbom.example.com",
                "ip_v4": "1.2.3.4",
                "ports": [{"port": 443, "protocol": "tcp"}],
                "discovery_methods": ["test"],
                "confidence_score": 1.0,
            }]
            saved_assets = save_discovered_assets(str(scan.id), mock_assets, db)
            asset_id = str(saved_assets[0].id)
            scan_id = str(scan.id)

            # Build CBOM
            mock_fp = _make_mock_fingerprint()
            cbom_data = build_cbom(asset_id, mock_fp)
            file_path = save_cbom(scan_id, asset_id, cbom_data["cbom_json"])

            # Save to DB
            record, components = save_cbom_to_db(scan_id, asset_id, cbom_data, file_path, db)

            # Verify
            db_records = db.query(CBOMRecord).filter(CBOMRecord.scan_id == scan.id).all()
            db_components = db.query(CBOMComponent).filter(CBOMComponent.cbom_id == record.id).all()

            print(f"\n  CBOM DB Record: {record.id}")
            print(f"  Total Components: {record.total_components}")
            print(f"  Vulnerable Components: {record.vulnerable_components}")
            print(f"  Quantum Ready: {record.quantum_ready_pct}%")
            print(f"  Components in DB: {len(db_components)}")
            for c in db_components:
                print(f"    [{c.component_type}] {c.name}: NIST={c.nist_quantum_level}")

            assert len(db_records) == 1
            assert len(db_components) >= 3
            assert record.total_components >= 3

            # Cleanup file
            if os.path.exists(file_path):
                os.remove(file_path)
                os.rmdir(os.path.dirname(file_path))

        finally:
            db.rollback()
            db.close()


# ─── P3.3: CBOM Aggregate Tests ─────────────────────────────────────────────

class TestCBOMAggregate:
    """Test org-wide aggregate CBOM generation."""

    def test_aggregate_cbom(self):
        """Build aggregate CBOM from multiple per-asset CBOMs."""
        from app.services.cbom_builder import build_cbom, save_cbom, save_cbom_to_db, build_aggregate_cbom
        from app.core.database import SessionLocal, init_db
        from app.services.asset_manager import create_scan_job, save_discovered_assets
        from app.models.cbom import CBOMRecord, CBOMComponent

        init_db()
        db = SessionLocal()

        try:
            # Create scan with 3 mock assets
            scan = create_scan_job(targets=["asset1.test.com", "asset2.test.com", "asset3.test.com"], db=db)
            scan_id = str(scan.id)

            for i, hostname in enumerate(["asset1.test.com", "asset2.test.com", "asset3.test.com"]):
                mock_assets = [{
                    "hostname": hostname,
                    "ip_v4": f"10.0.0.{i+1}",
                    "ports": [{"port": 443, "protocol": "tcp"}],
                    "discovery_methods": ["test"],
                    "confidence_score": 1.0,
                }]
                saved = save_discovered_assets(scan_id, mock_assets, db)
                asset_id = str(saved[0].id)

                mock_fp = _make_mock_fingerprint(hostname=hostname)
                cbom_data = build_cbom(asset_id, mock_fp)
                file_path = save_cbom(scan_id, asset_id, cbom_data["cbom_json"])
                save_cbom_to_db(scan_id, asset_id, cbom_data, file_path, db)

            # Build aggregate
            aggregate = build_aggregate_cbom(scan_id, db)

            print(f"\n{'='*60}")
            print(f"AGGREGATE CBOM: {aggregate['total_assets']} assets")
            print(f"  Raw Components: {aggregate['total_components_raw']}")
            print(f"  Deduplicated: {aggregate['total_components_deduplicated']}")
            print(f"  Vulnerable: {aggregate['vulnerable_components']}")
            print(f"  Safe: {aggregate['safe_components']}")
            print(f"  Quantum Ready: {aggregate['quantum_ready_pct']}%")
            print(f"  NIST Distribution: {aggregate['nist_level_distribution']}")
            print(f"{'='*60}")

            assert aggregate["total_assets"] == 3
            assert aggregate["total_components_deduplicated"] > 0
            assert "quantum_ready_pct" in aggregate

        finally:
            db.rollback()
            db.close()


# ─── P3.4: CVE Lookup Tests ─────────────────────────────────────────────────

class TestCVELookup:
    """Test CVE cross-referencing via NVD API."""

    def test_cve_lookup_openssl(self):
        """Look up CVEs for openssl 1.1.1 — should find multiple."""
        from app.services.cbom_builder import lookup_cves

        cves = lookup_cves("openssl", "1.1.1")
        print(f"\n  OpenSSL 1.1.1 CVEs found: {len(cves)}")
        for cve in cves[:5]:
            print(f"    {cve['cve_id']}: [{cve['severity']}] {cve['description'][:80]}...")

        # OpenSSL 1.1.1 has many known CVEs
        assert len(cves) >= 1, "Expected at least 1 CVE for OpenSSL 1.1.1"

    def test_cve_cache(self):
        """Verify CVE cache returns same results on second call."""
        from app.services.cbom_builder import lookup_cves

        result1 = lookup_cves("openssl", "3.0.0")
        result2 = lookup_cves("openssl", "3.0.0")
        assert result1 == result2, "Cache should return identical results"
        print(f"\n  Cache test: {len(result1)} CVEs, cache hit verified")


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _make_mock_fingerprint(hostname: str = "test.example.com") -> dict:
    """Create a mock crypto fingerprint for testing."""
    return {
        "hostname": hostname,
        "port": 443,
        "tls": {
            "versions_supported": ["TLSv1.2"],
            "cipher_suites": [
                {
                    "name": "ECDHE-RSA-AES256-GCM-SHA384",
                    "tls_version": "TLSv1.2",
                    "key_size": 256,
                    "quantum": {"nist_level": 0, "is_quantum_vulnerable": True},
                },
                {
                    "name": "AES-256-GCM",
                    "tls_version": "TLSv1.2",
                    "key_size": 256,
                    "quantum": {"nist_level": 5, "is_quantum_vulnerable": False},
                },
            ],
            "negotiated_cipher": "ECDHE-RSA-AES256-GCM-SHA384",
            "negotiated_protocol": "TLSv1.2",
            "key_exchange": "ECDHE",
            "forward_secrecy": True,
        },
        "certificates": [
            {
                "common_name": hostname,
                "issuer": "DigiCert Global Root CA",
                "chain_position": "leaf",
                "key_type": "RSA",
                "key_length": 2048,
                "signature_algorithm": "RSA-SHA256",
                "valid_from": "2025-01-01T00:00:00+00:00",
                "valid_to": "2026-12-31T23:59:59+00:00",
                "days_until_expiry": 267,
                "quantum": {"nist_level": 0, "is_quantum_vulnerable": True},
            },
        ],
        "quantum_summary": {
            "lowest_nist_level": 0,
            "has_vulnerable_crypto": True,
            "has_pqc": False,
        },
    }
