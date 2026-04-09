"""
Standalone tests for the Crypto Inspector.
Tests against real Indian banking domains per user requirement:
  - pnb.bank.in
  - onlinesbi.sbi.bank.in
  - www.hdfc.bank.in
"""
import pytest
import json
import sys
import os

# Ensure backend path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# ─── P2.1: TLS Scan Tests ───────────────────────────────────────────────────

class TestTLSScan:
    """Test TLS handshake and cipher suite enumeration."""

    def test_scan_tls_pnb(self):
        """TLS scan against pnb.bank.in — expect TLS 1.2+."""
        from app.services.crypto_inspector import scan_tls

        result = scan_tls("pnb.bank.in", 443)
        print(f"\n{'='*60}")
        print(f"TLS Scan: pnb.bank.in")
        print(f"  Versions: {result['tls_versions_supported']}")
        print(f"  Negotiated: {result['negotiated_cipher']} ({result['negotiated_protocol']})")
        print(f"  Key Exchange: {result['key_exchange']}")
        print(f"  Forward Secrecy: {result['forward_secrecy']}")
        print(f"  Cipher count: {len(result['cipher_suites'])}")
        print(f"  Cert chain: {len(result['certificate_chain_pem'])} certs")
        print(f"{'='*60}")

        assert result["error"] is None, f"TLS scan error: {result['error']}"
        assert len(result["tls_versions_supported"]) >= 1
        assert len(result["cipher_suites"]) >= 1
        assert result["negotiated_cipher"] is not None

    def test_scan_tls_sbi(self):
        """TLS scan against onlinesbi.sbi.bank.in."""
        from app.services.crypto_inspector import scan_tls

        result = scan_tls("onlinesbi.sbi.bank.in", 443)
        print(f"\n{'='*60}")
        print(f"TLS Scan: onlinesbi.sbi.bank.in")
        print(f"  Versions: {result['tls_versions_supported']}")
        print(f"  Negotiated: {result['negotiated_cipher']} ({result['negotiated_protocol']})")
        print(f"  Forward Secrecy: {result['forward_secrecy']}")
        print(f"  Cipher count: {len(result['cipher_suites'])}")
        print(f"{'='*60}")

        assert result["error"] is None, f"TLS scan error: {result['error']}"
        assert len(result["tls_versions_supported"]) >= 1

    def test_scan_tls_hdfc(self):
        """TLS scan against www.hdfc.bank.in."""
        from app.services.crypto_inspector import scan_tls

        result = scan_tls("www.hdfc.bank.in", 443)
        print(f"\n{'='*60}")
        print(f"TLS Scan: www.hdfc.bank.in")
        print(f"  Versions: {result['tls_versions_supported']}")
        print(f"  Negotiated: {result['negotiated_cipher']} ({result['negotiated_protocol']})")
        print(f"  Forward Secrecy: {result['forward_secrecy']}")
        print(f"  Cipher count: {len(result['cipher_suites'])}")
        print(f"{'='*60}")

        assert result["error"] is None, f"TLS scan error: {result['error']}"


# ─── P2.2: Certificate Parsing Tests ────────────────────────────────────────

class TestCertParse:
    """Test certificate chain parsing."""

    def test_parse_pnb_cert_chain(self):
        """Parse cert chain from pnb.bank.in."""
        from app.services.crypto_inspector import scan_tls, parse_certificate_chain

        tls = scan_tls("pnb.bank.in", 443)
        assert tls["certificate_chain_pem"], "No certs in chain"

        chain = parse_certificate_chain(tls["certificate_chain_pem"])
        print(f"\n{'='*60}")
        print(f"Certificate Chain: pnb.bank.in ({len(chain)} certs)")
        for cert in chain:
            print(f"  [{cert['chain_position']}] {cert['common_name']}")
            print(f"    Key: {cert['key_type']}-{cert['key_length']}")
            print(f"    Issuer: {cert['issuer']} ({cert['ca_name']})")
            print(f"    Sig Algo: {cert['signature_algorithm']}")
            print(f"    Valid: {cert['valid_from'][:10]} → {cert['valid_to'][:10]} ({cert['days_until_expiry']}d)")
            print(f"    CT Logged: {cert['is_ct_logged']}")
            print(f"    Fingerprint: {cert['sha256_fingerprint'][:16]}...")
        print(f"  Chain Valid: {chain[0]['chain_valid']}")
        print(f"{'='*60}")

        assert len(chain) >= 1
        assert chain[0]["chain_position"] == "leaf"
        assert chain[0]["key_type"] in ("RSA", "EC-prime256v1", "EC-secp256r1", "EC-secp384r1")
        assert chain[0]["key_length"] > 0

    def test_parse_sbi_cert(self):
        """Parse cert from onlinesbi.sbi.bank.in and verify fields."""
        from app.services.crypto_inspector import scan_tls, parse_certificate_chain

        tls = scan_tls("onlinesbi.sbi.bank.in", 443)
        if not tls["certificate_chain_pem"]:
            pytest.skip("No certs retrieved from SBI")

        chain = parse_certificate_chain(tls["certificate_chain_pem"])
        leaf = chain[0]

        print(f"\n  SBI Leaf Cert: {leaf['common_name']}")
        print(f"  Key: {leaf['key_type']}-{leaf['key_length']}, SAN count: {len(leaf['san_list'])}")

        assert leaf["common_name"], "Missing CN"
        assert leaf["signature_algorithm"], "Missing sig algo"

    def test_parse_hdfc_cert(self):
        """Parse cert from www.hdfc.bank.in."""
        from app.services.crypto_inspector import scan_tls, parse_certificate_chain

        tls = scan_tls("www.hdfc.bank.in", 443)
        if not tls["certificate_chain_pem"]:
            pytest.skip("No certs retrieved from HDFC")

        chain = parse_certificate_chain(tls["certificate_chain_pem"])
        print(f"\n  HDFC Chain: {len(chain)} certs, Leaf: {chain[0]['common_name']} ({chain[0]['key_type']}-{chain[0]['key_length']})")

        assert len(chain) >= 1


# ─── P2.3: NIST Quantum Level Tests ─────────────────────────────────────────

class TestQuantumLevel:
    """Test NIST quantum level assignment."""

    def test_rsa_2048_vulnerable(self):
        from app.services.crypto_inspector import get_nist_quantum_level
        result = get_nist_quantum_level("RSA-2048")
        assert result["nist_level"] == 0
        assert result["is_quantum_vulnerable"] is True
        print(f"  RSA-2048 → level={result['nist_level']}, vulnerable={result['is_quantum_vulnerable']}")

    def test_aes_256_safe(self):
        from app.services.crypto_inspector import get_nist_quantum_level
        result = get_nist_quantum_level("AES-256-GCM")
        assert result["nist_level"] == 5
        assert result["is_quantum_vulnerable"] is False
        print(f"  AES-256-GCM → level={result['nist_level']}, vulnerable={result['is_quantum_vulnerable']}")

    def test_ecdhe_vulnerable(self):
        from app.services.crypto_inspector import get_nist_quantum_level
        result = get_nist_quantum_level("ECDHE-RSA")
        assert result["nist_level"] == 0
        assert result["is_quantum_vulnerable"] is True
        print(f"  ECDHE-RSA → level={result['nist_level']}, vulnerable={result['is_quantum_vulnerable']}")

    def test_ml_kem_768_pqc(self):
        from app.services.crypto_inspector import get_nist_quantum_level
        result = get_nist_quantum_level("ML-KEM-768")
        assert result["nist_level"] == 3
        assert result["is_quantum_vulnerable"] is False
        print(f"  ML-KEM-768 → level={result['nist_level']}, vulnerable={result['is_quantum_vulnerable']}")

    def test_tls13_cipher_normalization(self):
        from app.services.crypto_inspector import get_nist_quantum_level
        result = get_nist_quantum_level("TLS_AES_256_GCM_SHA384")
        assert result["nist_level"] == 5
        print(f"  TLS_AES_256_GCM_SHA384 → normalized to {result['matched_as']}, level={result['nist_level']}")

    def test_unknown_algorithm(self):
        from app.services.crypto_inspector import get_nist_quantum_level
        result = get_nist_quantum_level("TOTALLY_UNKNOWN_ALGO")
        assert result["nist_level"] == -1
        assert result["quantum_status"] == "unknown"
        print(f"  TOTALLY_UNKNOWN_ALGO → level={result['nist_level']}, status={result['quantum_status']}")


# ─── P2.4: PQC Detection Tests ──────────────────────────────────────────────

class TestPQCDetect:
    """Test PQC detection against real sites."""

    def test_pqc_pnb(self):
        from app.services.crypto_inspector import detect_pqc
        result = detect_pqc("pnb.bank.in")
        print(f"\n  PQC pnb.bank.in: sig={result['pqc_signature']}, kex={result['pqc_key_exchange']}")
        print(f"    Algorithms: {result['pqc_algorithms_found']}")
        print(f"    Note: {result['note']}")
        # Indian banks likely don't have PQC yet
        assert isinstance(result["pqc_signature"], bool)
        assert isinstance(result["pqc_key_exchange"], bool)

    def test_pqc_sbi(self):
        from app.services.crypto_inspector import detect_pqc
        result = detect_pqc("onlinesbi.sbi.bank.in")
        print(f"\n  PQC onlinesbi.sbi.bank.in: sig={result['pqc_signature']}, kex={result['pqc_key_exchange']}")

    def test_pqc_oid_table_valid(self):
        """Verify the OID table is well-formed."""
        from app.services.crypto_inspector import PQC_OIDS
        assert len(PQC_OIDS) >= 10, f"Expected 10+ PQC OIDs, got {len(PQC_OIDS)}"
        for name, info in PQC_OIDS.items():
            assert "oid" in info, f"Missing OID for {name}"
            assert "nist_level" in info, f"Missing nist_level for {name}"
        print(f"  PQC OID table: {len(PQC_OIDS)} entries, all valid")


# ─── P2.6: Full Inspection Tests ────────────────────────────────────────────

class TestFullCryptoInspection:
    """Test the combined inspect_asset function against Indian bank domains."""

    def test_inspect_pnb(self):
        """Full crypto inspection of pnb.bank.in."""
        from app.services.crypto_inspector import inspect_asset

        fp = inspect_asset("pnb.bank.in")
        print(f"\n{'='*70}")
        print(f"FULL CRYPTO INSPECTION: pnb.bank.in")
        print(f"  TLS Versions: {fp['tls']['versions_supported']}")
        print(f"  Negotiated: {fp['tls']['negotiated_cipher']}")
        print(f"  Forward Secrecy: {fp['tls']['forward_secrecy']}")
        print(f"  Certificates: {len(fp['certificates'])}")
        if fp['certificates']:
            leaf = fp['certificates'][0]
            print(f"    Leaf: {leaf['common_name']} ({leaf['key_type']}-{leaf['key_length']})")
        print(f"  Quantum Summary:")
        qs = fp['quantum_summary']
        print(f"    Lowest NIST Level: {qs['lowest_nist_level']}")
        print(f"    Has Vulnerable Crypto: {qs['has_vulnerable_crypto']}")
        print(f"    Has PQC: {qs['has_pqc']}")
        print(f"    Vulnerable Algos: {qs['vulnerable_algorithms'][:5]}")
        print(f"    Safe Algos: {qs['safe_algorithms'][:5]}")
        print(f"  PQC: sig={fp['pqc']['pqc_signature']}, kex={fp['pqc']['pqc_key_exchange']}")
        print(f"{'='*70}")

        assert fp["error"] is None, f"Inspection error: {fp['error']}"
        assert fp["tls"] is not None
        assert len(fp["certificates"]) >= 1

    def test_inspect_sbi(self):
        """Full crypto inspection of onlinesbi.sbi.bank.in."""
        from app.services.crypto_inspector import inspect_asset

        fp = inspect_asset("onlinesbi.sbi.bank.in")
        print(f"\n  SBI: {fp['tls']['negotiated_cipher']} | "
              f"Certs: {len(fp['certificates'])} | "
              f"PQC: {fp['quantum_summary']['has_pqc']}")

        assert fp["tls"] is not None

    def test_inspect_hdfc(self):
        """Full crypto inspection of www.hdfc.bank.in."""
        from app.services.crypto_inspector import inspect_asset

        fp = inspect_asset("www.hdfc.bank.in")
        print(f"\n  HDFC: {fp['tls']['negotiated_cipher']} | "
              f"Certs: {len(fp['certificates'])} | "
              f"PQC: {fp['quantum_summary']['has_pqc']}")

        assert fp["tls"] is not None

    def test_batch_inspect_all_banks(self):
        """Batch inspect all 3 bank domains."""
        from app.services.crypto_inspector import inspect_assets_batch

        assets = [
            {"hostname": "pnb.bank.in"},
            {"hostname": "onlinesbi.sbi.bank.in"},
            {"hostname": "www.hdfc.bank.in"},
        ]
        results = inspect_assets_batch(assets, max_concurrent=3)

        print(f"\n{'='*70}")
        print("BATCH INSPECTION RESULTS:")
        for i, r in enumerate(results):
            if r and r.get("tls"):
                qs = r.get("quantum_summary", {})
                print(f"  {assets[i]['hostname']}: "
                      f"TLS={r['tls']['negotiated_protocol']} | "
                      f"Cipher={r['tls']['negotiated_cipher']} | "
                      f"FS={r['tls']['forward_secrecy']} | "
                      f"Vulnerable={qs.get('has_vulnerable_crypto')}")
            else:
                print(f"  {assets[i]['hostname']}: FAILED - {r.get('error', 'unknown')}")
        print(f"{'='*70}")

        successful = [r for r in results if r and r.get("tls")]
        assert len(successful) >= 1, "At least one bank should be scannable"


# ─── P2.7: Database Persistence Tests ───────────────────────────────────────

class TestCryptoPersistence:
    """Test saving crypto results to the database."""

    def test_save_to_db(self):
        """Inspect pnb.bank.in and save results to DB."""
        from app.services.crypto_inspector import inspect_asset, save_crypto_results
        from app.core.database import SessionLocal, init_db
        from app.services.asset_manager import create_scan_job, save_discovered_assets
        from app.models.certificate import Certificate

        init_db()
        db = SessionLocal()

        try:
            # Create scan + asset
            scan = create_scan_job(targets=["pnb.bank.in"], db=db)
            mock_assets = [{
                "hostname": "pnb.bank.in",
                "ip_v4": "1.2.3.4",
                "ports": [{"port": 443, "protocol": "tcp"}],
                "discovery_methods": ["test"],
                "confidence_score": 1.0,
            }]
            saved_assets = save_discovered_assets(str(scan.id), mock_assets, db)
            asset_id = str(saved_assets[0].id)

            # Inspect
            fp = inspect_asset("pnb.bank.in")
            assert fp["error"] is None, f"Inspection error: {fp['error']}"

            # Save to DB
            certs = save_crypto_results(str(scan.id), asset_id, fp, db)

            # Verify
            db_certs = db.query(Certificate).filter(Certificate.scan_id == scan.id).all()
            print(f"\n  Saved {len(db_certs)} certificates to DB for pnb.bank.in")
            for c in db_certs:
                print(f"    {c.common_name} | {c.key_type}-{c.key_length} | "
                      f"NIST={c.nist_quantum_level} | Vulnerable={c.is_quantum_vulnerable}")

            assert len(db_certs) >= 1, "At least one cert should be saved"

        finally:
            db.rollback()
            db.close()
