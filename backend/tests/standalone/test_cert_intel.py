"""
Standalone tests for Pre-P5 Hardening enhancements:
  - Certificate Intelligence (effective expiry, CA readiness, multi-SAN)
  - Infrastructure Fingerprinting (hosting, CDN, WAF)
  - Asset Type Classification
  - Certificate Pinning Detection

Test targets (Indian banks per user requirement):
  - pnb.bank.in
  - onlinesbi.sbi.bank.in
  - www.hdfc.bank.in
"""
import pytest
import json
import sys
import os
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# ─── Certificate Intelligence Tests ────────────────────────────────────────


class TestEffectiveExpiry:
    """Test CRQC-adjusted effective security expiry computation."""

    def test_rsa_cert_crqc_limited(self):
        """RSA-2048 cert expiring 2030 — limited by CRQC (2029)."""
        from app.services.crypto_inspector import compute_effective_security_expiry

        result = compute_effective_security_expiry(
            datetime(2030, 12, 31, tzinfo=timezone.utc), "RSA", 2048
        )

        print(f"\n  RSA-2048 expiry 2030: effective={result['effective_expiry']}")
        print(f"    Limited by: {result['limited_by']}")
        print(f"    CRQC-adjusted: {result['crqc_adjusted']}")

        assert result["crqc_adjusted"] is True
        assert result["limited_by"] == "crqc"
        # Effective expiry should be 2029-01-01 (CRQC pessimistic)
        assert "2029" in result["effective_expiry"]

    def test_rsa_cert_calendar_limited(self):
        """RSA-2048 cert expiring 2027 — limited by calendar (before 2029 CRQC)."""
        from app.services.crypto_inspector import compute_effective_security_expiry

        result = compute_effective_security_expiry(
            datetime(2027, 6, 15, tzinfo=timezone.utc), "RSA", 2048
        )

        print(f"\n  RSA-2048 expiry 2027: effective={result['effective_expiry']}")
        print(f"    Limited by: {result['limited_by']}")

        assert result["crqc_adjusted"] is True
        assert result["limited_by"] == "calendar"
        assert "2027" in result["effective_expiry"]

    def test_pqc_cert_no_adjustment(self):
        """ML-DSA cert — no CRQC adjustment needed (PQC-safe)."""
        from app.services.crypto_inspector import compute_effective_security_expiry

        result = compute_effective_security_expiry(
            datetime(2035, 1, 1, tzinfo=timezone.utc), "ML-DSA", None
        )

        print(f"\n  ML-DSA-65 expiry 2035: effective={result['effective_expiry']}")
        print(f"    CRQC-adjusted: {result['crqc_adjusted']}")

        assert result["crqc_adjusted"] is False
        assert "2035" in result["effective_expiry"]

    def test_ecdsa_cert_crqc_limited(self):
        """ECDSA P-256 cert — quantum-vulnerable, CRQC-limited."""
        from app.services.crypto_inspector import compute_effective_security_expiry

        result = compute_effective_security_expiry(
            datetime(2031, 6, 1, tzinfo=timezone.utc), "EC", 256
        )

        print(f"\n  EC-P256 expiry 2031: limited_by={result['limited_by']}")
        assert result["crqc_adjusted"] is True
        assert result["limited_by"] == "crqc"


class TestCAPQCReadiness:
    """Test CA PQC readiness lookup."""

    def test_digicert_has_roadmap(self):
        """DigiCert should have PQC roadmap published."""
        from app.services.crypto_inspector import lookup_ca_pqc_readiness

        ca = lookup_ca_pqc_readiness("DigiCert SHA2 Extended Validation")
        print(f"\n  DigiCert: roadmap={ca['pqc_roadmap_published']}, hybrid={ca['pqc_hybrid_certs_available']}")

        assert ca["pqc_roadmap_published"] is True
        assert ca["pqc_hybrid_certs_available"] is True

    def test_nic_india_no_roadmap(self):
        """NIC India (NICCA) should NOT have PQC roadmap."""
        from app.services.crypto_inspector import lookup_ca_pqc_readiness

        ca = lookup_ca_pqc_readiness("National Informatics Centre")
        print(f"\n  NIC India: roadmap={ca['pqc_roadmap_published']}")

        assert ca["pqc_roadmap_published"] is False

    def test_unknown_ca_fallback(self):
        """Unknown CA should return default entry."""
        from app.services.crypto_inspector import lookup_ca_pqc_readiness

        ca = lookup_ca_pqc_readiness("Some Random CA Corp")
        print(f"\n  Unknown CA: roadmap={ca['pqc_roadmap_published']}")

        assert ca["pqc_roadmap_published"] is False


class TestMultiSANExposure:
    """Test Multi-SAN exposure analysis."""

    def test_high_san_count(self):
        """Many SANs should trigger risk flag."""
        from app.services.crypto_inspector import analyze_multi_san_exposure

        sans = [f"sub{i}.bank.in" for i in range(15)]
        result = analyze_multi_san_exposure(sans)

        print(f"\n  {len(sans)} SANs: multi={result['is_multi_san']}, risk={result['risk_note']}")
        assert result["san_count"] == 15
        assert result["is_multi_san"] is True
        assert result["risk_note"] is not None
        assert "HIGH" in result["risk_note"]

    def test_low_san_count_safe(self):
        """Few SANs should be safe."""
        from app.services.crypto_inspector import analyze_multi_san_exposure

        result = analyze_multi_san_exposure(["example.com", "www.example.com"])
        assert result["san_count"] == 2
        assert result["is_multi_san"] is False
        assert result["risk_note"] is None

    def test_empty_san_list(self):
        """No SANs should return safe defaults."""
        from app.services.crypto_inspector import analyze_multi_san_exposure

        result = analyze_multi_san_exposure(None)
        assert result["san_count"] == 0
        assert result["is_multi_san"] is False


# ─── Asset Type Classification Tests ────────────────────────────────────────


class TestAssetClassification:
    """Test hostname-based asset type classification."""

    def test_internet_banking(self):
        from app.services.crypto_inspector import classify_asset_type

        assert classify_asset_type("onlinesbi.sbi.bank.in") == "internet_banking"
        assert classify_asset_type("netbanking.pnb.bank.in") == "internet_banking"

    def test_admin_portal(self):
        from app.services.crypto_inspector import classify_asset_type
        assert classify_asset_type("admin.pnb.bank.in") == "admin_portal"

    def test_mail_server(self):
        from app.services.crypto_inspector import classify_asset_type
        assert classify_asset_type("mail.pnb.bank.in") == "mail_server"

    def test_dns_server(self):
        from app.services.crypto_inspector import classify_asset_type
        assert classify_asset_type("ns1.pnb.bank.in") == "dns_server"

    def test_api_gateway(self):
        from app.services.crypto_inspector import classify_asset_type
        assert classify_asset_type("api.pnb.bank.in") == "api_gateway"

    def test_payment_gateway(self):
        from app.services.crypto_inspector import classify_asset_type
        assert classify_asset_type("payment.pnb.bank.in") == "payment_gateway"

    def test_www_defaults_to_banking(self):
        from app.services.crypto_inspector import classify_asset_type
        assert classify_asset_type("www.pnb.bank.in") == "internet_banking"

    def test_port_based_dns(self):
        from app.services.crypto_inspector import classify_asset_type
        result = classify_asset_type("unknown.pnb.bank.in", ports=[{"port": 53}])
        assert result == "dns_server"


# ─── Infrastructure Fingerprinting Tests (Network) ──────────────────────────


class TestInfrastructureDetection:
    """Test hosting, CDN, and WAF detection against real Indian banks."""

    @pytest.mark.network
    def test_pnb_infrastructure(self):
        """Detect hosting/CDN/WAF for PNB."""
        from app.services.crypto_inspector import detect_hosting_and_cdn

        result = detect_hosting_and_cdn("pnb.bank.in")

        print(f"\n  PNB Infrastructure:")
        print(f"    Hosting: {result['hosting_provider']}")
        print(f"    CDN: {result['cdn_detected']}")
        print(f"    WAF: {result['waf_detected']}")
        print(f"    Server: {result['server_header']}")
        print(f"    Behind proxy: {result['is_behind_proxy']}")

        # PNB should be detected (some field should be non-None)
        has_detection = (
            result["hosting_provider"] is not None
            or result["cdn_detected"] is not None
            or result["waf_detected"] is not None
            or result["server_header"] is not None
        )
        assert has_detection, "At least one infrastructure fingerprint should be detected"

    @pytest.mark.network
    def test_sbi_infrastructure(self):
        """Detect hosting/CDN/WAF for SBI."""
        from app.services.crypto_inspector import detect_hosting_and_cdn

        result = detect_hosting_and_cdn("onlinesbi.sbi.bank.in")

        print(f"\n  SBI Infrastructure:")
        print(f"    Hosting: {result['hosting_provider']}")
        print(f"    CDN: {result['cdn_detected']}")
        print(f"    WAF: {result['waf_detected']}")
        print(f"    Server: {result['server_header']}")

    @pytest.mark.network
    def test_hdfc_infrastructure(self):
        """Detect hosting/CDN/WAF for HDFC."""
        from app.services.crypto_inspector import detect_hosting_and_cdn

        result = detect_hosting_and_cdn("www.hdfc.bank.in")

        print(f"\n  HDFC Infrastructure:")
        print(f"    Hosting: {result['hosting_provider']}")
        print(f"    CDN: {result['cdn_detected']}")
        print(f"    WAF: {result['waf_detected']}")
        print(f"    Server: {result['server_header']}")


# ─── Certificate Pinning Detection Tests (Network) ─────────────────────────


class TestCertificatePinning:
    """Test certificate pinning detection."""

    @pytest.mark.network
    def test_pnb_pinning(self):
        """Check certificate pinning headers on PNB."""
        from app.services.crypto_inspector import detect_certificate_pinning

        result = detect_certificate_pinning("pnb.bank.in")

        print(f"\n  PNB Pinning: HPKP={result['hpkp_detected']}, "
              f"Expect-CT={result['expect_ct_detected']}, "
              f"Pinned={result['is_pinned']}")

        # Assert result has expected keys
        assert "is_pinned" in result
        assert "hpkp_detected" in result
        assert "expect_ct_detected" in result


# ─── Full Inspection with Enhancements (Network) ───────────────────────────


class TestFullInspectionEnhanced:
    """Test full inspect_asset with all new enhancements."""

    @pytest.mark.network
    def test_inspect_pnb_full(self):
        """Full crypto inspection of pnb.bank.in with all enhancements."""
        from app.services.crypto_inspector import inspect_asset

        fp = inspect_asset("pnb.bank.in")

        print(f"\n  Full Inspection: pnb.bank.in")
        print(f"    TLS: {fp.get('tls', {}).get('negotiated_protocol')}")
        print(f"    Certs: {len(fp.get('certificates', []))}")
        print(f"    Asset type: {fp.get('asset_type')}")
        print(f"    Infrastructure: {fp.get('infrastructure', {}).get('cdn_detected')}")
        print(f"    Pinned: {fp.get('pinning', {}).get('is_pinned')}")

        # Verify new fields are populated
        assert fp.get("asset_type") is not None, "asset_type should be classified"
        assert fp.get("cert_intelligence") is not None, "cert_intelligence should be present"
        assert fp.get("pinning") is not None, "pinning result should be present"
        assert fp.get("infrastructure") is not None, "infrastructure result should be present"

        # Verify cert intelligence has data if certs exist
        if fp.get("certificates"):
            assert len(fp["cert_intelligence"]) == len(fp["certificates"])
            intel = fp["cert_intelligence"][0]
            assert "effective_expiry" in intel or "ca_readiness" in intel

    @pytest.mark.network
    def test_inspect_pnb_db_persistence(self):
        """Full inspection with DB save — verify new fields persisted."""
        from app.services.crypto_inspector import inspect_asset, save_crypto_results
        from app.services.asset_manager import create_scan_job, save_discovered_assets
        from app.core.database import SessionLocal
        from app.models.certificate import Certificate
        from app.models.asset import Asset

        db = SessionLocal()
        try:
            # Setup — create scan job and asset
            scan_job = create_scan_job(["pnb.bank.in"], db)
            assets = save_discovered_assets(
                str(scan_job.id),
                [{"hostname": "pnb.bank.in", "ip_v4": "49.50.72.184",
                  "discovery_methods": ["test"], "confidence_score": 1.0}],
                db,
            )
            asset = assets[0]

            # Inspect and save
            fp = inspect_asset("pnb.bank.in")
            certs = save_crypto_results(str(scan_job.id), str(asset.id), fp, db)

            # Verify cert intelligence persisted
            if certs:
                cert = db.query(Certificate).filter(Certificate.asset_id == asset.id).first()
                print(f"\n  Persisted cert: {cert.common_name}")
                print(f"    Effective expiry: {cert.effective_security_expiry}")
                print(f"    CA PQC ready: {cert.ca_pqc_ready}")
                print(f"    SAN count: {cert.san_count}")
                print(f"    Pinned: {cert.is_pinned}")

                assert cert.effective_security_expiry is not None
                assert cert.ca_pqc_ready is not None
                assert cert.san_count >= 1

            # Verify asset enrichment persisted
            asset_db = db.query(Asset).filter(Asset.id == asset.id).first()
            print(f"    Asset type: {asset_db.asset_type}")
            print(f"    Hosting: {asset_db.hosting_provider}")
            print(f"    CDN: {asset_db.cdn_detected}")
            print(f"    WAF: {asset_db.waf_detected}")

            assert asset_db.asset_type is not None

        finally:
            db.close()
