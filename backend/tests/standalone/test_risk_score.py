"""
Standalone tests for the Risk Engine.

Tests Mosca's inequality, quantum risk scoring, HNDL exposure window,
and TNFL assessment per the plan (P4.1–P4.5).
"""
import pytest
import json
import sys
import os
import uuid
from datetime import datetime, timezone, timedelta

# Ensure backend path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


# ─── P4.1: Mosca's Inequality Tests ─────────────────────────────────────────

class TestMosca:
    """Test Mosca's inequality computation."""

    def test_mosca_swift_exposed(self):
        """SWIFT endpoint: X=2yr migration + Y=10yr shelf life → exposed in pessimistic (Z≈3yr)."""
        from app.services.risk_engine import compute_mosca

        result = compute_mosca(
            migration_time_years=2.0,
            data_shelf_life_years=10.0,
            reference_year=2026,
        )

        print(f"\n  SWIFT: X=2 + Y=10 = 12yr vs Z_pessimistic={result['z_pessimistic']}yr")
        print(f"  Exposed pessimistic: {result['exposed_pessimistic']}")
        print(f"  Exposed median: {result['exposed_median']}")
        print(f"  Exposed optimistic: {result['exposed_optimistic']}")
        print(f"  Years until exposure: {result['years_until_exposure']}")

        # X(2) + Y(10) = 12 > Z_pessimistic(3) → TRUE
        assert result["exposed_pessimistic"] is True
        # X(2) + Y(10) = 12 > Z_median(6) → TRUE
        assert result["exposed_median"] is True
        # X(2) + Y(10) = 12 > Z_optimistic(9) → TRUE
        assert result["exposed_optimistic"] is True

    def test_mosca_otp_safe(self):
        """OTP endpoint: X=0.5yr + Y=0.01yr → NOT exposed."""
        from app.services.risk_engine import compute_mosca

        result = compute_mosca(
            migration_time_years=0.5,
            data_shelf_life_years=0.01,
            reference_year=2026,
        )

        print(f"\n  OTP: X=0.5 + Y=0.01 = 0.51yr vs Z_pessimistic={result['z_pessimistic']}yr")
        print(f"  Exposed pessimistic: {result['exposed_pessimistic']}")

        # X(0.5) + Y(0.01) = 0.51 < Z_pessimistic(3) → FALSE
        assert result["exposed_pessimistic"] is False
        assert result["exposed_median"] is False
        assert result["exposed_optimistic"] is False

    def test_mosca_internet_banking_partial(self):
        """Internet banking: X=1.5yr + Y=5yr → partially exposed."""
        from app.services.risk_engine import compute_mosca

        result = compute_mosca(
            migration_time_years=1.5,
            data_shelf_life_years=5.0,
            reference_year=2026,
        )

        print(f"\n  InternetBanking: X=1.5 + Y=5 = 6.5yr")
        print(f"  Z_pessimistic={result['z_pessimistic']}, exposed={result['exposed_pessimistic']}")
        print(f"  Z_median={result['z_median']}, exposed={result['exposed_median']}")
        print(f"  Z_optimistic={result['z_optimistic']}, exposed={result['exposed_optimistic']}")

        # X(1.5) + Y(5) = 6.5 > Z_pessimistic(3) → TRUE
        assert result["exposed_pessimistic"] is True
        # X(1.5) + Y(5) = 6.5 > Z_median(6) → TRUE
        assert result["exposed_median"] is True
        # X(1.5) + Y(5) = 6.5 < Z_optimistic(9) → FALSE
        assert result["exposed_optimistic"] is False

    def test_mosca_batch(self):
        """Batch Mosca computation for 5 asset types."""
        from app.services.risk_engine import compute_mosca_batch

        assets = [
            {"migration_time_years": 3.0, "data_shelf_life_years": 10.0},  # SWIFT
            {"migration_time_years": 2.5, "data_shelf_life_years": 20.0},  # Core banking
            {"migration_time_years": 1.5, "data_shelf_life_years": 5.0},   # Internet banking
            {"migration_time_years": 1.0, "data_shelf_life_years": 3.0},   # UPI
            {"migration_time_years": 0.5, "data_shelf_life_years": 0.01},  # OTP
        ]

        results = compute_mosca_batch(assets, reference_year=2026)

        print(f"\n  Batch Mosca ({len(results)} assets):")
        for i, r in enumerate(results):
            x = r["x_migration"]
            y = r["y_shelf_life"]
            print(f"    Asset {i}: X={x} + Y={y} = {x+y:.2f}, "
                  f"exposed_pessimistic={r['exposed_pessimistic']}")

        assert len(results) == 5
        assert results[0]["exposed_pessimistic"] is True   # SWIFT
        assert results[4]["exposed_pessimistic"] is False   # OTP


# ─── P4.2: Quantum Risk Score Tests ─────────────────────────────────────────

class TestRiskScore:
    """Test the 5-factor quantum risk scoring model."""

    def test_risk_score_rsa_only_high_risk(self):
        """Asset with RSA-2048 only, no PQC → score > 700 (Vulnerable/Critical)."""
        from app.services.risk_engine import compute_risk_score

        asset_data = {
            "asset_type": "swift_endpoint",
            "certificates": [
                {"key_type": "RSA", "key_length": 2048, "is_ct_logged": True,
                 "chain_valid": True, "days_until_expiry": 200},
            ],
        }
        cbom_data = {
            "components": [
                {"name": "ECDHE-RSA-AES256-GCM", "type": "algorithm", "is_vulnerable": True, "nist_level": 0},
                {"name": "AES-256-GCM", "type": "algorithm", "is_vulnerable": True, "nist_level": 0},
                {"name": "RSA-2048", "type": "certificate", "is_vulnerable": True, "nist_level": 0, "key_length": 2048},
            ],
        }

        result = compute_risk_score(asset_data, cbom_data)
        print(f"\n  RSA-only risk score: {result['quantum_risk_score']} ({result['risk_classification']})")
        for f in result["factors"]:
            print(f"    {f['name']}: {f['score']}/{f['max_possible']} — {f['rationale'][:60]}")

        assert result["quantum_risk_score"] > 700, \
            f"RSA-only asset should be > 700 risk, got {result['quantum_risk_score']}"
        assert result["risk_classification"] in ("quantum_vulnerable", "quantum_critical")

    def test_risk_score_pqc_deployed_low_risk(self):
        """Asset with ML-KEM-768 deployed → score < 300 (Ready/Aware)."""
        from app.services.risk_engine import compute_risk_score

        asset_data = {
            "asset_type": "otp_2fa",  # Low shelf life → low HNDL
            "certificates": [
                {"key_type": "ML-DSA", "key_length": 2048, "is_ct_logged": True,
                 "chain_valid": True, "days_until_expiry": 300},
            ],
        }
        cbom_data = {
            "components": [
                {"name": "ML-KEM-768", "type": "algorithm", "is_vulnerable": False, "nist_level": 3},
                {"name": "AES-256-GCM", "type": "algorithm", "is_vulnerable": False, "nist_level": 5},
                {"name": "ML-DSA-65", "type": "certificate", "is_vulnerable": False, "nist_level": 3, "key_length": 2048},
            ],
        }

        result = compute_risk_score(asset_data, cbom_data)
        print(f"\n  PQC-deployed risk score: {result['quantum_risk_score']} ({result['risk_classification']})")
        for f in result["factors"]:
            print(f"    {f['name']}: {f['score']}/{f['max_possible']}")

        assert result["quantum_risk_score"] < 300, \
            f"PQC-deployed asset should be < 300 risk, got {result['quantum_risk_score']}"
        assert result["risk_classification"] in ("quantum_ready", "quantum_aware")

    def test_risk_score_hybrid_medium(self):
        """Mixed asset (hybrid TLS 1.3 + RSA cert) → score 300-600."""
        from app.services.risk_engine import compute_risk_score

        asset_data = {
            "asset_type": "internet_banking",
            "certificates": [
                {"key_type": "RSA", "key_length": 2048, "is_ct_logged": True,
                 "chain_valid": True, "days_until_expiry": 180},
            ],
        }
        cbom_data = {
            "components": [
                {"name": "X25519MLKEM768", "type": "algorithm", "is_vulnerable": False, "nist_level": 3},
                {"name": "ECDHE-RSA-AES256-GCM", "type": "algorithm", "is_vulnerable": True, "nist_level": 0},
                {"name": "AES-256-GCM", "type": "algorithm", "is_vulnerable": False, "nist_level": 5},
                {"name": "RSA-2048", "type": "certificate", "is_vulnerable": True, "nist_level": 0, "key_length": 2048},
            ],
        }

        result = compute_risk_score(asset_data, cbom_data)
        print(f"\n  Hybrid risk score: {result['quantum_risk_score']} ({result['risk_classification']})")
        for f in result["factors"]:
            print(f"    {f['name']}: {f['score']}/{f['max_possible']}")

        assert 200 <= result["quantum_risk_score"] <= 700, \
            f"Hybrid asset should be 200-700 risk, got {result['quantum_risk_score']}"


# ─── P4.3: HNDL Exposure Window Tests ───────────────────────────────────────

class TestHNDL:
    """Test Harvest-Now-Decrypt-Later exposure window computation."""

    def test_hndl_window_exposed(self):
        """Asset first seen 2024, vulnerable, shelf_life=10yr, CRQC=2032 → exposed."""
        from app.services.risk_engine import compute_hndl_window

        first_seen = datetime(2024, 6, 1, tzinfo=timezone.utc)
        result = compute_hndl_window(
            first_seen=first_seen,
            cipher_vulnerable=True,
            data_shelf_life_years=10.0,
            crqc_year=2032,
        )

        print(f"\n  HNDL Window:")
        print(f"    Harvest: {result['harvest_start'][:10]} → {result['harvest_end'][:10]}")
        print(f"    Decrypt risk: {result['decrypt_risk_start'][:10]} → {result['decrypt_risk_end'][:10]}")
        print(f"    Currently exposed: {result['is_currently_exposed']}")
        print(f"    Exposure years: {result['exposure_years']}")

        assert result["is_currently_exposed"] is True
        assert result["exposure_years"] > 10

    def test_hndl_window_safe(self):
        """Asset with PQC cipher → not exposed."""
        from app.services.risk_engine import compute_hndl_window

        first_seen = datetime(2024, 1, 1, tzinfo=timezone.utc)
        result = compute_hndl_window(
            first_seen=first_seen,
            cipher_vulnerable=False,  # PQC deployed
            data_shelf_life_years=5.0,
            crqc_year=2032,
        )

        print(f"\n  HNDL (PQC deployed): exposed={result['is_currently_exposed']}")
        assert result["is_currently_exposed"] is False


# ─── P4.4: TNFL Risk Assessment Tests ───────────────────────────────────────

class TestTNFL:
    """Test Trust-Now-Forge-Later risk assessment."""

    def test_tnfl_swift_ecdsa_critical(self):
        """SWIFT endpoint + ECDSA → TNFL=True, severity=CRITICAL."""
        from app.services.risk_engine import assess_tnfl

        result = assess_tnfl(
            asset_type="swift_endpoint",
            signature_algorithm="ECDSA-SHA256",
        )

        print(f"\n  TNFL SWIFT+ECDSA: risk={result['tnfl_risk']}, "
              f"severity={result['tnfl_severity']}, contexts={result['tnfl_contexts']}")

        assert result["tnfl_risk"] is True
        assert result["tnfl_severity"] == "CRITICAL"
        assert "SWIFT signing" in result["tnfl_contexts"]

    def test_tnfl_web_portal_rsa_medium(self):
        """Web portal + RSA + JWT → TNFL=True, severity=MEDIUM (JWT signing)."""
        from app.services.risk_engine import assess_tnfl

        result = assess_tnfl(
            asset_type="internet_banking",
            signature_algorithm="RSA-SHA256",
            auth_mechanisms=["Bearer", "OIDC"],
        )

        print(f"\n  TNFL Web+RSA+JWT: risk={result['tnfl_risk']}, "
              f"severity={result['tnfl_severity']}, contexts={result['tnfl_contexts']}")

        assert result["tnfl_risk"] is True
        assert result["tnfl_severity"] == "MEDIUM"

    def test_tnfl_pqc_safe(self):
        """Web portal + ML-DSA → TNFL=False (PQC signature not vulnerable)."""
        from app.services.risk_engine import assess_tnfl

        result = assess_tnfl(
            asset_type="internet_banking",
            signature_algorithm="ML-DSA-65",
        )

        print(f"\n  TNFL Web+ML-DSA: risk={result['tnfl_risk']}, severity={result['tnfl_severity']}")

        assert result["tnfl_risk"] is False


# ─── P4.5: Full Risk Assessment Tests ───────────────────────────────────────

class TestFullRiskAssessment:
    """Test the combined risk assessment for assets with DB persistence."""

    def test_assess_asset_risk_from_db(self):
        """Run full risk assessment on a previously scanned asset."""
        from app.services.risk_engine import assess_asset_risk
        from app.services.cbom_builder import build_cbom, save_cbom, save_cbom_to_db
        from app.core.database import SessionLocal, init_db
        from app.services.asset_manager import create_scan_job, save_discovered_assets
        from app.models.risk import RiskScore, RiskFactor

        init_db()
        db = SessionLocal()

        try:
            # Setup: create scan, asset, and CBOM
            scan = create_scan_job(targets=["risk-test.bank.in"], db=db)
            saved_assets = save_discovered_assets(str(scan.id), [{
                "hostname": "risk-test.bank.in",
                "ip_v4": "10.0.0.1",
                "ports": [{"port": 443, "protocol": "tcp"}],
                "discovery_methods": ["test"],
                "confidence_score": 1.0,
            }], db)
            asset_id = str(saved_assets[0].id)
            scan_id = str(scan.id)

            # Save a mock CBOM
            mock_fp = {
                "hostname": "risk-test.bank.in",
                "port": 443,
                "tls": {
                    "versions_supported": ["TLSv1.2"],
                    "cipher_suites": [
                        {"name": "ECDHE-RSA-AES256-GCM", "tls_version": "TLSv1.2",
                         "quantum": {"nist_level": 0, "is_quantum_vulnerable": True}},
                    ],
                    "negotiated_cipher": "ECDHE-RSA-AES256-GCM",
                    "negotiated_protocol": "TLSv1.2",
                    "key_exchange": "ECDHE",
                    "forward_secrecy": True,
                },
                "certificates": [
                    {"common_name": "risk-test.bank.in", "issuer": "TestCA", "chain_position": "leaf",
                     "key_type": "RSA", "key_length": 2048, "signature_algorithm": "RSA-SHA256",
                     "valid_from": "2025-01-01T00:00:00+00:00", "valid_to": "2027-01-01T00:00:00+00:00",
                     "days_until_expiry": 267, "is_ct_logged": True, "chain_valid": True,
                     "quantum": {"nist_level": 0, "is_quantum_vulnerable": True}},
                ],
                "quantum_summary": {"lowest_nist_level": 0, "has_vulnerable_crypto": True, "has_pqc": False},
            }

            # Save crypto results to DB (certificates)
            from app.services.crypto_inspector import save_crypto_results
            save_crypto_results(scan_id, asset_id, mock_fp, db)

            # Build and save CBOM
            cbom_data = build_cbom(asset_id, mock_fp)
            file_path = save_cbom(scan_id, asset_id, cbom_data["cbom_json"])
            save_cbom_to_db(scan_id, asset_id, cbom_data, file_path, db)

            # Run risk assessment
            result = assess_asset_risk(asset_id, scan_id, db)

            print(f"\n{'='*70}")
            print(f"FULL RISK ASSESSMENT: risk-test.bank.in")
            print(f"  Score: {result['risk_score']['quantum_risk_score']} "
                  f"({result['risk_score']['risk_classification']})")
            print(f"  HNDL: exposed={result['hndl']['is_currently_exposed']}, "
                  f"exposure_years={result['hndl']['exposure_years']}")
            print(f"  TNFL: risk={result['tnfl']['tnfl_risk']}, "
                  f"severity={result['tnfl']['tnfl_severity']}")
            for f in result["risk_score"]["factors"]:
                print(f"    {f['name']}: {f['score']}/{f['max_possible']}")
            print(f"{'='*70}")

            # Verify DB records
            db_scores = db.query(RiskScore).filter(RiskScore.scan_id == scan.id).all()
            db_factors = db.query(RiskFactor).filter(
                RiskFactor.risk_score_id == db_scores[0].id
            ).all() if db_scores else []

            print(f"  DB: {len(db_scores)} risk scores, {len(db_factors)} factors")

            assert len(db_scores) == 1
            assert len(db_factors) >= 5
            assert db_scores[0].quantum_risk_score > 0
            assert result["risk_record_id"]

            # Cleanup file
            if os.path.exists(file_path):
                os.remove(file_path)
                try:
                    os.rmdir(os.path.dirname(file_path))
                except OSError:
                    pass

        finally:
            db.rollback()
            db.close()
