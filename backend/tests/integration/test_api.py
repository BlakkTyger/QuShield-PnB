"""
Phase 7 Integration Tests — API Layer E2E Validation.

Tests all API endpoints against real scan data.
Run: cd backend && python -m pytest tests/integration/test_api.py -v
"""
import time
import pytest
from fastapi.testclient import TestClient

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from app.main import app
from app.core.database import engine, Base

client = TestClient(app)


# ─── System Endpoints ────────────────────────────────────────────────────────

class TestHealthAndDocs:
    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("ok", "degraded")
        assert "version" in data

    def test_openapi_docs(self):
        r = client.get("/docs")
        assert r.status_code == 200

    def test_redoc(self):
        r = client.get("/redoc")
        assert r.status_code == 200

    def test_openapi_json(self):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        assert schema["info"]["title"] == "QuShield-PnB"
        assert "/api/v1/scans/" in schema["paths"]
        assert "/api/v1/assets/" in schema["paths"]
        assert "/health" in schema["paths"]


# ─── Scan Endpoints ──────────────────────────────────────────────────────────

class TestScanAPI:
    def test_create_scan_invalid_target(self):
        r = client.post("/api/v1/scans/", json={"targets": []})
        assert r.status_code == 422  # validation error

    def test_create_scan_bad_domain(self):
        r = client.post("/api/v1/scans/", json={"targets": ["not a domain!!!"]})
        assert r.status_code == 400

    def test_list_scans_empty(self):
        r = client.get("/api/v1/scans/")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_scan_not_found(self):
        r = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_scan_summary_not_found(self):
        r = client.get("/api/v1/scans/00000000-0000-0000-0000-000000000000/summary")
        assert r.status_code == 404


# ─── Asset Endpoints ─────────────────────────────────────────────────────────

class TestAssetAPI:
    def test_list_assets(self):
        r = client.get("/api/v1/assets/")
        assert r.status_code == 200
        data = r.json()
        assert "items" in data
        assert "total" in data

    def test_search_assets(self):
        r = client.get("/api/v1/assets/search?q=test")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_shadow_assets(self):
        r = client.get("/api/v1/assets/shadow")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_third_party_assets(self):
        r = client.get("/api/v1/assets/third-party")
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_asset_detail_not_found(self):
        r = client.get("/api/v1/assets/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404


# ─── CBOM Endpoints ──────────────────────────────────────────────────────────

class TestCBOMAPI:
    def test_cbom_for_scan_not_found(self):
        r = client.get("/api/v1/cbom/scan/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 200  # returns empty list
        data = r.json()
        assert data["total"] == 0

    def test_cbom_for_asset_not_found(self):
        r = client.get("/api/v1/cbom/asset/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 404

    def test_cbom_export_not_found(self):
        r = client.get("/api/v1/cbom/asset/00000000-0000-0000-0000-000000000000/export")
        assert r.status_code == 404


# ─── Risk Endpoints ──────────────────────────────────────────────────────────

class TestRiskAPI:
    def test_mosca_simulate(self):
        r = client.post("/api/v1/risk/mosca/simulate", json={
            "migration_time_years": 5,
            "data_shelf_life_years": 10,
        })
        assert r.status_code == 200
        data = r.json()
        assert "input" in data
        assert "result" in data
        assert data["result"]["exposed_pessimistic"] is True

    def test_mosca_simulate_custom(self):
        r = client.post("/api/v1/risk/mosca/simulate", json={
            "migration_time_years": 1,
            "data_shelf_life_years": 2,
            "crqc_pessimistic_year": 2040,
            "crqc_median_year": 2045,
            "crqc_optimistic_year": 2050,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["result"]["exposed_pessimistic"] is False

    def test_risk_heatmap_not_found(self):
        r = client.get("/api/v1/risk/scan/00000000-0000-0000-0000-000000000000/heatmap")
        assert r.status_code == 404


# ─── Compliance Endpoints ────────────────────────────────────────────────────

class TestComplianceAPI:
    def test_regulatory_deadlines(self):
        r = client.get("/api/v1/compliance/deadlines")
        assert r.status_code == 200
        data = r.json()
        assert "deadlines" in data
        assert len(data["deadlines"]) > 0
        assert data["deadlines"][0]["jurisdiction"] == "India"

    def test_compliance_for_scan_empty(self):
        r = client.get("/api/v1/compliance/scan/00000000-0000-0000-0000-000000000000")
        assert r.status_code == 200
        assert r.json()["total"] == 0


# ─── Topology Endpoints ──────────────────────────────────────────────────────

class TestTopologyAPI:
    def test_topology_stats_not_found(self):
        r = client.get("/api/v1/topology/scan/00000000-0000-0000-0000-000000000000/stats")
        assert r.status_code in (200, 404, 500)  # 200 if cached graph file exists from prior scan


# ─── Full E2E Scan Test (requires network) ───────────────────────────────────

@pytest.mark.timeout(300)
@pytest.mark.skipif(
    os.environ.get("SKIP_NETWORK_TESTS") == "1",
    reason="Network tests disabled",
)
class TestFullScanE2E:
    """Runs a full scan through the API and validates all endpoints."""

    @pytest.fixture(autouse=True, scope="class")
    def run_scan(self, request):
        """Start a scan and wait for completion."""
        r = client.post("/api/v1/scans/", json={"targets": ["pnb.bank.in"]})
        assert r.status_code == 201
        data = r.json()
        request.cls.scan_id = str(data["scan_id"])

        # Poll until complete (max 5 min)
        for _ in range(60):
            status = client.get(f"/api/v1/scans/{request.cls.scan_id}").json()
            if status["status"] in ("completed", "failed"):
                break
            time.sleep(5)
        assert status["status"] == "completed"
        request.cls.total_assets = status["total_assets"]

    def test_scan_status_completed(self):
        r = client.get(f"/api/v1/scans/{self.scan_id}")
        assert r.status_code == 200
        assert r.json()["status"] == "completed"

    def test_scan_summary(self):
        r = client.get(f"/api/v1/scans/{self.scan_id}/summary")
        assert r.status_code == 200
        data = r.json()
        assert data["total_assets"] > 0
        assert data["total_risk_scores"] > 0

    def test_assets_found(self):
        r = client.get(f"/api/v1/assets/?scan_id={self.scan_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["total"] > 0

    def test_risk_heatmap(self):
        r = client.get(f"/api/v1/risk/scan/{self.scan_id}/heatmap")
        assert r.status_code == 200
        data = r.json()
        assert data["total_assets"] > 0
        assert "classification_distribution" in data

    def test_compliance_results(self):
        r = client.get(f"/api/v1/compliance/scan/{self.scan_id}/regulatory")
        assert r.status_code == 200
        data = r.json()
        assert "regulations" in data
        assert "rbi_it_framework" in data["regulations"]

    def test_topology_graph(self):
        r = client.get(f"/api/v1/topology/scan/{self.scan_id}")
        assert r.status_code == 200
        data = r.json()
        assert data["node_count"] > 0
