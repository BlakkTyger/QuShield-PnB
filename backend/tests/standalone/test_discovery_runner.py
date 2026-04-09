"""
Standalone test for the Discovery Runner and Asset Manager.
Tests the Go binary execution and database persistence.
"""
import json
import os
import pytest
from pathlib import Path


def test_discovery_runner_example_com():
    """Test discovery against example.com via the Go binary."""
    from app.services.discovery_runner import run_discovery

    result = run_discovery("example.com", scan_id="test_runner_001")

    assert "assets" in result, "Missing 'assets' key in result"
    assert len(result["assets"]) >= 1, f"Expected at least 1 asset, got {len(result['assets'])}"

    # Verify each asset has required fields
    for asset in result["assets"]:
        assert "hostname" in asset, "Missing 'hostname' in asset"
        assert asset["hostname"], "Empty hostname"
        assert "discovery_methods" in asset, "Missing 'discovery_methods'"

    # Verify stats
    assert "stats" in result
    assert result["stats"]["subdomains_found"] >= 1

    print(f"\n✅ Discovery found {len(result['assets'])} assets for example.com")
    for a in result["assets"]:
        print(f"   {a['hostname']} ({a.get('ip_v4', '?')}) — ports: {[p['port'] for p in a.get('ports', [])]}")


def test_asset_manager_save():
    """Test saving discovery results to the database."""
    from app.core.database import SessionLocal, init_db
    from app.services.asset_manager import save_discovered_assets, create_scan_job
    from app.models.asset import Asset, AssetPort

    # Ensure tables exist
    init_db()

    db = SessionLocal()
    try:
        # Create a scan job
        scan = create_scan_job(targets=["example.com"], db=db)
        scan_id = str(scan.id)

        # Mock discovery data (mimicking Go binary output)
        mock_assets = [
            {
                "hostname": "www.test-example.com",
                "ip_v4": "93.184.216.34",
                "ports": [
                    {"port": 80, "protocol": "tcp"},
                    {"port": 443, "protocol": "tcp", "service": "https"},
                ],
                "http": {
                    "status_code": 200,
                    "title": "Test Example",
                    "web_server": "nginx",
                    "tls_version": "TLSv1.3",
                },
                "discovery_methods": ["dns", "portscan", "httpx"],
                "confidence_score": 1.0,
            },
            {
                "hostname": "api.test-example.com",
                "ip_v4": "93.184.216.35",
                "ports": [{"port": 443, "protocol": "tcp"}],
                "http": {"status_code": 200, "web_server": "Apache"},
                "discovery_methods": ["dns", "httpx"],
                "confidence_score": 0.67,
            },
            {
                "hostname": "mail.test-example.com",
                "ip_v4": "93.184.216.36",
                "ports": [{"port": 25, "protocol": "tcp"}, {"port": 465, "protocol": "tcp"}],
                "discovery_methods": ["dns", "portscan"],
                "confidence_score": 0.67,
            },
        ]

        # Save to database
        saved = save_discovered_assets(scan_id, mock_assets, db)
        assert len(saved) == 3, f"Expected 3 saved assets, got {len(saved)}"

        # Verify database records
        db_assets = db.query(Asset).filter(Asset.scan_id == scan.id).all()
        assert len(db_assets) == 3, f"Expected 3 DB assets, got {len(db_assets)}"

        # Verify ports
        total_ports = db.query(AssetPort).join(Asset).filter(Asset.scan_id == scan.id).count()
        assert total_ports == 5, f"Expected 5 ports, got {total_ports}"

        # Verify specific asset
        www = db.query(Asset).filter(Asset.hostname == "www.test-example.com").first()
        assert www is not None
        assert www.web_server == "nginx"
        assert www.tls_version == "TLSv1.3"
        assert www.confidence_score == 1.0

        print(f"\n✅ Saved {len(saved)} assets with {total_ports} ports to database")
        for a in db_assets:
            port_count = len(a.ports)
            print(f"   {a.hostname} ({a.ip_v4}) — {port_count} ports, server={a.web_server}")

        # Test duplicate handling
        saved_again = save_discovered_assets(scan_id, mock_assets[:1], db)
        assert len(saved_again) == 1
        updated_asset = db.query(Asset).filter(Asset.hostname == "www.test-example.com").first()
        assert updated_asset is not None
        print("✅ Duplicate handling works (updated existing record)")

    finally:
        # Clean up test data
        db.rollback()
        db.close()


if __name__ == "__main__":
    test_discovery_runner_example_com()
    test_asset_manager_save()
    print("\n✅ All P1 standalone tests passed!")
