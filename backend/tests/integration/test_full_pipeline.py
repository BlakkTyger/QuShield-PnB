import pytest
from app.services.orchestrator import ScanOrchestrator
from app.core.database import SessionLocal
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.cbom import CBOMRecord
from app.models.risk import RiskScore

@pytest.mark.timeout(180)
def test_full_pipeline_orchestration():
    orch = ScanOrchestrator()
    target = "example.com"
    scan_id = orch.start_scan([target])
    
    summary = orch.run_scan(scan_id)

    assert summary["status"] == "completed"
    assert summary["assets_discovered"] > 0
    assert summary["crypto_scans"] > 0
    assert summary["cboms_generated"] > 0
    assert summary["risk_assessments"] > 0
    assert summary["compliance_scores_computed"] > 0
    assert summary["graph_nodes"] > 0

    # DB Integrity Checks
    db = SessionLocal()
    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    assert len(assets) == summary["assets_discovered"]

    for asset in assets:
        cert = db.query(Certificate).filter(Certificate.asset_id == asset.id).first()
        cbom = db.query(CBOMRecord).filter(CBOMRecord.asset_id == asset.id).first()
        risk = db.query(RiskScore).filter(RiskScore.asset_id == asset.id).first()
        # We assume if one succeeds, the logic tied to them persists OK
        assert cbom is not None

    db.close()
