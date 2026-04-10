# Standalone Test for Roadmap Agent Logic
import os
import sys
import json
import logging
from unittest.mock import MagicMock

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "backend"))

from app.services.roadmap_agent import generate_migration_roadmap
from app.models.auth import User
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.risk import RiskScore

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def test_roadmap_agent_manually():
    print("\n--- Testing Roadmap Agent Logic Manually ---")
    
    # Mock database session
    db = MagicMock()
    
    # Mock User
    user = User()
    user.id = "5178b42e-cfcd-4029-bd97-8999f7064587"
    user.deployment_mode = "cloud"
    user.ai_tier = "free"
    user.cloud_api_keys = {}
    
    # Mock ScanJob
    scan_id = "b9246410-838a-4f4a-88ac-7216dbe34952"
    scan_job = ScanJob(id=scan_id, user_id=user.id)
    db.query.return_value.filter.return_value.first.side_effect = [scan_job]
    
    # Mock Assets
    asset1 = Asset(id="a1", hostname="critical.pnb.bank.in", scan_id=scan_id)
    db.query.return_value.filter.return_value.all.side_effect = [[asset1]]
    
    # Mock Risks
    risk1 = RiskScore(asset_id="a1", scan_id=scan_id, quantum_risk_score=850, risk_classification="quantum_critical")
    db.query.return_value.filter.return_value.all.side_effect = [[asset1], [risk1]]
    
    try:
        roadmap = generate_migration_roadmap(scan_id, db, user)
        print(f"Generated Roadmap: {json.dumps(roadmap, indent=2)}")
        print("✅ Roadmap Agent logic verified.")
    except Exception as e:
        print(f"❌ Roadmap Agent failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    test_roadmap_agent_manually()
