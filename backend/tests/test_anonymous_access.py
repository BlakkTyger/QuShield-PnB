import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import SessionLocal
from app.models.auth import User
from app.models.scan import ScanJob
from app.services import auth_service
import uuid
from datetime import datetime, timezone

client = TestClient(app)

@pytest.fixture
def db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def test_anonymous_scan_visibility(db):
    # 1. Setup: Get superadmin ID
    sa_email = "superadmin@qushield.local"
    sa = db.query(User).filter(User.email == sa_email).first()
    if not sa:
        sa = auth_service.create_user(db, email=sa_email, password="superadmin123")
    sa_id = sa.id

    # 2. Trigger a quick scan anonymously (Mocking the persistence part)
    # In a real test we'd hit /api/v1/scans/quick but that triggers a real scan.
    # We'll just create a ScanJob assigned to superadmin.
    scan_id = uuid.uuid4()
    scan_job = ScanJob(
        id=scan_id,
        targets=["anon-test.com"],
        scan_type="quick",
        status="completed",
        user_id=sa_id,
        created_at=datetime.now(timezone.utc)
    )
    db.add(scan_job)
    db.commit()

    # 3. Test: Anonymous user (no token) should be able to see the status
    resp_status = client.get(f"/api/v1/scans/{scan_id}")
    assert resp_status.status_code == 200, "Anonymous should be able to see public (sa-owned) scan status"
    assert resp_status.json()["scan_id"] == str(scan_id)

    # 4. Test: Anonymous user should be able to see the summary
    resp_summary = client.get(f"/api/v1/scans/{scan_id}/summary")
    assert resp_summary.status_code == 200, "Anonymous should be able to see public scan summary"

    # 5. Cleanup
    db.delete(scan_job)
    db.commit()
    print("\n[SUCCESS] Anonymous access tests passed.")
