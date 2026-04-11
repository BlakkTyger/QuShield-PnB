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

def test_cross_user_data_leakage(db):
    # 1. Setup: Create User A, User B, and Superadmin
    email_a = f"user_a_{uuid.uuid4().hex[:4]}@test.com"
    email_b = f"user_b_{uuid.uuid4().hex[:4]}@test.com"
    sa_email = "superadmin@qushield.local"
    
    user_a = auth_service.create_user(db, email=email_a, password="password123")
    user_b = auth_service.create_user(db, email=email_b, password="password123")
    sa = db.query(User).filter(User.email == sa_email).first()
    if not sa:
        sa = auth_service.create_user(db, email=sa_email, password="superadmin123")

    token_a = auth_service.create_access_token({"sub": str(user_a.id), "email": user_a.email})
    token_b = auth_service.create_access_token({"sub": str(user_b.id), "email": user_b.email})
    token_sa = auth_service.create_access_token({"sub": str(sa.id), "email": sa.email})

    # 2. User A creates a scan
    scan_job = ScanJob(
        targets=["google.com"],
        scan_type="deep",
        status="completed",
        user_id=user_a.id,
        created_at=datetime.now(timezone.utc)
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)
    scan_id = str(scan_job.id)

    # 3. Test: User B tries to access User A's scan status
    resp_b = client.get(f"/api/v1/scans/{scan_id}", headers={"Authorization": f"Bearer {token_b}"})
    assert resp_b.status_code == 404, "User B should not be able to access User A's scan"

    # 4. Test: Anonymous tries to access User A's scan status
    resp_anon = client.get(f"/api/v1/scans/{scan_id}")
    assert resp_anon.status_code == 404, "Anonymous should be rejected from private scan with 404"

    # 5. Test: Superadmin tries to access User A's scan status
    resp_sa = client.get(f"/api/v1/scans/{scan_id}", headers={"Authorization": f"Bearer {token_sa}"})
    assert resp_sa.status_code == 200, "Superadmin should be able to access any scan"

    # 6. Test: List scans
    resp_list_a = client.get("/api/v1/scans", headers={"Authorization": f"Bearer {token_a}"})
    assert any(s["scan_id"] == scan_id for s in resp_list_a.json()), "User A should see their own scan"

    resp_list_b = client.get("/api/v1/scans", headers={"Authorization": f"Bearer {token_b}"})
    assert not any(s["scan_id"] == scan_id for s in resp_list_b.json()), "User B should not see User A's scan in list"

    resp_list_sa = client.get("/api/v1/scans", headers={"Authorization": f"Bearer {token_sa}"})
    assert any(s["scan_id"] == scan_id for s in resp_list_sa.json()), "Superadmin should see all scans in list"

    # Cleanup
    db.delete(scan_job)
    db.delete(user_a)
    db.delete(user_b)
    db.commit()
    print("\n[SUCCESS] User isolation tests passed.")
