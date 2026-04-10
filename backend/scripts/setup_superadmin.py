"""Superadmin setup script. Creates superadmin and attaches existing scans."""
from app.core.database import SessionLocal
from app.models.auth import User
from app.models.scan import ScanJob
import bcrypt

def run():
    db = SessionLocal()
    try:
        # Check if superadmin exists
        sa = db.query(User).filter(User.email == "superadmin@qushield.local").first()
        if not sa:
            sa = User(
                email="superadmin@qushield.local",
                password_hash=bcrypt.hashpw(b"superadmin123", bcrypt.gensalt()).decode('utf-8'),
                email_verified=True
            )
            db.add(sa)
            db.commit()
            db.refresh(sa)
            print(f"Created superadmin User ID: {sa.id}")
        else:
            print(f"Superadmin already exists: {sa.id}")
            
        # Migrate existing scans
        unclaimed_scans = db.query(ScanJob).filter(ScanJob.user_id == None).all()
        for scan in unclaimed_scans:
            scan.user_id = sa.id
        db.commit()
        print(f"Migrated {len(unclaimed_scans)} unclaimed scans to superadmin.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    run()
