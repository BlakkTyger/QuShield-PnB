"""
Script to clear all scan-related data from the QuShield database.
Preserves User accounts and settings.
"""
from sqlalchemy import text
from app.core.database import SessionLocal
from app.models.scan import ScanJob
from app.models.asset import Asset, AssetPort
from app.models.certificate import Certificate
from app.models.risk import RiskScore, RiskFactor
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.compliance import ComplianceResult
from app.models.geo import GeoLocation
from app.models.auth import ScanCache

def clear_database():
    db = SessionLocal()
    try:
        print("Clearing scan-related data...")
        
        # Order matters due to foreign key constraints if not using CASCADE
        # In this project, we'll delete in reverse order of dependency
        
        print("- Deleting GeoLocation data")
        db.query(GeoLocation).delete()
        
        print("- Deleting Compliance results")
        db.query(ComplianceResult).delete()
        
        print("- Deleting CBOM detail records")
        db.query(CBOMComponent).delete()
        db.query(CBOMRecord).delete()
        
        print("- Deleting Risk factors")
        db.query(RiskFactor).delete()
        
        print("- Deleting Risk scores")
        db.query(RiskScore).delete()
        
        print("- Deleting Asset ports")
        db.query(AssetPort).delete()
        
        print("- Deleting Certificates")
        db.query(Certificate).delete()
        
        print("- Deleting Assets")
        db.query(Asset).delete()
        
        print("- Deleting Scan Cache")
        db.query(ScanCache).delete()
        
        print("- Deleting Scan Jobs (History)")
        db.query(ScanJob).delete()
        
        db.commit()
        print("\nDatabase cleared successfully (Users preserved).")
        
    except Exception as e:
        db.rollback()
        print(f"\nError clearing database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    confirm = input("Are you sure you want to delete ALL scan data? (y/n): ")
    if confirm.lower() == 'y':
        clear_database()
    else:
        print("Operation cancelled.")
