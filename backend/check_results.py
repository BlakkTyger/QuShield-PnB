from app.core.database import SessionLocal
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.certificate import Certificate

db = SessionLocal()

# Get the latest deep scan for pnb.bank.in
scan = db.query(ScanJob).order_by(ScanJob.created_at.desc()).first()

if not scan:
    print("No scan found.")
else:
    print(f"Scan ID: {scan.id} | Status: {scan.status}")
    assets = db.query(Asset).filter(Asset.scan_id == scan.id).all()
    print(f"Assets Found: {len(assets)}")
    for a in assets:
        print(f"Asset: {a.hostname} | TLS: {a.tls_version} | CDN: {a.cdn_detected} | JWT: {a.jwt_algorithm}")

    print("\n--- Certificates ---")
    certs = db.query(Certificate).filter(Certificate.scan_id == scan.id).limit(10).all()
    for c in certs:
        print(f"Cert: {c.issuer_cn} | Algo: {c.signature_algorithm} | Safe? {c.is_pqc_safe}")

db.close()
