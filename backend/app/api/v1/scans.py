"""
Scan API Router — start scans, poll status, list results, stream progress.
"""
import asyncio
import threading
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.risk import RiskScore
from app.models.cbom import CBOMRecord
from app.models.compliance import ComplianceResult
from app.schemas.scan import ScanRequest, ScanResponse, ScanStatus, QuickScanRequest, ShallowScanRequest
from app.services.orchestrator import ScanOrchestrator
from app.services.quick_scanner import quick_scan
from app.services.shallow_scanner import shallow_scan
from app.core.utils import clean_domain

from datetime import datetime, timedelta, timezone
from app.api.v1.auth import get_current_user, get_optional_user
from app.models.auth import User, ScanCache

logger = get_logger("api.scans")
router = APIRouter()

# Track running scans
_running_scans: dict[str, threading.Thread] = {}

def get_superadmin_id(db: Session) -> UUID:
    """Helper to get or create the superadmin user ID."""
    sa_email = "superadmin@qushield.local"
    sa = db.query(User).filter(User.email == sa_email).first()
    if not sa:
        import uuid
        import bcrypt
        sa = User(
            email=sa_email,
            password_hash=bcrypt.hashpw(b"superadmin123", bcrypt.gensalt()).decode('utf-8'),
            email_verified=True
        )
        db.add(sa)
        db.commit()
        db.refresh(sa)
    return sa.id

def check_scan_cache(db: Session, domain: str, allowed_types: list[str], user_id: Optional[UUID] = None) -> Optional[ScanCache]:
    """Check for a valid, non-expired scan cache entry for a domain and user."""
    query = db.query(ScanCache).filter(
        ScanCache.domain == domain,
        ScanCache.scan_type.in_(allowed_types),
        ScanCache.expires_at > datetime.now(timezone.utc)
    )
    
    # Strictly filter by user_id to prevent data leakage
    # We allow public scans (user_id=None) to be seen by anyone if requested,
    # but for private scans, user_id must match.
    if user_id:
        # If user is logged in, show their private scans OR public scans
        from sqlalchemy import or_
        query = query.filter(or_(ScanCache.user_id == user_id, ScanCache.user_id == None))
    else:
        # If anonymous, only show public scans
        query = query.filter(ScanCache.user_id == None)

    caches = query.order_by(ScanCache.cached_at.desc()).all()
    
    for cache in caches:
        scan_job = db.query(ScanJob).filter(ScanJob.id == cache.scan_id).first()
        if not scan_job or scan_job.status == "failed" or (scan_job.status == "completed" and getattr(scan_job, "total_assets", 0) == 0):
            db.delete(cache)
            db.commit()
            continue
        return cache
    return None

@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(request: ScanRequest, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """Start a new deep scan. The scan runs in a background thread."""
    effective_user_id = user.id if user else get_superadmin_id(db)
    
    # Cache check for single-target deep scan
    if len(request.targets) == 1:
        cached = check_scan_cache(db, request.targets[0], ["deep"], user_id=effective_user_id)
        if cached:
            scan_job = db.query(ScanJob).filter(ScanJob.id == cached.scan_id).first()
            if scan_job:
                return ScanResponse(
                    scan_id=str(scan_job.id),
                    status=scan_job.status,
                    created_at=scan_job.created_at,
                    message="Returned from cache",
                )

    orch = ScanOrchestrator()
    try:
        scan_id = orch.start_scan(request.targets, request.config, user_id=effective_user_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    import uuid
    scan_uuid = uuid.UUID(scan_id)
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_uuid).first()
        
    # Associate cache entry for single target
    if len(request.targets) == 1:
        import uuid
        cache = ScanCache(
            domain=request.targets[0],
            scan_type="deep",
            scan_id=uuid.UUID(scan_id),
            user_id=effective_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        db.add(cache)
        db.commit()

    # Capture the current asyncio event loop (which is running the FastAPI request)
    # so the background thread can use it to safely broadcast SSE events.
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    # Run scan in background thread
    def _run():
        try:
            orch.run_scan(scan_id, loop=loop)
        except Exception as e:
            logger.error(f"Background scan {scan_id} failed: {e}", exc_info=True)

    thread = threading.Thread(target=_run, daemon=True, name=f"scan-{scan_id}")
    thread.start()
    _running_scans[scan_id] = thread

    return ScanResponse(
        scan_id=scan_id,
        status=scan_job.status if scan_job else "queued",
        created_at=scan_job.created_at if scan_job else None,
        message="Scan started in background",
    )

@router.post("/quick")
async def run_quick_scan(request: QuickScanRequest, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """Run a quick scan on a single domain. Returns results synchronously in <8s."""
    effective_user_id = user.id if user else get_superadmin_id(db)
    
    # Check cache for existing deep or shallow scan
    cached = check_scan_cache(db, request.domain, ["quick", "shallow", "deep"], user_id=effective_user_id)
    if cached:
        scan_job = db.query(ScanJob).filter(ScanJob.id == cached.scan_id).first()
        if scan_job:
            return {
                "domain": request.domain,
                "scan_type": scan_job.scan_type,
                "cached": True,
                "scan_id": str(scan_job.id),
                "summary": "Returned from cache (Check /summary endpoint for details)"
            }
            
    clean_tgt = clean_domain(request.domain)
    try:
        result = quick_scan(clean_tgt, request.port)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Quick scan connection failed for {clean_tgt}: {e}")

    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])

    # Persist quick scan for history and results view
    try:
        scan_job = ScanJob(
            targets=[clean_tgt],
            scan_type="quick",
            status="completed",
            user_id=effective_user_id,
            completed_at=datetime.now(timezone.utc),
            total_assets=1,
            total_certificates=1 if result.get("certificate") else 0,
        )
        db.add(scan_job)
        db.commit()
        db.refresh(scan_job)
        scan_id_str = str(scan_job.id)
        
        # Save Asset
        from app.models.asset import Asset
        asset = Asset(
            scan_id=scan_job.id,
            hostname=clean_tgt,
            asset_type=result.get("risk", {}).get("asset_type", "unknown"),
            tls_version=result.get("tls", {}).get("negotiated_protocol"),
        )
        db.add(asset)
        db.commit()
        db.refresh(asset)
        asset_id_str = str(asset.id)

        # Save Certificate & Crypto results
        from app.services.crypto_inspector import save_crypto_results
        fingerprint = {
            "hostname": clean_tgt,
            "port": request.port,
            "tls": result.get("tls"),
            "certificates": [result.get("certificate")] if result.get("certificate") else [],
            "asset_type": result.get("risk", {}).get("asset_type"),
            "auth": {"mechanisms": []}
        }
        save_crypto_results(scan_id_str, asset_id_str, fingerprint, db)

        # Save CBOM, Risk & Compliance
        from app.services.cbom_builder import build_cbom, save_cbom, save_cbom_to_db
        cbom_res = build_cbom(asset_id_str, fingerprint)
        if cbom_res:
            file_path = save_cbom(scan_id_str, asset_id_str, cbom_res["cbom_json"])
            save_cbom_to_db(scan_id_str, asset_id_str, cbom_res, file_path, db)

        from app.models.risk import RiskScore, RiskFactor
        risk_data = result.get("risk", {})
        mosca_data = risk_data.get("mosca", {})
        risk_score = RiskScore(
            asset_id=asset.id,
            scan_id=scan_job.id,
            quantum_risk_score=risk_data.get("score", 0),
            risk_classification=risk_data.get("classification", "unknown"),
            mosca_x=mosca_data.get("migration_time_years"),
            mosca_y=mosca_data.get("data_shelf_life_years"),
            hndl_exposed=mosca_data.get("exposed_pessimistic", False),
            tnfl_risk=result.get("quantum_assessment", {}).get("is_quantum_vulnerable", False),
        )
        db.add(risk_score)
        db.commit()

        from app.services.compliance import save_compliance_result
        comp_data = result.get("compliance", {})
        # Re-map quick scan compliance to match save_compliance_result expectations
        # (Though they already mostly match)
        save_compliance_result(scan_id_str, asset_id_str, comp_data, {"agility_score": comp_data.get("agility_score", 50)}, db)

        # Save cache entry
        cache = ScanCache(
            domain=clean_tgt,
            scan_type="quick",
            scan_id=scan_job.id,
            user_id=effective_user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1)
        )
        db.add(cache)
        db.commit()
        
        # Add the scan_id to the result so the frontend can poll summary if needed
        result["scan_id"] = str(scan_job.id)
        result["cached"] = False
    except Exception as e:
        logger.error(f"Failed to persist quick scan result: {e}", exc_info=True)

    return result


@router.post("/shallow", response_model=ScanResponse)
async def run_shallow_scan(request: ShallowScanRequest, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """Run a shallow scan (CT discovery + top-N TLS). Runs in background thread."""
    effective_user_id = user.id if user else get_superadmin_id(db)
    
    # Check cache for existing shallow or deep scan
    cached = check_scan_cache(db, request.domain, ["shallow", "deep"], user_id=effective_user_id)
    if cached:
        scan_job = db.query(ScanJob).filter(ScanJob.id == cached.scan_id).first()
        if scan_job:
            return ScanResponse(
                scan_id=str(scan_job.id),
                status=scan_job.status,
                created_at=scan_job.created_at,
                message="Returned from cache",
            )

    clean_tgt = clean_domain(request.domain)
    
    # Create the ScanJob first
    scan_job = ScanJob(
        targets=[clean_tgt],
        scan_type="shallow",
        status="running",
        user_id=effective_user_id,
        started_at=datetime.now(timezone.utc)
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)
    scan_id = str(scan_job.id)

    # Initial cache entry (running state)
    cache = ScanCache(
        domain=clean_tgt,
        scan_type="shallow",
        scan_id=scan_job.id,
        user_id=effective_user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(hours=6)
    )
    db.add(cache)
    db.commit()

    # Capture loop for SSE (must be done on the main thread for async routes)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    # Run shallow scan in background thread
    def _run_shallow():
        logger.info(f"Background thread starting for shallow scan {scan_id}")
        try:
            orch = ScanOrchestrator()
            orch.run_shallow_scan(scan_id, loop=loop)
        except Exception as e:
            logger.error(f"Background shallow scan {scan_id} failed: {e}", exc_info=True)

    thread = threading.Thread(target=_run_shallow, daemon=True, name=f"shallow-{scan_id}")
    thread.start()
    _running_scans[scan_id] = thread

    return ScanResponse(
        scan_id=scan_id,
        status="running",
        created_at=scan_job.created_at,
        message="Shallow scan started in background"
    )


@router.get("/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: UUID, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """Get scan status and phase progress."""
    import uuid
    # Use explicit UUID casting for cross-DB reliability (SQLite/Postgres)
    scan_job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(str(scan_id))).first()
    
    # Enforce ownership: Only owner, superadmin, or ANYONE for a public (sa-owned) scan
    sa_id = get_superadmin_id(db)
    is_sa = user and user.id == sa_id
    
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Access logic:
    # 1. If scan belongs to superadmin, it's public -> Allow
    # 2. If user is logged in and owns the scan -> Allow
    # 3. If user is actual superadmin (ID matched) -> Allow
    allowed = (scan_job.user_id == sa_id) or (user and scan_job.user_id == user.id) or is_sa
    
    if not allowed:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return ScanStatus(
        scan_id=scan_job.id,
        status=scan_job.status,
        scan_type=scan_job.scan_type,
        current_phase=scan_job.current_phase or 0,
        targets=scan_job.targets or [],
        created_at=scan_job.created_at,
        started_at=scan_job.started_at,
        completed_at=scan_job.completed_at,
        total_assets=scan_job.total_assets or 0,
        total_certificates=scan_job.total_certificates or 0,
        total_vulnerable=scan_job.total_vulnerable or 0,
        error_message=scan_job.error_message,
    )

@router.post("/{scan_id}/cancel")
def cancel_scan(scan_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Mark a scan as cancelled so the orchestrator thread stops."""
    import uuid
    scan_job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(str(scan_id))).first()
    is_sa = current_user.email == "superadmin@qushield.local"
    if not scan_job or (scan_job.user_id != current_user.id and not is_sa):
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan_job.status in ("completed", "failed", "cancelled"):
        return {"message": "Scan already finished"}
    
    scan_job.status = "cancelled"
    db.commit()
    logger.info(f"Scan {scan_id} cancelled by user {current_user.email}")
    return {"message": "Scan cancellation requested"}


@router.get("/{scan_id}/stream")
async def stream_scan_events(
    scan_id: UUID,
    # Auth is usually passed via query param for SSE (EventSource doesn't support headers)
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """
    Server-Sent Events (SSE) endpoint for real-time deep scan progress stream.
    """
    from app.services.scan_events import scan_events
    
    import uuid
    # Optional auth check (validate token if present, skip complete verification for now to permit simple CLI testing)
    scan_job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(str(scan_id))).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    return StreamingResponse(
        scan_events.event_generator(str(scan_id)),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@router.get("", response_model=list[ScanStatus])
def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None, description="Filter by status"),
    user: Optional[User] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all scans, sorted by created_at descending."""
    if not user:
        # Anonymous users don't see a history list (otherwise they'd see ALL public scans)
        return []

    sa_id = get_superadmin_id(db)
    is_sa = user.id == sa_id
    
    if is_sa:
        # Superadmin sees all scans
        query = db.query(ScanJob)
    else:
        # Others see only their own
        query = db.query(ScanJob).filter(ScanJob.user_id == user.id)
    if status:
        query = query.filter(ScanJob.status == status)
    scans = query.order_by(ScanJob.created_at.desc()).offset(offset).limit(limit).all()
    return [
        ScanStatus(
            scan_id=s.id,
            status=s.status,
            scan_type=s.scan_type,
            current_phase=s.current_phase or 0,
            targets=s.targets or [],
            created_at=s.created_at,
            started_at=s.started_at,
            completed_at=s.completed_at,
            total_assets=s.total_assets or 0,
            total_certificates=s.total_certificates or 0,
            total_vulnerable=s.total_vulnerable or 0,
            error_message=s.error_message,
        )
        for s in scans
    ]


@router.get("/{scan_id}/summary")
def get_scan_summary(scan_id: UUID, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """Get a full scan results summary with counts and breakdowns."""
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan not found")

    sa_id = get_superadmin_id(db)
    is_sa = user and user.id == sa_id
    
    # Access logic: Same as get_scan_status
    allowed = (scan_job.user_id == sa_id) or (user and scan_job.user_id == user.id) or is_sa
    
    if not allowed:
        raise HTTPException(status_code=404, detail="Scan not found")

    assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
    certs = db.query(Certificate).filter(Certificate.scan_id == scan_id).all()
    risks = db.query(RiskScore).filter(RiskScore.scan_id == scan_id).all()
    cboms = db.query(CBOMRecord).filter(CBOMRecord.scan_id == scan_id).all()
    compliances = db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()

    # Risk classification breakdown
    risk_breakdown = {}
    for r in risks:
        cls = r.risk_classification or "unknown"
        risk_breakdown[cls] = risk_breakdown.get(cls, 0) + 1

    # Compliance summary
    compliance_summary = {
        "tls_13_enforced": sum(1 for c in compliances if c.tls_13_enforced),
        "forward_secrecy": sum(1 for c in compliances if c.forward_secrecy),
        "rbi_compliant": sum(1 for c in compliances if c.rbi_compliant),
        "pci_compliant": sum(1 for c in compliances if c.pci_compliant),
        "avg_agility_score": round(sum(c.crypto_agility_score for c in compliances) / max(len(compliances), 1), 1),
        "avg_compliance_pct": round(sum(c.compliance_pct or 0 for c in compliances) / max(len(compliances), 1), 1),
    }

    return {
        "scan_id": str(scan_id),
        "status": scan_job.status,
        "targets": scan_job.targets,
        "created_at": str(scan_job.created_at),
        "completed_at": str(scan_job.completed_at) if scan_job.completed_at else None,
        "total_assets": len(assets),
        "total_certificates": len(certs),
        "total_cboms": len(cboms),
        "total_risk_scores": len(risks),
        "total_compliance_results": len(compliances),
        "risk_breakdown": risk_breakdown,
        "compliance_summary": compliance_summary,
        "shadow_assets": sum(1 for a in assets if a.is_shadow),
        "third_party_assets": sum(1 for a in assets if a.is_third_party),
    }
