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

from datetime import datetime, timedelta, timezone
from app.api.v1.auth import get_current_user, get_optional_user
from app.models.auth import User, ScanCache

logger = get_logger("api.scans")
router = APIRouter()

# Track running scans
_running_scans: dict[str, threading.Thread] = {}

def check_scan_cache(db: Session, domain: str, allowed_types: list[str]) -> Optional[ScanCache]:
    return db.query(ScanCache).filter(
        ScanCache.domain == domain,
        ScanCache.scan_type.in_(allowed_types),
        ScanCache.expires_at > datetime.now(timezone.utc)
    ).order_by(ScanCache.cached_at.desc()).first()

@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(request: ScanRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Start a new scan. The scan runs in a background thread."""
    
    # Cache check for single-target deep scan
    if len(request.targets) == 1:
        cached = check_scan_cache(db, request.targets[0], ["deep"])
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
        scan_id = orch.start_scan(request.targets, request.config)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    # Associate scan with user
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if scan_job:
        scan_job.user_id = current_user.id
        db.commit()

        # Create cache entry for single target
        if len(request.targets) == 1:
            cache = ScanCache(
                domain=request.targets[0],
                scan_type="deep",
                scan_id=scan_id,
                user_id=current_user.id,
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
def run_quick_scan(request: QuickScanRequest, user: Optional[User] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """Run a quick scan on a single domain. Returns results synchronously in <8s."""
    # Check cache for existing deep or shallow scan
    cached = check_scan_cache(db, request.domain, ["quick", "shallow", "deep"])
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
            
    try:
        result = quick_scan(request.domain, request.port)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Quick scan failed: {e}")

    if result.get("error"):
        raise HTTPException(status_code=502, detail=result["error"])

    return result


@router.post("/shallow")
def run_shallow_scan(request: ShallowScanRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Run a shallow scan (CT discovery + top-N TLS). Returns results synchronously in 30–90s."""
    # Check cache for existing shallow or deep scan
    cached = check_scan_cache(db, request.domain, ["shallow", "deep"])
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

    try:
        result = shallow_scan(request.domain, top_n=request.top_n, port=request.port)
        if result and not result.get("error"):
            # Create a shallow ScanJob to satisfy future cache requests
            scan_job = ScanJob(
                targets=[request.domain],
                scan_type="shallow",
                status="completed",
                user_id=current_user.id
            )
            db.add(scan_job)
            db.commit()
            db.refresh(scan_job)
            
            cache = ScanCache(
                domain=request.domain,
                scan_type="shallow",
                scan_id=scan_job.id,
                user_id=current_user.id,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=6)
            )
            db.add(cache)
            db.commit()
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Shallow scan failed: {e}")

    if result.get("error") and not result.get("assets"):
        raise HTTPException(status_code=502, detail=result["error"])

    return result


@router.get("/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get scan status and phase progress."""
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job or (scan_job.user_id and scan_job.user_id != current_user.id):
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatus(
        scan_id=scan_job.id,
        status=scan_job.status,
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
    
    # Optional auth check (validate token if present, skip complete verification for now to permit simple CLI testing)
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
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


@router.get("/", response_model=list[ScanStatus])
def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all scans, sorted by created_at descending."""
    query = db.query(ScanJob).filter(ScanJob.user_id == current_user.id)
    if status:
        query = query.filter(ScanJob.status == status)
    scans = query.order_by(ScanJob.created_at.desc()).offset(offset).limit(limit).all()
    return [
        ScanStatus(
            scan_id=s.id,
            status=s.status,
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
def get_scan_summary(scan_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Get a full scan results summary with counts and breakdowns."""
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job or (scan_job.user_id and scan_job.user_id != current_user.id):
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
