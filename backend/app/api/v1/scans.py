"""
Scan API Router — start scans, poll status, list results.
"""
import threading
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.logging import get_logger
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.risk import RiskScore
from app.models.cbom import CBOMRecord
from app.models.compliance import ComplianceResult
from app.schemas.scan import ScanRequest, ScanResponse, ScanStatus
from app.services.orchestrator import ScanOrchestrator

logger = get_logger("api.scans")
router = APIRouter()

# Track running scans
_running_scans: dict[str, threading.Thread] = {}


@router.post("/", response_model=ScanResponse, status_code=201)
def create_scan(request: ScanRequest, db: Session = Depends(get_db)):
    """Start a new scan. The scan runs in a background thread."""
    orch = ScanOrchestrator()
    try:
        scan_id = orch.start_scan(request.targets, request.config)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Run scan in background thread
    def _run():
        try:
            orch.run_scan(scan_id)
        except Exception as e:
            logger.error(f"Background scan {scan_id} failed: {e}", exc_info=True)

    thread = threading.Thread(target=_run, daemon=True, name=f"scan-{scan_id}")
    thread.start()
    _running_scans[scan_id] = thread

    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    return ScanResponse(
        scan_id=scan_id,
        status=scan_job.status if scan_job else "queued",
        created_at=scan_job.created_at if scan_job else None,
        message="Scan started in background",
    )


@router.get("/{scan_id}", response_model=ScanStatus)
def get_scan_status(scan_id: UUID, db: Session = Depends(get_db)):
    """Get scan status and phase progress."""
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job:
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


@router.get("/", response_model=list[ScanStatus])
def list_scans(
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None, description="Filter by status"),
    db: Session = Depends(get_db),
):
    """List all scans, sorted by created_at descending."""
    query = db.query(ScanJob)
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
def get_scan_summary(scan_id: UUID, db: Session = Depends(get_db)):
    """Get a full scan results summary with counts and breakdowns."""
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
    if not scan_job:
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
