"""
TLS Deep Inspection API — run testssl.sh against assets and retrieve results.
"""
import threading
import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.models.asset import Asset
from app.models.tls_inspection import TLSInspection, TLSInspectionStatus
from app.services.testssl_service import (
    start_inspection,
    get_latest_inspection,
    get_inspection_history,
)

logger = logging.getLogger(__name__)
router = APIRouter()


def _run_inspection_background(inspection_id: str, asset_id: str, hostname: str, port: str):
    """Run testssl.sh in a background thread with its own DB session."""
    logger.info(f"[bg-thread] START inspection={inspection_id}, host={hostname}:{port}")
    db = SessionLocal()
    try:
        inspection = db.query(TLSInspection).filter(TLSInspection.id == inspection_id).first()
        if not inspection:
            logger.error(f"[bg-thread] Inspection {inspection_id} not found in DB")
            return

        from app.services.testssl_service import run_testssl, parse_testssl_json
        from datetime import datetime, timezone

        inspection.status = TLSInspectionStatus.RUNNING
        db.commit()
        logger.info(f"[bg-thread] Status set to RUNNING for {hostname}")

        raw_findings, error = run_testssl(hostname, port)

        logger.info(f"[bg-thread] run_testssl returned: {len(raw_findings)} findings, error={error}")

        if error:
            inspection.status = TLSInspectionStatus.FAILED
            inspection.error_message = error
            inspection.completed_at = datetime.now(timezone.utc)
            db.commit()
            logger.warning(f"[bg-thread] FAILED for {hostname}: {error}")
            return

        try:
            summary = parse_testssl_json(raw_findings)
            logger.info(f"[bg-thread] Parsed: grade={summary.get('grade')}, "
                        f"findings={summary.get('total_findings')}, "
                        f"sections={({k: len(v) for k, v in summary.get('sections', {}).items()})}")
        except Exception as e:
            inspection.status = TLSInspectionStatus.FAILED
            inspection.error_message = f"Parse error: {e}"
            inspection.completed_at = datetime.now(timezone.utc)
            db.commit()
            logger.error(f"[bg-thread] Parse error for {hostname}: {e}", exc_info=True)
            return

        inspection.raw_json = raw_findings
        inspection.summary = summary
        inspection.status = TLSInspectionStatus.COMPLETED
        inspection.completed_at = datetime.now(timezone.utc)
        db.commit()
        logger.info(f"[bg-thread] COMPLETED {hostname}: grade={summary.get('grade')}, "
                     f"total_findings={summary.get('total_findings')}, "
                     f"severity={summary.get('severity_counts')}")
    except Exception as e:
        logger.error(f"[bg-thread] Unhandled error for {hostname}: {e}", exc_info=True)
        try:
            inspection = db.query(TLSInspection).filter(TLSInspection.id == inspection_id).first()
            if inspection:
                inspection.status = TLSInspectionStatus.FAILED
                inspection.error_message = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
        logger.info(f"[bg-thread] END inspection={inspection_id}")


@router.post("/{asset_id}/run")
def run_tls_inspection(asset_id: UUID, db: Session = Depends(get_db)):
    """
    Start a TLS Deep Inspection for an asset.
    Runs testssl.sh in a background thread and returns the inspection ID immediately.
    """
    asset = db.query(Asset).filter(Asset.id == asset_id).first()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    # Check if there's already a running inspection
    running = (
        db.query(TLSInspection)
        .filter(
            TLSInspection.asset_id == asset_id,
            TLSInspection.status.in_([TLSInspectionStatus.PENDING, TLSInspectionStatus.RUNNING]),
        )
        .first()
    )
    if running:
        return {
            "inspection_id": str(running.id),
            "status": running.status.value,
            "message": "Inspection already in progress",
        }

    import uuid
    from datetime import datetime, timezone

    inspection = TLSInspection(
        id=uuid.uuid4(),
        asset_id=asset_id,
        hostname=asset.hostname,
        port="443",
        status=TLSInspectionStatus.PENDING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(inspection)
    db.commit()
    db.refresh(inspection)

    # Start background thread
    thread = threading.Thread(
        target=_run_inspection_background,
        args=(str(inspection.id), str(asset_id), asset.hostname, "443"),
        daemon=True,
        name=f"testssl-{asset.hostname}",
    )
    thread.start()

    return {
        "inspection_id": str(inspection.id),
        "status": "pending",
        "hostname": asset.hostname,
        "message": "TLS Deep Inspection started",
    }


@router.get("/{asset_id}/status")
def get_inspection_status(asset_id: UUID, db: Session = Depends(get_db)):
    """Get the current status of the latest TLS inspection for an asset."""
    inspection = get_latest_inspection(db, str(asset_id))
    if not inspection:
        return {"status": "none", "message": "No inspection found for this asset"}

    result = {
        "inspection_id": str(inspection.id),
        "status": inspection.status.value,
        "hostname": inspection.hostname,
        "started_at": inspection.started_at.isoformat() if inspection.started_at else None,
        "completed_at": inspection.completed_at.isoformat() if inspection.completed_at else None,
        "error_message": inspection.error_message,
    }

    if inspection.status == TLSInspectionStatus.COMPLETED and inspection.summary:
        result["grade"] = inspection.summary.get("grade")
        result["total_findings"] = inspection.summary.get("total_findings")
        result["severity_counts"] = inspection.summary.get("severity_counts")

    return result


@router.get("/{asset_id}/results")
def get_inspection_results(asset_id: UUID, db: Session = Depends(get_db)):
    """Get full parsed results for the latest completed inspection."""
    inspection = (
        db.query(TLSInspection)
        .filter(
            TLSInspection.asset_id == asset_id,
            TLSInspection.status == TLSInspectionStatus.COMPLETED,
        )
        .order_by(TLSInspection.created_at.desc())
        .first()
    )

    if not inspection:
        raise HTTPException(status_code=404, detail="No completed inspection found")

    return {
        "inspection_id": str(inspection.id),
        "hostname": inspection.hostname,
        "port": inspection.port,
        "status": inspection.status.value,
        "started_at": inspection.started_at.isoformat() if inspection.started_at else None,
        "completed_at": inspection.completed_at.isoformat() if inspection.completed_at else None,
        "summary": inspection.summary,
        "raw_findings_count": len(inspection.raw_json) if inspection.raw_json else 0,
    }


@router.get("/{asset_id}/results/raw")
def get_inspection_raw(asset_id: UUID, db: Session = Depends(get_db)):
    """Get raw testssl.sh JSON findings for the latest completed inspection."""
    inspection = (
        db.query(TLSInspection)
        .filter(
            TLSInspection.asset_id == asset_id,
            TLSInspection.status == TLSInspectionStatus.COMPLETED,
        )
        .order_by(TLSInspection.created_at.desc())
        .first()
    )

    if not inspection:
        raise HTTPException(status_code=404, detail="No completed inspection found")

    return {
        "inspection_id": str(inspection.id),
        "hostname": inspection.hostname,
        "raw_json": inspection.raw_json,
    }


@router.get("/{asset_id}/history")
def list_inspection_history(asset_id: UUID, db: Session = Depends(get_db)):
    """List all past inspections for an asset."""
    inspections = get_inspection_history(db, str(asset_id), limit=20)

    return [
        {
            "inspection_id": str(i.id),
            "hostname": i.hostname,
            "status": i.status.value,
            "grade": i.summary.get("grade") if i.summary else None,
            "total_findings": i.summary.get("total_findings") if i.summary else None,
            "started_at": i.started_at.isoformat() if i.started_at else None,
            "completed_at": i.completed_at.isoformat() if i.completed_at else None,
            "error_message": i.error_message,
        }
        for i in inspections
    ]
