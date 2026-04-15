"""
Reports API Endpoint — Triggers and downloads AI-generated PDF/HTML reports.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from typing import Literal, List, Optional
from sqlalchemy.orm import Session
from uuid import UUID
import logging
from pydantic import BaseModel, ConfigDict
from datetime import datetime

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.auth import User
from app.models.report import ReportSchedule
from app.models.generated_report import GeneratedReport
from app.services.report_generator import ReportGenerator

router = APIRouter()
logger = logging.getLogger(__name__)

class ReportRequest(BaseModel):
    report_type: Literal["executive", "cbom_audit", "rbi_submission", "migration_progress", "full_scan", "pqc_migration_plan"] = "executive"
    format: Literal["pdf", "csv", "json", "html"] = "pdf"
    password: Optional[str] = None
    download_link: Optional[bool] = False  # If True, save report and return link instead of direct download

class ScheduleCreate(BaseModel):
    report_type: str
    frequency: str
    target_assets: str
    sections: Optional[List[str]] = None
    schedule_date: Optional[str] = None
    schedule_time: Optional[str] = None
    time_zone: Optional[str] = None
    delivery_email: Optional[str] = None
    delivery_location: Optional[str] = None
    download_link: Optional[bool] = False

class ScheduleResponse(ScheduleCreate):
    id: UUID
    user_id: UUID
    schedule_date: Optional[datetime] = None
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

@router.post("/generate/{scan_id}")
def generate_report(
    scan_id: UUID,
    payload: ReportRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate a PDF report for the given scan_id and report type.
    
    If download_link is True, saves the report and returns metadata with download URL.
    Otherwise, returns the file directly for immediate download.
    """
    try:
        generator = ReportGenerator(db, current_user)
        output_bytes = generator.generate_report(str(scan_id), payload.report_type, format=payload.format, password=payload.password)
        
        # If download_link is requested, get the saved report and return metadata
        if payload.download_link:
            from app.models.scan import ScanJob
            scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if not scan_job:
                raise ValueError(f"Scan {scan_id} not found")
            
            # generate_report() already saved the report, query for it
            saved_report = db.query(GeneratedReport).filter(
                GeneratedReport.scan_id == scan_id,
                GeneratedReport.report_type == payload.report_type,
                GeneratedReport.format == payload.format
            ).order_by(GeneratedReport.generated_at.desc()).first()
            
            if not saved_report:
                raise HTTPException(status_code=500, detail="Failed to save report")
            
            # Return the saved report metadata with download URL
            return {
                "id": str(saved_report.id),
                "scan_id": str(saved_report.scan_id),
                "report_type": saved_report.report_type,
                "format": saved_report.format,
                "title": saved_report.title,
                "file_size_kb": saved_report.file_size_kb,
                "generated_at": str(saved_report.generated_at),
                "targets": saved_report.targets,
                "download_url": f"/api/v1/reports/saved/{saved_report.id}/download"
            }
        
        # Otherwise, return the file directly for immediate download
        media_types = {
            "pdf": "application/pdf",
            "csv": "text/csv",
            "json": "application/json"
        }
        
        return Response(
            content=output_bytes,
            media_type=media_types.get(payload.format, "application/pdf"),
            headers={"Content-Disposition": f"attachment; filename=qushield_{payload.report_type}_report_{scan_id}.{payload.format}"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")


@router.post("/schedule", response_model=ScheduleResponse)
def create_schedule(
    payload: ScheduleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new report schedule."""
    schedule = ReportSchedule(
        user_id=current_user.id,
        report_type=payload.report_type,
        frequency=payload.frequency,
        target_assets=payload.target_assets,
        sections=payload.sections,
        schedule_date=datetime.fromisoformat(payload.schedule_date.replace("Z", "").replace("+00:00", "")) if payload.schedule_date else None,
        schedule_time=payload.schedule_time,
        time_zone=payload.time_zone,
        delivery_email=payload.delivery_email,
        delivery_location=payload.delivery_location,
        download_link=payload.download_link
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)
    return schedule

@router.get("/schedules", response_model=List[ScheduleResponse])
def list_schedules(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all scheduled reports for the current user."""
    schedules = db.query(ReportSchedule).filter(ReportSchedule.user_id == current_user.id).order_by(ReportSchedule.created_at.desc()).all()
    return schedules

@router.delete("/schedules/{schedule_id}")
def delete_schedule(
    schedule_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a scheduled report."""
    schedule = db.query(ReportSchedule).filter(
        ReportSchedule.id == schedule_id,
        ReportSchedule.user_id == current_user.id
    ).first()
    if not schedule:
        raise HTTPException(status_code=404, detail="Schedule not found")
    db.delete(schedule)
    db.commit()
    return {"status": "deleted", "id": str(schedule_id)}


# ─── Saved Reports ────────────────────────────────────────────────────────────

class SavedReportResponse(BaseModel):
    id: UUID
    scan_id: UUID
    report_type: str
    format: str
    title: Optional[str] = None
    file_size_kb: Optional[int] = None
    generated_at: datetime
    targets: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)


@router.get("/saved", response_model=List[SavedReportResponse])
def list_saved_reports(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List all previously generated reports for the current user."""
    reports = (
        db.query(GeneratedReport)
        .filter(GeneratedReport.user_id == current_user.id)
        .order_by(GeneratedReport.generated_at.desc())
        .limit(100)
        .all()
    )
    return reports


@router.get("/saved/{report_id}/download")
def download_saved_report(
    report_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Download a previously generated report file."""
    import os
    record = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.user_id == current_user.id,
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")
    if not record.file_path or not os.path.exists(record.file_path):
        raise HTTPException(status_code=410, detail="Report file no longer available on disk")

    with open(record.file_path, "rb") as f:
        content = f.read()

    media_map = {"pdf": "application/pdf", "csv": "text/csv",
                 "json": "application/json", "html": "text/html"}
    fmt = record.format or "pdf"
    filename = f"qushield_{record.report_type}_{str(record.id)[:8]}.{fmt}"
    return Response(
        content=content,
        media_type=media_map.get(fmt, "application/octet-stream"),
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.delete("/saved/{report_id}")
def delete_saved_report(
    report_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a saved report record (and its file if it exists)."""
    import os
    record = db.query(GeneratedReport).filter(
        GeneratedReport.id == report_id,
        GeneratedReport.user_id == current_user.id,
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Report not found")
    if record.file_path and os.path.exists(record.file_path):
        try:
            os.remove(record.file_path)
        except OSError:
            pass
    db.delete(record)
    db.commit()
    return {"status": "deleted", "id": str(report_id)}


@router.get("/chart-data/{scan_id}")
def get_chart_data(
    scan_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return raw chart data JSON for frontend rendering (no base64 images)."""
    try:
        generator = ReportGenerator(db, current_user)
        return generator.get_chart_data(str(scan_id))
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Chart data error: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve chart data")
