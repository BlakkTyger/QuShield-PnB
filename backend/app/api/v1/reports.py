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
from app.services.report_generator import ReportGenerator

router = APIRouter()
logger = logging.getLogger(__name__)

class ReportRequest(BaseModel):
    report_type: Literal["executive", "cbom_audit", "rbi_submission", "migration_progress", "full_scan"] = "executive"
    format: Literal["pdf", "csv", "json"] = "pdf"
    password: Optional[str] = None

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
    """Generate a PDF report for the given scan_id and report type."""
    try:
        generator = ReportGenerator(db, current_user)
        output_bytes = generator.generate_report(str(scan_id), payload.report_type, format=payload.format, password=payload.password)
        
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
