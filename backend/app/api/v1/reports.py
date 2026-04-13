"""
Reports API Endpoint — Triggers and downloads AI-generated PDF/HTML reports.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from typing import Literal
from sqlalchemy.orm import Session
from uuid import UUID
import logging
from pydantic import BaseModel

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.auth import User
from app.services.report_generator import ReportGenerator

router = APIRouter()
logger = logging.getLogger(__name__)

class ReportRequest(BaseModel):
    report_type: Literal["executive", "cbom_audit", "rbi_submission", "migration_progress", "full_scan"] = "executive"


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
        pdf_bytes = generator.generate_report(str(scan_id), payload.report_type)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=qushield_{payload.report_type}_report_{scan_id}.pdf"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")
