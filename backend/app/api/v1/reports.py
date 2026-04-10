"""
Reports API Endpoint — Triggers and downloads AI-generated PDF/HTML reports.
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from fastapi.responses import Response
from typing import Optional
from sqlalchemy.orm import Session
from uuid import UUID
import logging

from app.core.database import get_db
from app.api.v1.auth import get_current_user
from app.models.auth import User
from app.services.report_generator import ReportGenerator

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/generate/{scan_id}")
def generate_report(scan_id: UUID, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Generate an AI-driven Executive Summary PDF for the given scan_id."""
    try:
        generator = ReportGenerator(db, current_user)
        pdf_bytes = generator.generate_executive_report(str(scan_id))
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=qushield_executive_report_{scan_id}.pdf"}
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to generate report: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate report")
