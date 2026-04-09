"""Pydantic schemas for Scan operations."""
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request to start a new scan."""
    targets: list[str] = Field(..., min_length=1, description="List of domains/IPs to scan")
    config: Optional[dict] = Field(default=None, description="Optional scan configuration overrides")


class ScanPhaseStatus(BaseModel):
    """Status of a single scan phase."""
    phase: int
    name: str
    status: str  # pending, running, completed, failed
    duration_ms: Optional[float] = None
    assets_processed: Optional[int] = None


class ScanResponse(BaseModel):
    """Response after creating a scan."""
    scan_id: UUID
    status: str
    created_at: datetime
    message: str = "Scan queued successfully"


class ScanStatus(BaseModel):
    """Full scan status with phase details."""
    scan_id: UUID
    status: str
    current_phase: int
    targets: list[str]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_assets: int = 0
    total_certificates: int = 0
    total_vulnerable: int = 0
    error_message: Optional[str] = None

    model_config = {"from_attributes": True}
