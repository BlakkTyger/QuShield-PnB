"""ScanJob model — tracks scan lifecycle."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID, JSON
from app.core.database import Base
import enum


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    targets = Column(JSON, nullable=False)  # list of domain strings
    config = Column(JSON, nullable=True)  # scan configuration overrides
    status = Column(String(20), default=ScanStatus.QUEUED, nullable=False)
    current_phase = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    # Summary stats (populated on completion)
    total_assets = Column(Integer, default=0)
    total_certificates = Column(Integer, default=0)
    total_vulnerable = Column(Integer, default=0)
