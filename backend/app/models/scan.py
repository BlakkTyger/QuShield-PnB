"""ScanJob model — tracks scan lifecycle."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, Text, Enum as SAEnum, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID, JSON
from app.core.database import Base
import enum


class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, enum.Enum):
    QUICK = "quick"
    SHALLOW = "shallow"
    DEEP = "deep"


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    targets = Column(JSON, nullable=False)  # list of domain strings
    config = Column(JSON, nullable=True)  # scan configuration overrides
    status = Column(String(20), default=ScanStatus.QUEUED, nullable=False)
    scan_type = Column(String(10), default=ScanType.DEEP, nullable=False)
    current_phase = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)
    # Summary stats (populated on completion)
    total_assets = Column(Integer, default=0)
    total_certificates = Column(Integer, default=0)
    total_vulnerable = Column(Integer, default=0)
    
    # Relationships
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True) # nullable for back-compat
    user = relationship("User", back_populates="scan_jobs")
