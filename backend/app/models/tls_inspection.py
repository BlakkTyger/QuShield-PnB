"""TLSInspection model — stores testssl.sh deep inspection results per asset."""
import uuid
import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Enum as SAEnum, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSON
from app.core.database import Base


class TLSInspectionStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class TLSInspection(Base):
    __tablename__ = "tls_inspections"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False, index=True)
    hostname = Column(String(512), nullable=False)
    port = Column(String(10), nullable=False, default="443")
    status = Column(SAEnum(TLSInspectionStatus), nullable=False, default=TLSInspectionStatus.PENDING)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    raw_json = Column(JSON, nullable=True)
    summary = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
