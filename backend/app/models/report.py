from sqlalchemy import Column, String, DateTime, Boolean, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid

from app.core.database import Base

class ReportSchedule(Base):
    __tablename__ = "report_schedules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    report_type = Column(String, nullable=False)
    frequency = Column(String, nullable=False) # e.g. "Weekly", "Monthly", etc.
    target_assets = Column(String, nullable=False) # e.g. "All Assets" or specific IDs
    sections = Column(JSON, nullable=True) # e.g. ["discovery", "inventory", "cbom", "pqc_posture", "cyber_rating"]
    schedule_date = Column(DateTime, nullable=True)
    schedule_time = Column(String, nullable=True)
    time_zone = Column(String, nullable=True)
    delivery_email = Column(String, nullable=True)
    delivery_location = Column(String, nullable=True)
    download_link = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
