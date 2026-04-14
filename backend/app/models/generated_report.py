"""GeneratedReport model — persists report files with metadata for quick access and AI RAG."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class GeneratedReport(Base):
    __tablename__ = "generated_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    report_type = Column(String(50), nullable=False)  # executive, full_scan, rbi_submission, cbom_audit, migration_progress, pqc_migration_plan
    format = Column(String(10), nullable=False, default="pdf")  # pdf, csv, json
    title = Column(String(255), nullable=True)
    file_path = Column(Text, nullable=True)          # Absolute path to saved file
    file_size_kb = Column(Integer, nullable=True)
    generated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    targets = Column(Text, nullable=True)            # Comma-separated target domains for display

    user = relationship("User")
    scan = relationship("ScanJob")
