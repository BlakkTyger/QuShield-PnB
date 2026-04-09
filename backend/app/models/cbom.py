"""CBOM models — CycloneDX Cryptographic Bill of Materials."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, Float, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class CBOMRecord(Base):
    __tablename__ = "cbom_records"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    spec_version = Column(String(10), default="1.6")  # CycloneDX spec version
    file_path = Column(String(1024), nullable=True)  # local filesystem path to .cdx.json
    total_components = Column(Integer, default=0)
    vulnerable_components = Column(Integer, default=0)
    quantum_ready_pct = Column(Float, default=0.0)
    generated_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    components = relationship("CBOMComponent", back_populates="cbom_record", cascade="all, delete-orphan")


class CBOMComponent(Base):
    __tablename__ = "cbom_components"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    cbom_id = Column(UUID(as_uuid=True), ForeignKey("cbom_records.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    name = Column(String(255), nullable=False)
    component_type = Column(String(50), nullable=False)  # algorithm, certificate, key_exchange, protocol
    nist_quantum_level = Column(Integer, default=-1)
    is_quantum_vulnerable = Column(Boolean, default=True)
    key_type = Column(String(50), nullable=True)  # RSA, EC, Ed25519
    key_length = Column(Integer, nullable=True)
    tls_version = Column(String(20), nullable=True)
    bom_ref = Column(String(255), nullable=True)

    cbom_record = relationship("CBOMRecord", back_populates="components")
