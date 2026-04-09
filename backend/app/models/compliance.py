"""Compliance model — regulatory check results."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from app.core.database import Base


class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    fips_203_deployed = Column(Boolean, default=False)  # ML-KEM
    fips_204_deployed = Column(Boolean, default=False)  # ML-DSA
    fips_205_deployed = Column(Boolean, default=False)  # SLH-DSA
    tls_13_enforced = Column(Boolean, default=False)
    forward_secrecy = Column(Boolean, default=False)
    cert_key_adequate = Column(Boolean, default=False)  # key length >= 2048
    ct_logged = Column(Boolean, default=False)
    chain_valid = Column(Boolean, default=False)
    crypto_agility_score = Column(Integer, default=0)  # 0-100
    computed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
