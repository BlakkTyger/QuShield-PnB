"""Compliance model — regulatory check results."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    fips_203_deployed = Column(Boolean, default=False)  # ML-KEM
    fips_204_deployed = Column(Boolean, default=False)  # ML-DSA
    fips_205_deployed = Column(Boolean, default=False)  # SLH-DSA
    tls_13_enforced = Column(Boolean, default=False)
    forward_secrecy = Column(Boolean, default=False)
    hybrid_mode_active = Column(Boolean, default=False)  # X25519+ML-KEM hybrid
    classical_deprecated = Column(Boolean, default=False)  # RSA/ECDHE/ECDSA gone
    cert_key_adequate = Column(Boolean, default=False)  # key length >= 2048
    ct_logged = Column(Boolean, default=False)
    chain_valid = Column(Boolean, default=False)
    rbi_compliant = Column(Boolean, default=False)  # RBI IT Framework
    sebi_compliant = Column(Boolean, default=False)  # SEBI CSCRF
    pci_compliant = Column(Boolean, default=False)  # PCI DSS 4.0
    npci_compliant = Column(Boolean, default=False)  # NPCI UPI mTLS
    crypto_agility_score = Column(Integer, default=0)  # 0-100
    compliance_pct = Column(Float, default=0.0)  # overall compliance %
    checks_json = Column(JSON, nullable=True)  # detailed check results
    computed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationship for efficient joins
    asset = relationship("Asset", lazy="noload")
