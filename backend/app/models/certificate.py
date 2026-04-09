"""Certificate model — parsed TLS certificate data."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class Certificate(Base):
    __tablename__ = "certificates"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    common_name = Column(String(512), nullable=True)
    san_list = Column(JSON, nullable=True)  # list of subject alt names
    issuer = Column(String(512), nullable=True)
    ca_name = Column(String(255), nullable=True)
    key_type = Column(String(20), nullable=True)  # RSA, EC, Ed25519, ML-DSA
    key_length = Column(Integer, nullable=True)
    signature_algorithm = Column(String(100), nullable=True)
    signature_algorithm_oid = Column(String(100), nullable=True)
    valid_from = Column(DateTime(timezone=True), nullable=True)
    valid_to = Column(DateTime(timezone=True), nullable=True)
    sha256_fingerprint = Column(String(64), nullable=True, unique=True)
    is_ct_logged = Column(Boolean, default=False)
    nist_quantum_level = Column(Integer, default=-1)  # 0-6, -1=unknown
    is_quantum_vulnerable = Column(Boolean, default=True)
    chain_depth = Column(Integer, default=0)  # 0=leaf, 1=intermediate, 2=root
    chain_valid = Column(Boolean, nullable=True)
    forward_secrecy = Column(Boolean, nullable=True)
    negotiated_cipher = Column(String(100), nullable=True)
    tls_version = Column(String(20), nullable=True)

    asset = relationship("Asset", back_populates="certificates")
