"""Risk models — quantum risk scores and factors."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.core.database import Base


class RiskScore(Base):
    __tablename__ = "risk_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    quantum_risk_score = Column(Integer, default=0)  # 0-1000
    risk_classification = Column(String(30), default="unknown")  # quantum_ready, aware, at_risk, vulnerable, critical
    mosca_x = Column(Float, nullable=True)  # migration time (years)
    mosca_y = Column(Float, nullable=True)  # data shelf life (years)
    mosca_z_pessimistic = Column(Float, nullable=True)  # CRQC arrival pessimistic
    mosca_z_median = Column(Float, nullable=True)
    mosca_z_optimistic = Column(Float, nullable=True)
    hndl_exposed = Column(Boolean, default=False)
    tnfl_risk = Column(Boolean, default=False)
    tnfl_severity = Column(String(20), nullable=True)  # CRITICAL, HIGH, MEDIUM, LOW
    computed_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    factors = relationship("RiskFactor", back_populates="risk_score", cascade="all, delete-orphan")


class RiskFactor(Base):
    __tablename__ = "risk_factors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    risk_score_id = Column(UUID(as_uuid=True), ForeignKey("risk_scores.id"), nullable=False, index=True)
    factor_name = Column(String(100), nullable=False)
    factor_score = Column(Float, default=0.0)
    factor_weight = Column(Float, default=0.0)
    rationale = Column(Text, nullable=True)

    risk_score = relationship("RiskScore", back_populates="factors")
