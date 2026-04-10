"""Authentication models — User, EmailVerification, and ScanCache."""
import uuid
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    email_verified = Column(Boolean, default=False)
    
    # AI Feature Flags & Preferences
    deployment_mode = Column(String(20), default="secure") # secure | cloud
    ai_tier = Column(String(20), default="free")           # free | professional | enterprise
    cloud_api_keys = Column(JSON, nullable=True)           # Encrypted dict of external provider keys
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relationships
    scan_jobs = relationship("ScanJob", back_populates="user", cascade="all, delete-orphan")
    scan_caches = relationship("ScanCache", back_populates="user", cascade="all, delete-orphan")


class EmailVerification(Base):
    __tablename__ = "email_verifications"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)


class ScanCache(Base):
    __tablename__ = "scan_caches"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(String(255), index=True, nullable=False)
    scan_type = Column(String(10), nullable=False)  # quick/shallow/deep
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True) # Public rapid scans might not have user
    cached_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True), nullable=False)

    user = relationship("User", back_populates="scan_caches")
    scan_job = relationship("ScanJob")
