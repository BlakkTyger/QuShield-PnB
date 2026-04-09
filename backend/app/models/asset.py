"""Asset and AssetPort models — discovered infrastructure."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, Text
from sqlalchemy.dialects.postgresql import UUID, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scan_jobs.id"), nullable=False)
    hostname = Column(String(512), nullable=False)
    url = Column(String(2048), nullable=True)
    ip_v4 = Column(String(45), nullable=True)
    ip_v6 = Column(String(45), nullable=True)
    asset_type = Column(String(50), default="web_server")  # web_server, api, mail, dns, etc.
    discovery_method = Column(String(100), nullable=True)  # subfinder, naabu, httpx
    is_shadow = Column(Boolean, default=False)
    hosting_provider = Column(String(255), nullable=True)
    cdn_detected = Column(String(100), nullable=True)  # Akamai, Cloudflare, Incapsula, etc.
    waf_detected = Column(String(100), nullable=True)   # WAF product name if detected
    is_third_party = Column(Boolean, default=False)     # True if asset is a third-party dependency
    web_server = Column(String(255), nullable=True)
    tls_version = Column(String(20), nullable=True)
    confidence_score = Column(Float, default=0.0)
    first_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    ports = relationship("AssetPort", back_populates="asset", cascade="all, delete-orphan")
    certificates = relationship("Certificate", back_populates="asset", cascade="all, delete-orphan")


class AssetPort(Base):
    __tablename__ = "asset_ports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    asset_id = Column(UUID(as_uuid=True), ForeignKey("assets.id"), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    service_name = Column(String(100), nullable=True)
    banner = Column(Text, nullable=True)

    asset = relationship("Asset", back_populates="ports")
