"""GeoLocation model — IP geolocation data for discovered assets."""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime
from sqlalchemy.dialects.postgresql import UUID
from app.core.database import Base


class GeoLocation(Base):
    __tablename__ = "geo_locations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=True), nullable=True, index=True)
    hostname = Column(String, nullable=True)
    ip = Column(String(45), nullable=False)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    city = Column(String, nullable=True)
    state = Column(String, nullable=True)
    country = Column(String, nullable=True)
    country_code = Column(String(3), nullable=True)
    org = Column(String, nullable=True)
    isp = Column(String, nullable=True)
    as_number = Column(String, nullable=True)
    source = Column(String(20), nullable=True)  # maxmind or ip-api.com
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
