"""Pydantic schemas for Asset operations."""
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class PortInfo(BaseModel):
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    banner: Optional[str] = None


class AssetCreate(BaseModel):
    """Data for creating an asset from discovery results."""
    hostname: str
    url: Optional[str] = None
    ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None
    asset_type: str = "web_server"
    discovery_method: Optional[str] = None
    hosting_provider: Optional[str] = None
    web_server: Optional[str] = None
    confidence_score: float = 0.0
    ports: list[PortInfo] = []


class AssetResponse(BaseModel):
    """Full asset detail response."""
    id: UUID
    scan_id: UUID
    hostname: str
    url: Optional[str] = None
    ip_v4: Optional[str] = None
    ip_v6: Optional[str] = None
    asset_type: str
    discovery_method: Optional[str] = None
    is_shadow: bool = False
    hosting_provider: Optional[str] = None
    web_server: Optional[str] = None
    tls_version: Optional[str] = None
    confidence_score: float = 0.0
    first_seen_at: datetime
    last_seen_at: datetime
    ports: list[PortInfo] = []

    model_config = {"from_attributes": True}


class AssetList(BaseModel):
    """Paginated list of assets."""
    items: list[AssetResponse]
    total: int
    page: int = 1
    page_size: int = 50
