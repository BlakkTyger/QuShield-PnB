"""Pydantic schemas for Compliance operations."""
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class ComplianceResponse(BaseModel):
    id: UUID
    asset_id: UUID
    scan_id: UUID
    fips_203_deployed: bool = False
    fips_204_deployed: bool = False
    fips_205_deployed: bool = False
    tls_13_enforced: bool = False
    forward_secrecy: bool = False
    cert_key_adequate: bool = False
    ct_logged: bool = False
    chain_valid: bool = False
    crypto_agility_score: int = 0
    computed_at: datetime

    model_config = {"from_attributes": True}
