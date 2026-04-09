"""Pydantic schemas for CBOM operations."""
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class CBOMComponentResponse(BaseModel):
    component_type: str
    algorithm_name: str
    key_length: Optional[int] = None
    nist_quantum_level: int = -1
    is_quantum_vulnerable: bool = True
    usage_context: Optional[str] = None
    pqc_replacement: Optional[str] = None

    model_config = {"from_attributes": True}


class CBOMResponse(BaseModel):
    id: UUID
    scan_id: UUID
    asset_id: UUID
    component_count: int = 0
    vulnerable_count: int = 0
    file_path: Optional[str] = None
    generated_at: datetime
    components: list[CBOMComponentResponse] = []

    model_config = {"from_attributes": True}
