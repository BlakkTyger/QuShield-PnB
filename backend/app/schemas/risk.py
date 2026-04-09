"""Pydantic schemas for Risk Engine operations."""
from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel, Field


class MoscaInput(BaseModel):
    """Input for Mosca inequality simulation."""
    migration_time_years: float = Field(..., ge=0, description="X: estimated migration time in years")
    data_shelf_life_years: float = Field(..., ge=0, description="Y: data shelf life in years")
    crqc_pessimistic_year: int = Field(default=2029, description="Z pessimistic: aggressive CRQC estimate")
    crqc_median_year: int = Field(default=2032, description="Z median: consensus estimate")
    crqc_optimistic_year: int = Field(default=2035, description="Z optimistic: conservative estimate")


class MoscaResult(BaseModel):
    """Result of Mosca inequality computation."""
    exposed_pessimistic: bool
    exposed_median: bool
    exposed_optimistic: bool
    years_until_exposure_pessimistic: Optional[float] = None


class RiskFactorResponse(BaseModel):
    factor_name: str
    factor_score: float
    factor_weight: float
    rationale: Optional[str] = None

    model_config = {"from_attributes": True}


class RiskScoreResponse(BaseModel):
    id: UUID
    asset_id: UUID
    scan_id: UUID
    quantum_risk_score: int
    risk_classification: str
    mosca_x: Optional[float] = None
    mosca_y: Optional[float] = None
    hndl_exposed: bool = False
    tnfl_risk: bool = False
    tnfl_severity: Optional[str] = None
    computed_at: datetime
    factors: list[RiskFactorResponse] = []

    model_config = {"from_attributes": True}
