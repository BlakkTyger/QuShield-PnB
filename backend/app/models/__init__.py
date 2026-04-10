"""
QuShield-PnB Database Models

Import all models here so SQLAlchemy registers them with Base.metadata.
"""
from app.core.database import Base

from app.models.scan import ScanJob, ScanStatus
from app.models.asset import Asset, AssetPort
from app.models.certificate import Certificate
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.risk import RiskScore, RiskFactor
from app.models.compliance import ComplianceResult
from app.models.auth import User, EmailVerification, ScanCache
__all__ = [
    "Base",
    "ScanJob", "ScanStatus",
    "Asset", "AssetPort",
    "Certificate",
    "CBOMRecord", "CBOMComponent",
    "RiskScore", "RiskFactor",
    "ComplianceResult",
    "User", "EmailVerification", "ScanCache"
]
