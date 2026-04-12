"""
Remove all database (and on-disk graph) data tied to a scan_jobs row.

Required before DELETE scan_jobs when child tables use ON DELETE RESTRICT
(default SQLAlchemy FK without ondelete=CASCADE).
"""
from __future__ import annotations

import logging
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import PROJECT_ROOT
from app.models.asset import Asset
from app.models.auth import ScanCache
from app.models.certificate import Certificate
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.compliance import ComplianceResult
from app.models.geo import GeoLocation
from app.models.risk import RiskScore
from app.core.logging import get_logger

logger = get_logger("scan_cleanup")


def purge_scan_dependencies(db: Session, scan_id: uuid.UUID) -> None:
    """
    Delete rows that reference scan_jobs.id = scan_id.

    Order respects foreign keys: CBOM/risk/compliance/certs/geo/cache, then assets (ports cascade).
    """
    sid = scan_id

    # CBOM: delete records (ORM cascades to components); also strip any stray components by scan_id
    for comp in db.query(CBOMComponent).filter(CBOMComponent.scan_id == sid).all():
        db.delete(comp)
    for rec in db.query(CBOMRecord).filter(CBOMRecord.scan_id == sid).all():
        db.delete(rec)

    for rs in db.query(RiskScore).filter(RiskScore.scan_id == sid).all():
        db.delete(rs)

    db.query(ComplianceResult).filter(ComplianceResult.scan_id == sid).delete(synchronize_session=False)
    db.query(Certificate).filter(Certificate.scan_id == sid).delete(synchronize_session=False)
    db.query(GeoLocation).filter(GeoLocation.scan_id == sid).delete(synchronize_session=False)
    db.query(ScanCache).filter(ScanCache.scan_id == sid).delete(synchronize_session=False)

    for asset in db.query(Asset).filter(Asset.scan_id == sid).all():
        db.delete(asset)

    graph_path = PROJECT_ROOT / "data" / "graphs" / f"{sid}.json"
    try:
        if graph_path.is_file():
            graph_path.unlink()
    except OSError as e:
        logger.warning("Could not remove topology graph %s: %s", graph_path, e)

    db.flush()
    logger.info("Purged all dependencies for scan_id=%s", sid)
