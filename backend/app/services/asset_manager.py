"""
Asset Manager — persists discovered assets to the database.
"""
import uuid
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.core.timing import timed
from app.models.asset import Asset, AssetPort
from app.models.scan import ScanJob, ScanStatus

logger = get_logger("asset_manager")


@timed
def save_discovered_assets(
    scan_id: str,
    assets: list[dict],
    db: Session,
) -> list[Asset]:
    """
    Save discovered assets to the database.

    Args:
        scan_id: UUID of the scan job
        assets: List of asset dicts from discovery engine output
        db: SQLAlchemy session

    Returns:
        List of created/updated Asset ORM objects
    """
    created = 0
    updated = 0
    ports_created = 0
    result_assets = []

    for asset_data in assets:
        hostname = asset_data.get("hostname", "")
        ip_v4 = asset_data.get("ip_v4", "")

        # Check for existing asset (by hostname) within THIS scan
        existing = db.query(Asset).filter(
            Asset.hostname == hostname,
            Asset.scan_id == (uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id)
        ).first()

        # Shadow IT Heuristics
        is_shadow = any(k in hostname.lower() for k in ["dev", "uat", "test", "staging", "legacy", "old", "beta", "demo"])

        # Supply chain Heuristics
        vendor_match = None
        hostname_parts = hostname.lower()
        if any(v in hostname_parts for v in ["npci", "rupay", "upi", "bhim", "aeps"]): vendor_match = "NPCI"
        elif "finacle" in hostname_parts: vendor_match = "Infosys Finacle"
        elif "bancs" in hostname_parts: vendor_match = "TCS BaNCS"
        elif "flexcube" in hostname_parts: vendor_match = "Oracle Flexcube"
        elif "razorpay" in hostname_parts: vendor_match = "Razorpay"
        elif "billdesk" in hostname_parts: vendor_match = "BillDesk"
        elif "payu" in hostname_parts: vendor_match = "PayU"
        elif "swift" in hostname_parts: vendor_match = "SWIFT Network"
        elif "fss" in hostname_parts: vendor_match = "FSS"

        if existing:
            # Update existing asset WITHIN the current scan
            existing.last_seen_at = datetime.now(timezone.utc)
            if asset_data.get("http", {}).get("web_server"):
                existing.web_server = asset_data["http"]["web_server"]
            if asset_data.get("http", {}).get("tls_version"):
                existing.tls_version = asset_data["http"]["tls_version"]
            existing.confidence_score = asset_data.get("confidence_score", 0.0)
            existing.discovery_method = ", ".join(asset_data.get("discovery_methods", []))
            existing.is_shadow = is_shadow
            if vendor_match:
                existing.is_third_party = True
                existing.third_party_vendor = vendor_match

            result_assets.append(existing)
            updated += 1
        else:
            # Fetch `first_seen_at` from prior scan if exists, to maintain continuity
            prior_asset = db.query(Asset).filter(Asset.hostname == hostname).order_by(Asset.first_seen_at.asc()).first()
            first_seen = prior_asset.first_seen_at if prior_asset else datetime.now(timezone.utc)
            
            # Create new asset record for this scan
            http_info = asset_data.get("http", {}) or {}
            asset = Asset(
                scan_id=uuid.UUID(scan_id) if isinstance(scan_id, str) else scan_id,
                hostname=hostname,
                url=http_info.get("url") or f"https://{hostname}",
                ip_v4=ip_v4,
                ip_v6=asset_data.get("ip_v6"),
                asset_type="web_server",
                discovery_method=", ".join(asset_data.get("discovery_methods", [])),
                web_server=http_info.get("web_server"),
                tls_version=http_info.get("tls_version"),
                confidence_score=asset_data.get("confidence_score", 0.0),
                is_shadow=is_shadow,
                is_third_party=vendor_match is not None,
                third_party_vendor=vendor_match,
            )
            db.add(asset)
            db.flush()  # Get the ID

            # Create port records
            for port_data in asset_data.get("ports", []):
                port = AssetPort(
                    asset_id=asset.id,
                    port=port_data.get("port"),
                    protocol=port_data.get("protocol", "tcp"),
                    service_name=port_data.get("service"),
                )
                db.add(port)
                ports_created += 1

            result_assets.append(asset)
            created += 1

    db.commit()

    logger.info(
        f"Saved {len(assets)} assets: {created} new, {updated} updated, {ports_created} ports",
        extra={
            "scan_id": scan_id,
            "assets_created": created,
            "assets_updated": updated,
            "ports_added": ports_created,
        },
    )

    return result_assets


@timed
def create_scan_job(targets: list[str], db: Session, user_id: Optional[uuid.UUID] = None, scan_type: str = "deep") -> ScanJob:
    """Create a new scan job record."""
    scan = ScanJob(
        targets=targets,
        status=ScanStatus.QUEUED,
        scan_type=scan_type,
        user_id=user_id
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    logger.info(
        f"Created scan job {scan.id}",
        extra={"scan_id": str(scan.id), "targets": targets},
    )
    return scan
