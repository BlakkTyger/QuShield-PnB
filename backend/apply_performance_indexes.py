#!/usr/bin/env python3
"""
Apply performance indexes to production database.
Run this script after deploying the updated models to create database indexes.
"""
import sys
from sqlalchemy import text
from app.core.database import engine

def apply_indexes():
    """Apply all performance indexes."""
    indexes_to_create = [
        # Asset indexes
        ("ix_assets_scan_id", "CREATE INDEX IF NOT EXISTS ix_assets_scan_id ON assets (scan_id)"),
        ("ix_assets_hostname", "CREATE INDEX IF NOT EXISTS ix_assets_hostname ON assets (hostname)"),

        # AssetPort indexes
        ("ix_asset_ports_asset_id", "CREATE INDEX IF NOT EXISTS ix_asset_ports_asset_id ON asset_ports (asset_id)"),

        # ComplianceResult indexes
        ("ix_compliance_results_scan_id", "CREATE INDEX IF NOT EXISTS ix_compliance_results_scan_id ON compliance_results (scan_id)"),
        ("ix_compliance_results_asset_id", "CREATE INDEX IF NOT EXISTS ix_compliance_results_asset_id ON compliance_results (asset_id)"),

        # CBOMRecord indexes
        ("ix_cbom_records_scan_id", "CREATE INDEX IF NOT EXISTS ix_cbom_records_scan_id ON cbom_records (scan_id)"),
        ("ix_cbom_records_asset_id", "CREATE INDEX IF NOT EXISTS ix_cbom_records_asset_id ON cbom_records (asset_id)"),

        # CBOMComponent indexes
        ("ix_cbom_components_scan_id", "CREATE INDEX IF NOT EXISTS ix_cbom_components_scan_id ON cbom_components (scan_id)"),
        ("ix_cbom_components_cbom_id", "CREATE INDEX IF NOT EXISTS ix_cbom_components_cbom_id ON cbom_components (cbom_id)"),
        ("ix_cbom_components_name", "CREATE INDEX IF NOT EXISTS ix_cbom_components_name ON cbom_components (name)"),
        ("ix_cbom_components_component_type", "CREATE INDEX IF NOT EXISTS ix_cbom_components_component_type ON cbom_components (component_type)"),

        # Certificate indexes
        ("ix_certificates_scan_id", "CREATE INDEX IF NOT EXISTS ix_certificates_scan_id ON certificates (scan_id)"),
        ("ix_certificates_asset_id", "CREATE INDEX IF NOT EXISTS ix_certificates_asset_id ON certificates (asset_id)"),
        ("ix_certificates_ca_name", "CREATE INDEX IF NOT EXISTS ix_certificates_ca_name ON certificates (ca_name)"),

        # RiskScore indexes
        ("ix_risk_scores_scan_id", "CREATE INDEX IF NOT EXISTS ix_risk_scores_scan_id ON risk_scores (scan_id)"),
        ("ix_risk_scores_asset_id", "CREATE INDEX IF NOT EXISTS ix_risk_scores_asset_id ON risk_scores (asset_id)"),

        # RiskFactor indexes
        ("ix_risk_factors_risk_score_id", "CREATE INDEX IF NOT EXISTS ix_risk_factors_risk_score_id ON risk_factors (risk_score_id)"),
    ]

    created = []
    failed = []

    with engine.connect() as conn:
        for index_name, sql in indexes_to_create:
            try:
                conn.execute(text(sql))
                conn.commit()
                created.append(index_name)
                print(f"✅ Created index: {index_name}")
            except Exception as e:
                failed.append((index_name, str(e)))
                print(f"❌ Failed to create index {index_name}: {e}")

    print(f"\n Summary: {len(created)} indexes created, {len(failed)} failed")

    if failed:
        print("\n⚠️ Failed indexes:")
        for name, error in failed:
            print(f"  - {name}: {error}")
        return 1

    print("\nAll performance indexes applied successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(apply_indexes())
