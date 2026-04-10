#!/usr/bin/env python3
"""
Standalone Deep Scan Test — runs the orchestrator directly (no API server).
This bypasses FastAPI, auth, caching, and SSE to isolate orchestrator bugs.

Usage:
    cd backend
    python tests/standalone/test_deep_scan.py [domain]

Default domain: pnb.bank.in
"""

import sys
import os
import time
import json
import logging

# Add backend to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.core.database import SessionLocal
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.models.certificate import Certificate
from app.models.risk import RiskScore
from app.models.cbom import CBOMRecord, CBOMComponent
from app.models.compliance import ComplianceResult
from app.services.orchestrator import ScanOrchestrator

# ─── Logging Setup ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)-7s] %(name)-30s %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("tests/standalone/deep_scan_debug.log", mode="w"),
    ],
)
# Reduce noise from urllib3/httpx
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)

logger = logging.getLogger("test_deep_scan")

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "pnb.bank.in"


def main():
    logger.info("=" * 70)
    logger.info(f"  STANDALONE DEEP SCAN TEST — {DOMAIN}")
    logger.info("=" * 70)

    orch = ScanOrchestrator()

    # Step 1: Create scan job
    logger.info("Step 1: Creating scan job...")
    t0 = time.time()
    try:
        scan_id = orch.start_scan([DOMAIN])
    except Exception as e:
        logger.error(f"start_scan FAILED: {e}", exc_info=True)
        return
    logger.info(f"Scan job created: {scan_id} ({time.time()-t0:.2f}s)")

    # Step 2: Run the scan (no event loop — SSE won't fire, that's OK)
    logger.info("Step 2: Running scan pipeline (no SSE)...")
    t0 = time.time()
    summary = orch.run_scan(scan_id, loop=None)
    elapsed = time.time() - t0

    logger.info("=" * 70)
    logger.info(f"  SCAN RESULT: {summary.get('status', 'UNKNOWN')}")
    logger.info(f"  Duration: {elapsed:.1f}s")
    logger.info("=" * 70)
    logger.info(f"Summary: {json.dumps(summary, indent=2, default=str)}")

    # Step 3: Validate DB state
    logger.info("\nStep 3: Validating database state...")
    db = SessionLocal()
    try:
        scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
        if not scan_job:
            logger.error("ScanJob NOT FOUND in DB!")
            return

        logger.info(f"  ScanJob status:         {scan_job.status}")
        logger.info(f"  ScanJob current_phase:  {scan_job.current_phase}")
        logger.info(f"  ScanJob total_assets:   {scan_job.total_assets}")
        logger.info(f"  ScanJob total_certs:    {scan_job.total_certificates}")
        logger.info(f"  ScanJob total_vuln:     {scan_job.total_vulnerable}")
        logger.info(f"  ScanJob error:          {scan_job.error_message}")

        assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
        logger.info(f"\n  Assets in DB: {len(assets)}")
        for a in assets[:5]:
            logger.info(f"    {a.hostname:40s} ip={a.ip_v4 or '?':20s} type={a.asset_type or '?'}")
        if len(assets) > 5:
            logger.info(f"    ... and {len(assets)-5} more")

        certs = db.query(Certificate).filter(Certificate.scan_id == scan_id).all()
        logger.info(f"\n  Certificates in DB: {len(certs)}")
        for c in certs[:5]:
            logger.info(f"    CN={c.common_name or '?':40s} issuer={c.issuer or '?':30s} key={c.key_type}")
        if len(certs) > 5:
            logger.info(f"    ... and {len(certs)-5} more")

        cboms = db.query(CBOMRecord).filter(CBOMRecord.scan_id == scan_id).all()
        total_comps = 0
        for cbom in cboms:
            count = db.query(CBOMComponent).filter(CBOMComponent.cbom_id == cbom.id).count()
            total_comps += count
        logger.info(f"\n  CBOM records: {len(cboms)}, total components: {total_comps}")

        risks = db.query(RiskScore).filter(RiskScore.scan_id == scan_id).all()
        logger.info(f"\n  Risk scores: {len(risks)}")
        classifications = {}
        for r in risks:
            cls = r.risk_classification or "unknown"
            classifications[cls] = classifications.get(cls, 0) + 1
        for cls, count in sorted(classifications.items()):
            logger.info(f"    {cls}: {count}")

        compliances = db.query(ComplianceResult).filter(ComplianceResult.scan_id == scan_id).all()
        logger.info(f"\n  Compliance results: {len(compliances)}")

        # Final verdict
        logger.info("\n" + "=" * 70)
        all_ok = (
            scan_job.status == "completed"
            and len(assets) > 0
            and len(certs) > 0
            and len(cboms) > 0
            and len(risks) > 0
            and len(compliances) > 0
        )
        if all_ok:
            logger.info("  ✅ STANDALONE DEEP SCAN: ALL PHASES PASSED")
        else:
            logger.warning("  ❌ STANDALONE DEEP SCAN: SOME PHASES HAVE ISSUES")
            if scan_job.status != "completed":
                logger.warning(f"    - ScanJob status is '{scan_job.status}', not 'completed'")
            if len(assets) == 0:
                logger.warning("    - No assets discovered")
            if len(certs) == 0:
                logger.warning("    - No certificates saved")
            if len(cboms) == 0:
                logger.warning("    - No CBOM records generated")
            if len(risks) == 0:
                logger.warning("    - No risk scores computed")
            if len(compliances) == 0:
                logger.warning("    - No compliance results")
        logger.info("=" * 70)

    finally:
        db.close()

    logger.info(f"\nFull debug log: tests/standalone/deep_scan_debug.log")


if __name__ == "__main__":
    main()
