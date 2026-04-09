import logging
import time
import re
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.scan import ScanJob
from app.models.asset import Asset
from app.services.asset_manager import create_scan_job, save_discovered_assets
from app.services.discovery_runner import run_discovery
from app.services.crypto_inspector import inspect_asset, save_crypto_results
from app.services.cbom_builder import save_cbom, build_aggregate_cbom
from app.services.risk_engine import assess_all_assets

from app.services.compliance import evaluate_compliance, compute_agility_score
from app.services.graph_builder import build_topology_graph

logger = logging.getLogger(__name__)

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,6}$"
)

def validate_targets(targets: list[str]) -> list[str]:
    valid_targets = []
    for tgt in targets:
        if not DOMAIN_REGEX.match(tgt):
            logger.warning(f"Invalid target (format): {tgt}")
            continue
        try:
            socket.gethostbyname(tgt)
            valid_targets.append(tgt)
        except socket.gaierror:
            logger.warning(f"Invalid target (DNS resolution failed): {tgt}")
    return valid_targets

class ScanOrchestrator:
    def __init__(self):
        pass

    def start_scan(self, targets: list[str], config: dict = None) -> str:
        valid_targets = validate_targets(targets)
        if not valid_targets:
            raise ValueError("No valid targets provided that pass DNS resolution.")

        db: Session = SessionLocal()
        try:
            scan_job = create_scan_job(valid_targets, db)
            scan_id = str(scan_job.id)
            logger.info(f"Started scan job: {scan_id}")
            return scan_id
        finally:
            db.close()

    def run_scan(self, scan_id: str) -> dict:
        summary = {
            "scan_id": scan_id,
            "status": "failed",
            "phases_completed": [],
            "assets_discovered": 0,
            "crypto_scans": 0,
            "cboms_generated": 0,
            "risk_assessments": 0,
            "duration_seconds": 0
        }
        
        start_time = time.time()
        db: Session = SessionLocal()
        try:
            scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if not scan_job:
                logger.error(f"Scan job not found: {scan_id}")
                return summary

            targets = scan_job.targets
            all_assets = []

            # Phase 1: Discovery
            logger.info(f"[{scan_id}] Phase 1: Discovery Engine")
            scan_job.current_phase = 1
            scan_job.status = "running"
            db.commit()
            
            for target in targets:
                try:
                    discovery_data = run_discovery(target, scan_id)
                    all_assets.extend(discovery_data.get("assets", []))
                except Exception as e:
                    logger.error(f"Discovery failed for {target}: {e}")
                    # OSINT Fallback: Log and continue
            
            # Save discovered assets to DB
            db_assets = save_discovered_assets(scan_id, all_assets, db)
            summary["assets_discovered"] = len(db_assets)
            summary["phases_completed"].append(1)

            if len(db_assets) == 0:
                logger.warning(f"[{scan_id}] Phase 1 found no assets. Terminating scan.")
                scan_job.status = "completed"
                scan_job.completed_at = datetime.utcnow()
                db.commit()
                summary["status"] = "completed_empty"
                return summary

            # Phase 2: Crypto Inspection
            logger.info(f"[{scan_id}] Phase 2: Crypto Inspection on {len(db_assets)} assets")
            scan_job.current_phase = 2
            db.commit()

            def process_crypto(asset):
                try:
                    fp = inspect_asset(asset.hostname)
                    # Use a local session since we are threading
                    local_db = SessionLocal()
                    try:
                        save_crypto_results(scan_id, str(asset.id), fp, local_db)
                    finally:
                        local_db.close()
                    return str(asset.id), fp
                except Exception as e:
                    logger.error(f"Crypto scan failed for {asset.hostname}: {e}")
                    return str(asset.id), None

            successful_crypto = 0
            asset_crypto_map = {}
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(process_crypto, asset): asset for asset in db_assets}
                for future in as_completed(futures):
                    result_id, fp = future.result()
                    if fp is not None:
                        successful_crypto += 1
                        asset_crypto_map[result_id] = fp
            
            summary["crypto_scans"] = successful_crypto
            summary["phases_completed"].append(2)

            # Phase 3: CBOM Generation
            logger.info(f"[{scan_id}] Phase 3: CBOM Generation")
            scan_job.current_phase = 3
            db.commit()

            from app.services.cbom_builder import build_cbom, save_cbom, save_cbom_to_db, build_aggregate_cbom

            successful_cboms = 0
            for asset in db_assets:
                fp = asset_crypto_map.get(str(asset.id))
                if fp:
                    try:
                        cbom_data = build_cbom(str(asset.id), fp)
                        if cbom_data:
                            # save_cbom returns file path
                            file_path = save_cbom(scan_id, str(asset.id), cbom_data["cbom_json"])
                            # also save to db
                            save_cbom_to_db(scan_id, str(asset.id), cbom_data, file_path, db)
                            successful_cboms += 1
                    except Exception as e:
                        logger.error(f"CBOM generation failed for {asset.hostname}: {e}")

            build_aggregate_cbom(scan_id, db)
            summary["cboms_generated"] = successful_cboms
            summary["phases_completed"].append(3)

            # Phase 4: Risk Engine
            logger.info(f"[{scan_id}] Phase 4: Risk Assessment")
            scan_job.current_phase = 4
            db.commit()

            try:
                results = assess_all_assets(scan_id, db)
                summary["risk_assessments"] = len(results)
            except Exception as e:
                logger.error(f"Risk assessment failed for scan {scan_id}: {e}")
            summary["phases_completed"].append(4)

            # Phase 5: Compliance Verification & Agility
            logger.info(f"[{scan_id}] Phase 5: Compliance and Agility Scores")
            scan_job.current_phase = 5
            db.commit()
            
            successful_compliance = 0
            for asset in db_assets:
                try:
                    # POC: evaluate compliance without pushing directly to a new DB table
                    # We just run the engine to make sure it doesn't fail.
                    comp = evaluate_compliance(str(asset.id), {}, {})
                    ag = compute_agility_score({})
                    successful_compliance += 1
                except Exception as e:
                    logger.error(f"Compliance failed for {asset.hostname}: {e}")

            summary["compliance_scores_computed"] = successful_compliance
            summary["phases_completed"].append(5)

            # Phase 6: Topographical Graph Buildup
            logger.info(f"[{scan_id}] Phase 6: Topographical Graph & Blast Radius")
            scan_job.current_phase = 6
            db.commit()
            
            try:
                graph_data = build_topology_graph(scan_id, db)
                summary["graph_nodes"] = graph_data["node_count"]
                summary["graph_edges"] = graph_data["edge_count"]
                summary["phases_completed"].append(6)
            except Exception as e:
                logger.error(f"Graph topology failed for scan {scan_id}: {e}")

            # Mark scan complete
            scan_job.status = "completed"
            scan_job.completed_at = datetime.utcnow()
            db.commit()
            
            summary["status"] = "completed"
            summary["duration_seconds"] = round(time.time() - start_time, 2)
            logger.info(f"[{scan_id}] Full scan pipeline completed in {summary['duration_seconds']}s")

            return summary

        except Exception as e:
            logger.error(f"[{scan_id}] Orchestrator critical failure: {e}", exc_info=True)
            if 'scan_job' in locals() and scan_job:
                scan_job.status = "failed"
                db.commit()
            return summary

        finally:
            db.close()

    def get_scan_status(self, scan_id: str) -> dict:
        db: Session = SessionLocal()
        try:
            scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if not scan_job:
                return {"error": "not found"}
            
            return {
                "scan_id": scan_id,
                "status": scan_job.status,
                "current_phase": scan_job.current_phase,
                "started_at": str(scan_job.started_at) if scan_job.started_at else None,
                "completed_at": str(scan_job.completed_at) if scan_job.completed_at else None,
                "targets": scan_job.targets
            }
        finally:
            db.close()
