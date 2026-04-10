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

from app.services.compliance import evaluate_compliance, compute_agility_score, save_compliance_result
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
            raw_asset_map = {a.get("hostname"): a for a in all_assets}
            mapped_assets = [(str(a.id), a.hostname) for a in db_assets]

            def process_crypto(asset_id_str, asset_hostname):
                try:
                    raw_data = raw_asset_map.get(asset_hostname, {})
                    tls_results = raw_data.get("tls_results")
                    fp = inspect_asset(asset_hostname, pre_fetched_tls=tls_results)
                    # Use a local session since we are threading
                    local_db = SessionLocal()
                    try:
                        save_crypto_results(scan_id, asset_id_str, fp, local_db)
                    finally:
                        local_db.close()
                    return asset_id_str, fp
                except Exception as e:
                    logger.error(f"Crypto scan failed for {asset_hostname}: {e}")
                    return asset_id_str, None

            successful_crypto = 0
            asset_crypto_map = {}
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(process_crypto, a_id, a_host): a_id for a_id, a_host in mapped_assets}
                for future in as_completed(futures):
                    result_id, fp = future.result()
                    if fp is not None:
                        successful_crypto += 1
                        asset_crypto_map[result_id] = fp
            
            summary["crypto_scans"] = successful_crypto
            summary["phases_completed"].append(2)

            # Phase 2.5: Incremental scan — compute fingerprints and detect deltas
            from app.services.incremental import (
                compute_asset_fingerprint, find_previous_asset,
                is_unchanged, clone_scan_data,
            )
            cloned_count = 0
            assets_to_scan = set()  # asset IDs that need full pipeline
            for asset in db_assets:
                asset_id_str = str(asset.id)
                fp = asset_crypto_map.get(asset_id_str)
                if fp:
                    fph = compute_asset_fingerprint(asset, fp)
                    asset.fingerprint_hash = fph
                    prev = find_previous_asset(asset.hostname, scan_id, db)
                    if prev and is_unchanged(fph, prev):
                        # Clone prior results instead of re-processing
                        clone_scan_data(prev.id, scan_id, asset.id, db)
                        cloned_count += 1
                    else:
                        assets_to_scan.add(asset_id_str)
                else:
                    assets_to_scan.add(asset_id_str)
            db.commit()
            summary["cloned_assets"] = cloned_count
            summary["rescanned_assets"] = len(assets_to_scan)
            logger.info(f"[{scan_id}] Incremental: {cloned_count} cloned, {len(assets_to_scan)} need full pipeline")

            # Phase 3: CBOM Generation
            logger.info(f"[{scan_id}] Phase 3: CBOM Generation")
            scan_job.current_phase = 3
            db.commit()

            from app.services.cbom_builder import build_cbom, save_cbom, save_cbom_to_db, build_aggregate_cbom

            successful_cboms = 0

            def process_cbom(asset_obj):
                if str(asset_obj.id) not in assets_to_scan:
                    return False  # Already cloned
                fp = asset_crypto_map.get(str(asset_obj.id))
                if not fp:
                    return False
                try:
                    cbom_data = build_cbom(str(asset_obj.id), fp)
                    if cbom_data:
                        file_path = save_cbom(scan_id, str(asset_obj.id), cbom_data["cbom_json"])
                        local_db = SessionLocal()
                        try:
                            save_cbom_to_db(scan_id, str(asset_obj.id), cbom_data, file_path, local_db)
                        finally:
                            local_db.close()
                        return True
                except Exception as e:
                    logger.error(f"CBOM generation failed for {asset_obj.hostname}: {e}")
                return False

            with ThreadPoolExecutor(max_workers=10) as executor:
                cbom_futures = {executor.submit(process_cbom, a): a for a in db_assets}
                for f in as_completed(cbom_futures):
                    if f.result():
                        successful_cboms += 1

            build_aggregate_cbom(scan_id, db)
            summary["cboms_generated"] = successful_cboms
            summary["phases_completed"].append(3)

            # Phase 4: Risk Engine
            logger.info(f"[{scan_id}] Phase 4: Risk Assessment")
            scan_job.current_phase = 4
            db.commit()

            # IDs of cloned assets (already have risk/compliance from prior scan)
            cloned_ids = {str(a.id) for a in db_assets if str(a.id) not in assets_to_scan}

            try:
                results = assess_all_assets(scan_id, db, skip_asset_ids=cloned_ids)
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
                if str(asset.id) in cloned_ids:
                    continue  # Already cloned from prior scan
                try:
                    # Build crypto_data dict from the asset's crypto fingerprint
                    fp = asset_crypto_map.get(str(asset.id), {})
                    tls_data = fp.get("tls") or {}
                    certs_list = fp.get("certificates") or []
                    first_cert = certs_list[0] if certs_list else {}
                    auth_data = fp.get("auth") or {}
                    crypto_data = {
                        "tls": {
                            "negotiated_protocol": tls_data.get("negotiated_protocol", "") or "",
                            "negotiated_cipher": tls_data.get("negotiated_cipher", "") or "",
                            "forward_secrecy": tls_data.get("forward_secrecy", False),
                            "key_exchange": tls_data.get("key_exchange", "") or "",
                        },
                        "certificate": {
                            "key_type": first_cert.get("key_type", "") or "",
                            "key_length": first_cert.get("key_length", 0) or 0,
                            "ct_logged": first_cert.get("ct_logged", False),
                            "chain_valid": first_cert.get("chain_valid", False),
                            "signature_algorithm": first_cert.get("signature_algorithm", "") or "",
                        },
                        "asset_type": asset.asset_type or "",
                        "auth_mechanisms": auth_data.get("mechanisms", []) if isinstance(auth_data, dict) else [],
                    }
                    # Build cbom_data from DB
                    from app.models.cbom import CBOMRecord, CBOMComponent
                    cbom_rec = db.query(CBOMRecord).filter(
                        CBOMRecord.asset_id == asset.id,
                        CBOMRecord.scan_id == scan_id,
                    ).first()
                    cbom_data = {"components": []}
                    if cbom_rec:
                        comps = db.query(CBOMComponent).filter(CBOMComponent.cbom_id == cbom_rec.id).all()
                        cbom_data["components"] = [{"name": c.name, "component_type": c.component_type} for c in comps]

                    comp_result = evaluate_compliance(str(asset.id), cbom_data, crypto_data)
                    agility_data_dict = {
                        "tls_version": tls_data.get("negotiated_protocol", "") or asset.tls_version or "",
                        "cert_issuer": first_cert.get("issuer", "") or "",
                        "cdn_detected": asset.cdn_detected,
                        "waf_detected": asset.waf_detected,
                    }
                    ag = compute_agility_score(agility_data_dict)
                    save_compliance_result(scan_id, str(asset.id), comp_result, ag, db)
                    successful_compliance += 1
                except Exception as e:
                    logger.error(f"Compliance failed for {asset.hostname}: {e}", exc_info=True)

            db.commit()
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

            # Update scan summary stats
            from app.models.certificate import Certificate as CertModel
            from app.models.risk import RiskScore as RiskModel
            scan_job.total_assets = len(db_assets)
            cert_count = db.query(CertModel).filter(CertModel.scan_id == scan_id).count()
            scan_job.total_certificates = cert_count
            vuln_count = db.query(RiskModel).filter(
                RiskModel.scan_id == scan_id,
                RiskModel.risk_classification.in_(["quantum_critical", "quantum_vulnerable"])
            ).count()
            scan_job.total_vulnerable = vuln_count

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
