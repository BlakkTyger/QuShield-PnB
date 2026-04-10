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

    def run_scan(self, scan_id: str, loop=None) -> dict:
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
        TAG = f"[SCAN:{scan_id[:8]}]"
        
        def _elapsed():
            return f"{time.time() - start_time:.1f}s"
        
        def _emit(event_type: str, phase: int = 0, pct: int = 0, msg: str = "", data: dict = None):
            """Helper to emit events to the async SSE manager safely from this sync thread."""
            from app.services.scan_events import scan_events
            import asyncio
            logger.debug(f"{TAG} SSE emit: {event_type} phase={phase} pct={pct} msg={msg}")
            if loop and loop.is_running():
                try:
                    future = asyncio.run_coroutine_threadsafe(
                        scan_events.broadcast(scan_id, event_type, phase, pct, msg, data),
                        loop
                    )
                    # Wait briefly for delivery to confirm it worked
                    future.result(timeout=2.0)
                except Exception as e:
                    logger.warning(f"{TAG} SSE emit failed ({event_type}): {e}")
            else:
                logger.debug(f"{TAG} SSE skipped (no event loop): {event_type}")

        try:
            logger.info(f"{TAG} ═══ DEEP SCAN STARTING ═══ elapsed={_elapsed()}")
            scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if not scan_job:
                logger.error(f"{TAG} Scan job not found in DB!")
                return summary

            _emit("scan_started", phase=1, pct=0, msg="Starting Deep Scan")

            targets = scan_job.targets
            logger.info(f"{TAG} Targets: {targets}")
            all_assets = []

            # ═══════════════════════════════════════════════════════════════
            # PHASE 1: Discovery
            # ═══════════════════════════════════════════════════════════════
            logger.info(f"{TAG} ── PHASE 1: Discovery Engine ── elapsed={_elapsed()}")
            scan_job.current_phase = 1
            scan_job.status = "running"
            db.commit()
            
            _emit("phase_start", phase=1, pct=0, msg="Starting asset discovery")
            
            for i, target in enumerate(targets):
                logger.info(f"{TAG} P1: Discovering target {i+1}/{len(targets)}: {target}")
                t0 = time.time()
                try:
                    discovery_data = run_discovery(target, scan_id)
                    found = discovery_data.get("assets", [])
                    logger.info(f"{TAG} P1: {target} → {len(found)} assets in {time.time()-t0:.1f}s")
                    for a in found[:5]:
                        logger.debug(f"{TAG} P1:   asset: {a.get('hostname')} ip={a.get('ip_v4','?')}")
                    if len(found) > 5:
                        logger.debug(f"{TAG} P1:   ... and {len(found)-5} more")
                    all_assets.extend(found)
                    _emit("asset_discovered", phase=1, pct=int((i+1)/len(targets)*80),
                          msg=f"Discovered {len(found)} assets for {target}",
                          data={"target": target, "count": len(found)})
                except Exception as e:
                    logger.error(f"{TAG} P1: Discovery FAILED for {target}: {e}", exc_info=True)
            
            logger.info(f"{TAG} P1: Total raw assets: {len(all_assets)}")
            
            # Save discovered assets to DB
            logger.info(f"{TAG} P1: Saving assets to database...")
            db_assets = save_discovered_assets(scan_id, all_assets, db)
            logger.info(f"{TAG} P1: Saved {len(db_assets)} assets to DB elapsed={_elapsed()}")
            summary["assets_discovered"] = len(db_assets)
            summary["phases_completed"].append(1)
            
            _emit("phase_complete", phase=1, pct=100,
                  msg=f"Discovered {len(db_assets)} assets",
                  data={"count": len(db_assets), "hostnames": [a.hostname for a in db_assets[:10]]})

            if len(db_assets) == 0:
                logger.warning(f"{TAG} P1: No assets found. Terminating scan.")
                scan_job.status = "completed"
                scan_job.completed_at = datetime.utcnow()
                db.commit()
                summary["status"] = "completed_empty"
                _emit("scan_complete", phase=1, pct=100, msg="Scan complete — no assets found")
                return summary

            # ═══════════════════════════════════════════════════════════════
            # PHASE 2: Crypto Inspection (threaded)
            # ═══════════════════════════════════════════════════════════════
            logger.info(f"{TAG} ── PHASE 2: Crypto Inspection on {len(db_assets)} assets ── elapsed={_elapsed()}")
            scan_job.current_phase = 2
            db.commit()
            _emit("phase_start", phase=2, pct=0, msg=f"Starting crypto inspection on {len(db_assets)} assets")
            
            raw_asset_map = {a.get("hostname"): a for a in all_assets}
            mapped_assets = [(str(a.id), a.hostname) for a in db_assets]
            total_mapped = len(mapped_assets)
            logger.info(f"{TAG} P2: {total_mapped} assets mapped for crypto scan, workers=20")

            # Close main session before thread pool to prevent concurrent access
            db.close()
            db = None
            logger.debug(f"{TAG} P2: Main DB session closed before thread pool")

            def process_crypto(asset_id_str, asset_hostname):
                t0 = time.time()
                try:
                    raw_data = raw_asset_map.get(asset_hostname, {})
                    has_prefetched = raw_data.get("tls_results") is not None
                    fp = inspect_asset(asset_hostname, pre_fetched_tls=raw_data.get("tls_results"))
                    local_db = SessionLocal()
                    try:
                        save_crypto_results(scan_id, asset_id_str, fp, local_db)
                    finally:
                        local_db.close()
                    certs = len(fp.get("certificates", []))
                    logger.debug(f"{TAG} P2: ✓ {asset_hostname} — {certs} certs, prefetched={has_prefetched}, {time.time()-t0:.1f}s")
                    return asset_id_str, fp
                except Exception as e:
                    logger.error(f"{TAG} P2: ✗ {asset_hostname} FAILED ({time.time()-t0:.1f}s): {e}")
                    return asset_id_str, None

            successful_crypto = 0
            failed_crypto = 0
            asset_crypto_map = {}
            processed_crypto = 0
            crypto_t0 = time.time()
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = {executor.submit(process_crypto, a_id, a_host): (a_id, a_host) for a_id, a_host in mapped_assets}
                for future in as_completed(futures):
                    result_id, fp = future.result()
                    processed_crypto += 1
                    pct = int((processed_crypto / total_mapped) * 100) if total_mapped > 0 else 100
                    
                    if fp is not None:
                        successful_crypto += 1
                        asset_crypto_map[result_id] = fp
                    else:
                        failed_crypto += 1
                    
                    if processed_crypto % 10 == 0 or processed_crypto == total_mapped:
                        logger.info(f"{TAG} P2: Progress {processed_crypto}/{total_mapped} "
                                   f"(ok={successful_crypto} fail={failed_crypto}) {time.time()-crypto_t0:.1f}s")
                    _emit("crypto_result", phase=2, pct=pct,
                          msg=f"Scanned {processed_crypto}/{total_mapped}",
                          data={"asset_id": result_id, "success": fp is not None})
            
            logger.info(f"{TAG} P2: Crypto complete — {successful_crypto}/{total_mapped} succeeded, "
                       f"{failed_crypto} failed, {time.time()-crypto_t0:.1f}s elapsed={_elapsed()}")
            summary["crypto_scans"] = successful_crypto
            summary["phases_completed"].append(2)

            # Re-open session after threaded crypto phase
            db = SessionLocal()
            scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            db_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
            logger.debug(f"{TAG} P2: DB session re-opened, {len(db_assets)} assets loaded")

            # Phase 2.5: Incremental scan — compute fingerprints and detect deltas
            logger.info(f"{TAG} ── PHASE 2.5: Incremental Delta Detection ── elapsed={_elapsed()}")
            from app.services.incremental import (
                compute_asset_fingerprint, find_previous_asset,
                is_unchanged, clone_scan_data,
            )
            cloned_count = 0
            assets_to_scan = set()
            for asset in db_assets:
                asset_id_str = str(asset.id)
                fp = asset_crypto_map.get(asset_id_str)
                if fp:
                    fph = compute_asset_fingerprint(asset, fp)
                    asset.fingerprint_hash = fph
                    prev = find_previous_asset(asset.hostname, scan_id, db)
                    if prev and is_unchanged(fph, prev):
                        try:
                            clone_scan_data(prev.id, scan_id, asset.id, db)
                            cloned_count += 1
                            logger.debug(f"{TAG} P2.5: CLONE {asset.hostname} from prev scan")
                        except Exception as e:
                            logger.error(f"{TAG} P2.5: Clone failed for {asset.hostname}: {e}")
                            assets_to_scan.add(asset_id_str)
                    else:
                        assets_to_scan.add(asset_id_str)
                else:
                    assets_to_scan.add(asset_id_str)
            db.commit()
            summary["cloned_assets"] = cloned_count
            summary["rescanned_assets"] = len(assets_to_scan)
            logger.info(f"{TAG} P2.5: Incremental done — {cloned_count} cloned, "
                       f"{len(assets_to_scan)} need full pipeline elapsed={_elapsed()}")
            
            _emit("phase_complete", phase=2, pct=100, msg="Crypto inspection complete")

            # ═══════════════════════════════════════════════════════════════
            # PHASE 3: CBOM Generation (threaded)
            # ═══════════════════════════════════════════════════════════════
            logger.info(f"{TAG} ── PHASE 3: CBOM Generation ── elapsed={_elapsed()}")
            _emit("phase_start", phase=3, pct=0, msg="Building Cryptographic Bills of Material")
            scan_job.current_phase = 3
            db.commit()

            from app.services.cbom_builder import build_cbom, save_cbom_to_db

            successful_cboms = 0
            failed_cboms = 0

            # Extract plain data before closing session
            asset_plain = [(str(a.id), a.hostname) for a in db_assets]
            logger.info(f"{TAG} P3: {len(asset_plain)} assets, {len(assets_to_scan)} need CBOM generation")

            db.close()
            db = None
            logger.debug(f"{TAG} P3: Main DB session closed before thread pool")

            def process_cbom(asset_id_str, asset_hostname):
                if asset_id_str not in assets_to_scan:
                    return None  # Already cloned — skip silently
                fp = asset_crypto_map.get(asset_id_str)
                if not fp:
                    logger.debug(f"{TAG} P3: Skip {asset_hostname} — no crypto fingerprint")
                    return None
                t0 = time.time()
                try:
                    cbom_data = build_cbom(asset_id_str, fp)
                    if cbom_data and "cbom_json" in cbom_data:
                        file_path = save_cbom(scan_id, asset_id_str, cbom_data["cbom_json"])
                        local_db = SessionLocal()
                        try:
                            save_cbom_to_db(scan_id, asset_id_str, cbom_data, file_path, local_db)
                        finally:
                            local_db.close()
                        n_comps = len(cbom_data.get("components", []))
                        logger.debug(f"{TAG} P3: ✓ {asset_hostname} — {n_comps} components, {time.time()-t0:.1f}s")
                        return True
                    else:
                        logger.warning(f"{TAG} P3: ✗ {asset_hostname} — build_cbom returned {type(cbom_data)}, keys={list(cbom_data.keys()) if isinstance(cbom_data, dict) else 'N/A'}")
                        return False
                except Exception as e:
                    logger.error(f"{TAG} P3: ✗ {asset_hostname} FAILED ({time.time()-t0:.1f}s): {e}", exc_info=True)
                    return False

            cbom_t0 = time.time()
            processed_cboms = 0
            with ThreadPoolExecutor(max_workers=10) as executor:
                cbom_futures = {executor.submit(process_cbom, a_id, a_host): (a_id, a_host) for a_id, a_host in asset_plain}
                for f in as_completed(cbom_futures):
                    result = f.result()
                    processed_cboms += 1
                    if result is True:
                        successful_cboms += 1
                    elif result is False:
                        failed_cboms += 1
                    # result is None = skipped (cloned)
                    
                    if processed_cboms % 10 == 0 or processed_cboms == len(asset_plain):
                        logger.info(f"{TAG} P3: Progress {processed_cboms}/{len(asset_plain)} "
                                   f"(ok={successful_cboms} fail={failed_cboms}) {time.time()-cbom_t0:.1f}s")

            logger.info(f"{TAG} P3: CBOM generation complete — {successful_cboms} ok, "
                       f"{failed_cboms} failed, {time.time()-cbom_t0:.1f}s elapsed={_elapsed()}")

            # Re-open session after threaded CBOM phase
            db = SessionLocal()
            scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            db_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
            logger.debug(f"{TAG} P3: DB session re-opened")

            _emit("phase_progress", phase=3, pct=90, msg="Building aggregate CBOM for enterprise")
            logger.info(f"{TAG} P3: Building aggregate CBOM...")
            try:
                agg_data = build_aggregate_cbom(scan_id, db)
                if agg_data:
                    save_cbom(scan_id, "aggregate", agg_data["cbom_json"])
                    logger.info(f"{TAG} P3: Aggregate CBOM saved — "
                               f"{agg_data.get('stats', {}).get('total_components', '?')} components")
                else:
                    logger.warning(f"{TAG} P3: build_aggregate_cbom returned None")
            except Exception as e:
                logger.error(f"{TAG} P3: Aggregate CBOM failed: {e}", exc_info=True)

            summary["cboms_generated"] = successful_cboms
            summary["phases_completed"].append(3)
            
            _emit("phase_complete", phase=3, pct=100, msg=f"Generated {successful_cboms} CBOMs")

            # ═══════════════════════════════════════════════════════════════
            # PHASE 4: Risk Engine
            # ═══════════════════════════════════════════════════════════════
            logger.info(f"{TAG} ── PHASE 4: Risk Assessment ── elapsed={_elapsed()}")
            _emit("phase_start", phase=4, pct=0, msg="Quantifying quantum risk for all assets")
            scan_job.current_phase = 4
            db.commit()

            cloned_ids = {str(a.id) for a in db_assets if str(a.id) not in assets_to_scan}
            logger.info(f"{TAG} P4: Assessing {len(assets_to_scan)} assets (skipping {len(cloned_ids)} cloned)")

            try:
                risk_t0 = time.time()
                results = assess_all_assets(scan_id, db, skip_asset_ids=cloned_ids)
                summary["risk_assessments"] = len(results)
                logger.info(f"{TAG} P4: Risk assessment complete — {len(results)} scores in {time.time()-risk_t0:.1f}s")
            except Exception as e:
                logger.error(f"{TAG} P4: Risk assessment FAILED: {e}", exc_info=True)
            summary["phases_completed"].append(4)
            _emit("phase_complete", phase=4, pct=100, msg="Risk assessment complete")

            # ═══════════════════════════════════════════════════════════════
            # PHASE 5: Compliance Verification & Agility
            # ═══════════════════════════════════════════════════════════════
            logger.info(f"{TAG} ── PHASE 5: Compliance & Agility ── elapsed={_elapsed()}")
            _emit("phase_start", phase=5, pct=0, msg="Running compliance checks")
            scan_job.current_phase = 5
            db.commit()
            
            successful_compliance = 0
            failed_compliance = 0
            from app.models.cbom import CBOMRecord, CBOMComponent
            for idx, asset in enumerate(db_assets):
                if str(asset.id) in cloned_ids:
                    continue
                try:
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
                    failed_compliance += 1
                    logger.error(f"{TAG} P5: Compliance FAILED for {asset.hostname}: {e}")

            db.commit()
            summary["compliance_scores_computed"] = successful_compliance
            summary["phases_completed"].append(5)
            logger.info(f"{TAG} P5: Compliance complete — {successful_compliance} ok, "
                       f"{failed_compliance} failed elapsed={_elapsed()}")
            _emit("phase_complete", phase=5, pct=100, msg="Compliance assessment complete")

            # ═══════════════════════════════════════════════════════════════
            # PHASE 6: Topology Graph
            # ═══════════════════════════════════════════════════════════════
            logger.info(f"{TAG} ── PHASE 6: Topology Graph ── elapsed={_elapsed()}")
            _emit("phase_start", phase=6, pct=0, msg="Building topology graph")
            scan_job.current_phase = 6
            db.commit()
            
            try:
                graph_t0 = time.time()
                graph_data = build_topology_graph(scan_id, db)
                summary["graph_nodes"] = graph_data["node_count"]
                summary["graph_edges"] = graph_data["edge_count"]
                summary["phases_completed"].append(6)
                logger.info(f"{TAG} P6: Graph built — {graph_data['node_count']} nodes, "
                           f"{graph_data['edge_count']} edges in {time.time()-graph_t0:.1f}s")
            except Exception as e:
                logger.error(f"{TAG} P6: Graph topology FAILED: {e}", exc_info=True)

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
            logger.info(f"{TAG} Final stats: {len(db_assets)} assets, {cert_count} certs, {vuln_count} vulnerable")

            # Mark scan complete
            scan_job.status = "completed"
            scan_job.completed_at = datetime.utcnow()
            db.commit()
            
            summary["status"] = "completed"
            summary["duration_seconds"] = round(time.time() - start_time, 2)
            logger.info(f"{TAG} ═══ DEEP SCAN COMPLETED ═══ {summary['duration_seconds']}s "
                       f"phases={summary['phases_completed']}")
            
            _emit("scan_complete", phase=6, pct=100, msg="Deep scan successfully completed!",
                  data={"duration": summary["duration_seconds"], "assets": len(db_assets)})
            return summary

        except Exception as e:
            logger.error(f"{TAG} ═══ ORCHESTRATOR EXCEPTION ═══ {e}", exc_info=True)
            try:
                db_err = SessionLocal()
                sj = db_err.query(ScanJob).filter(ScanJob.id == scan_id).first()
                if sj:
                    sj.status = "failed"
                    sj.error_message = str(e)[:500]
                    db_err.commit()
                db_err.close()
            except Exception as dbe:
                logger.error(f"{TAG} Failed to update scan job error status: {dbe}")
                
            _emit("scan_failed", phase=0, pct=0, msg=f"Scan failed: {str(e)}")
            return summary
        finally:
            if db is not None:
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
