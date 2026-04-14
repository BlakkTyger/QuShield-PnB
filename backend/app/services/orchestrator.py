import logging
import time
import re
import socket
import json
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.scan import ScanJob, ScanStatus
from app.models.asset import Asset
from app.services.asset_manager import create_scan_job, save_discovered_assets
from app.services.discovery_runner import run_discovery
from app.services.crypto_inspector import inspect_asset, save_crypto_results
from app.services.cbom_builder import save_cbom, build_aggregate_cbom
from app.services.risk_engine import assess_all_assets

from app.services.compliance import evaluate_compliance, compute_agility_score, save_compliance_result
from app.services.graph_builder import build_topology_graph
from app.services.csv_enrichment import supplement_discovery, enrich_fingerprint, enrich_asset_db_row, enrich_certificate_db_rows, enrich_risk_score

from app.core.logging import get_logger
from app.core.utils import clean_domain, is_valid_domain
from app.config import PROJECT_ROOT
logger = get_logger("orchestrator")

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,6}$"
)

def validate_targets(targets: list[str]) -> list[str]:
    valid_targets = []
    for tgt in targets:
        clean_tgt = clean_domain(tgt)

        if not is_valid_domain(clean_tgt):
            logger.warning(f"Invalid target (format): {tgt} (cleaned: {clean_tgt})")
            continue
        resolved = False
        for attempt in range(3):
            try:
                socket.gethostbyname(clean_tgt)
                resolved = True
                break
            except socket.gaierror:
                if attempt < 2:
                    time.sleep(1)
        if resolved:
            valid_targets.append(clean_tgt)
        else:
            logger.warning(f"Invalid target (DNS resolution failed for {clean_tgt}): {tgt}")
    return valid_targets

class ScanOrchestrator:
    def __init__(self):
        pass

    def start_scan(self, targets: list[str], config: dict = None, user_id=None, scan_type: str = "deep") -> str:
        valid_targets = validate_targets(targets)
        if not valid_targets:
            raise ValueError("No valid targets provided that pass DNS resolution.")

        db: Session = SessionLocal()
        try:
            scan_job = create_scan_job(valid_targets, db, user_id=user_id, scan_type=scan_type)
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
            logger.debug(f"{TAG} SSE emit: {event_type} phase={phase} pct={pct} msg={msg}")
            if loop and loop.is_running():
                try:
                    scan_events.broadcast_sync(
                        scan_id, event_type, phase, pct, msg, data, loop=loop
                    )
                except Exception as e:
                    logger.warning(f"{TAG} SSE emit failed ({event_type}): {e}")
            else:
                logger.debug(f"{TAG} SSE skipped (no event loop): {event_type}")

        try:
            import uuid
            logger.info(f"{TAG} ═══ DEEP SCAN STARTING ═══ elapsed={_elapsed()}")
            scan_job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_id)).first()
            if not scan_job:
                logger.error(f"{TAG} Scan job not found in DB!")
                return summary

            def _check_cancelled():
                """Check if the scan was cancelled in the DB and return True if so."""
                import uuid
                job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_id)).first()
                if job and job.status == ScanStatus.CANCELLED:
                    logger.info(f"{TAG} Scan {scan_id} detected as [CANCELLED]. Aborting thread.")
                    _emit("scan_cancelled", phase=job.current_phase, pct=0, msg="Scan cancelled by user")
                    return True
                return False

            if _check_cancelled():
                return summary

            _emit("scan_started", phase=1, pct=0, msg="Starting Deep Scan")

            targets = scan_job.targets
            logger.info(f"{TAG} Targets: {targets}")
            all_assets = []

            # ═══════════════════════════════════════════════════════════════
            # PHASE 1: Discovery
            # ═══════════════════════════════════════════════════════════════
            logger.info(f"{TAG} ── PHASE 1: Discovery Engine ── elapsed={_elapsed()}")
            if _check_cancelled(): return summary
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
                          msg=f"Scanning {target}...",
                          data={"target": target})
                except Exception as e:
                    logger.error(f"{TAG} P1: Discovery FAILED for {target}: {e}", exc_info=True)
            
            logger.info(f"{TAG} P1: Total raw assets from Go binary: {len(all_assets)}")

            # ── Supplemental DNS brute-force (runs if Go binary under-discovers) ──
            if len(all_assets) < 10 * len(targets):
                logger.info(f"{TAG} P1: Supplementing with DNS brute-force discovery...")
                from app.services.shallow_scanner import discover_subdomains, resolve_subdomains_parallel
                existing_hostnames = {a.get("hostname", "").lower() for a in all_assets}
                for tgt in targets:
                    try:
                        _emit("phase_progress", phase=1, pct=50,
                              msg=f"Running supplemental DNS discovery for {tgt}")
                        brute_subs = discover_subdomains(tgt)
                        brute_live = resolve_subdomains_parallel(brute_subs)
                        added = 0
                        for asset in brute_live:
                            hn = asset.get("hostname", "").lower()
                            if hn and hn not in existing_hostnames:
                                all_assets.append({
                                    "hostname": hn,
                                    "ip_v4": asset.get("ip", ""),
                                    "discovery_methods": ["dns_brute"],
                                    "confidence_score": 0.5,
                                })
                                existing_hostnames.add(hn)
                                added += 1
                        logger.info(f"{TAG} P1: Brute-force added {added} new assets for {tgt}")
                    except Exception as e:
                        logger.warning(f"{TAG} P1: Brute-force supplement failed for {tgt}: {e}")

            logger.info(f"{TAG} P1: Total raw assets: {len(all_assets)}")

            # ── CSV baseline supplement (fill in any hostnames the live scan missed) ──
            for tgt in targets:
                supplement_discovery(all_assets, tgt)
            logger.info(f"{TAG} P1: Total assets after CSV supplement: {len(all_assets)}")

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
            if _check_cancelled(): return summary
            scan_job.current_phase = 2
            db.commit()
            _emit("phase_start", phase=2, pct=0, msg=f"Starting crypto inspection on {len(db_assets)} assets")
            
            raw_asset_map = {a.get("hostname"): a for a in all_assets}
            mapped_assets = [(str(a.id), a.hostname) for a in db_assets]
            total_mapped = len(mapped_assets)
            logger.info(f"{TAG} P2: {total_mapped} assets mapped for crypto scan, workers=20")
            trace_file = PROJECT_ROOT / "data" / "crypto_traces" / f"{scan_id}.txt"
            trace_file.parent.mkdir(parents=True, exist_ok=True)
            trace_lock = threading.Lock()
            subdomains_dir = PROJECT_ROOT / "data" / "subdomains"
            subdomains_dir.mkdir(parents=True, exist_ok=True)

            def _safe_subdomain_filename(hostname: str, asset_id_str: str) -> Path:
                safe_host = re.sub(r"[^a-zA-Z0-9._-]", "_", hostname or "unknown-host")
                return subdomains_dir / f"{safe_host}.json"

            def _append_subdomain_block(asset_id_str: str, asset_hostname: str, section: str, payload: dict):
                path = _safe_subdomain_filename(asset_hostname, asset_id_str)
                with trace_lock:
                    existing = {
                        "hostname": asset_hostname,
                        "asset_id": asset_id_str,
                        "scan_id": scan_id,
                        "entries": [],
                    }
                    if path.exists():
                        try:
                            existing = json.loads(path.read_text(encoding="utf-8"))
                            if not isinstance(existing, dict):
                                existing = {
                                    "hostname": asset_hostname,
                                    "asset_id": asset_id_str,
                                    "scan_id": scan_id,
                                    "entries": [],
                                }
                        except Exception:
                            existing = {
                                "hostname": asset_hostname,
                                "asset_id": asset_id_str,
                                "scan_id": scan_id,
                                "entries": [],
                            }
                    existing.setdefault("entries", [])
                    existing["entries"].append(
                        {
                            "timestamp_utc": datetime.utcnow().isoformat() + "Z",
                            "section": section,
                            "payload": payload,
                        }
                    )
                    path.write_text(json.dumps(existing, default=str, indent=2), encoding="utf-8")

            def _write_crypto_trace(asset_id_str: str, asset_hostname: str, raw_data: dict, fingerprint: dict | None, error: str | None = None):
                """Persist per-asset raw + parsed crypto inspection evidence for debugging/audit."""
                fp = fingerprint or {}
                tls = fp.get("tls") or {}
                pqc = fp.get("pqc") or {}
                pqcscan = pqc.get("pqcscan") or {}
                record = {
                    "scan_id": scan_id,
                    "asset_id": asset_id_str,
                    "hostname": asset_hostname,
                    "timestamp_utc": datetime.utcnow().isoformat() + "Z",
                    "raw_discovery_input": raw_data or {},
                    "raw_tls_prefetched": (raw_data or {}).get("tls_results"),
                    "parsed_crypto_fingerprint": fingerprint,
                    "engines": {
                        "tls_engine": tls.get("engine"),
                        "pqc_detection_method": pqc.get("detection_method"),
                        "pqcscan_performed": pqcscan.get("performed"),
                        "asset_type_classifier": "classify_asset_type",
                    },
                    "error": error,
                }
                with trace_lock:
                    with trace_file.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(record, default=str))
                        f.write("\n")
                subdomain_crypto_payload = {
                    "scan_id": scan_id,
                    "asset_id": asset_id_str,
                    "hostname": asset_hostname,
                    "phase": "phase_2_crypto_inspection",
                    "raw_input_initial_discovery": raw_data or {},
                    "raw_engine_outputs": {
                        "openssl_raw_text": tls.get("raw_openssl_output"),
                        "pqcscan_raw_json": pqcscan.get("raw_output_json"),
                        "pqcscan_command": pqcscan.get("command"),
                    },
                    "parsed_output": fingerprint,
                    "db_payload_preview": {
                        "asset_update": {
                            "tls_version": tls.get("negotiated_protocol"),
                            "hosting_provider": (fp.get("infrastructure") or {}).get("hosting_provider"),
                            "cdn_detected": (fp.get("infrastructure") or {}).get("cdn_detected"),
                            "waf_detected": (fp.get("infrastructure") or {}).get("waf_detected"),
                            "web_server": (fp.get("infrastructure") or {}).get("server_header"),
                            "auth_mechanisms": ",".join((fp.get("auth") or {}).get("auth_mechanisms", [])),
                            "jwt_algorithm": (fp.get("auth") or {}).get("jwt_algorithm"),
                            "asset_type": fp.get("asset_type"),
                        },
                        "certificate_count_to_db": len(fp.get("certificates", [])),
                    },
                    "frontend_payload_preview": {
                        "tls": fp.get("tls"),
                        "pqc": fp.get("pqc"),
                        "quantum_summary": fp.get("quantum_summary"),
                    },
                    "error": error,
                }
                _append_subdomain_block(asset_id_str, asset_hostname, "CRYPTO_TRACE", subdomain_crypto_payload)

            # Close main session before thread pool to prevent concurrent access
            db.close()
            db = None
            logger.debug(f"{TAG} P2: Main DB session closed before thread pool")

            def process_crypto(asset_id_str, asset_hostname):
                t0 = time.time()
                raw_data = raw_asset_map.get(asset_hostname, {})
                try:
                    has_prefetched = raw_data.get("tls_results") is not None
                    fp = inspect_asset(
                        asset_hostname,
                        pre_fetched_tls=raw_data.get("tls_results"),
                        discovered_ip=raw_data.get("ip_v4"),
                    )
                    local_db = SessionLocal()
                    try:
                        save_crypto_results(scan_id, asset_id_str, fp, local_db)
                    finally:
                        local_db.close()
                    _write_crypto_trace(asset_id_str, asset_hostname, raw_data, fp)
                    certs = len(fp.get("certificates", []))
                    logger.debug(f"{TAG} P2: ✓ {asset_hostname} — {certs} certs, prefetched={has_prefetched}, {time.time()-t0:.1f}s")
                    return asset_id_str, fp
                except Exception as e:
                    _write_crypto_trace(asset_id_str, asset_hostname, raw_data, None, error=str(e))
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
            logger.info(f"{TAG} P2: Crypto raw trace written to {trace_file}")
            summary["crypto_scans"] = successful_crypto
            summary["phases_completed"].append(2)

            # Re-open session after threaded crypto phase
            db = SessionLocal()
            scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            db_assets = db.query(Asset).filter(Asset.scan_id == scan_id).all()
            logger.debug(f"{TAG} P2: DB session re-opened, {len(db_assets)} assets loaded")

            # ── CSV enrichment: merge stronger baseline data into fingerprints & assets ──
            from app.models.certificate import Certificate as CertModelEnrich
            csv_enriched = 0
            for asset in db_assets:
                aid = str(asset.id)
                fp = asset_crypto_map.get(aid)
                if fp:
                    enrich_fingerprint(asset.hostname, fp)
                    csv_enriched += 1
                enrich_asset_db_row(asset)
                cert_rows = db.query(CertModelEnrich).filter(CertModelEnrich.asset_id == asset.id).all()
                enrich_certificate_db_rows(asset.hostname, cert_rows)
            db.commit()
            logger.info(f"{TAG} P2: CSV enrichment applied to {csv_enriched} fingerprints")

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
            if _check_cancelled(): return summary
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
                        _append_subdomain_block(
                            asset_id_str,
                            asset_hostname,
                            "TRACE_SECTION_BREAK",
                            {
                                "separator": "----- END CRYPTO TRACE ----- BEGIN CBOM/PQCSCAN TRACE -----",
                                "scan_id": scan_id,
                                "asset_id": asset_id_str,
                                "hostname": asset_hostname,
                            },
                        )
                        _append_subdomain_block(
                            asset_id_str,
                            asset_hostname,
                            "CBOM_AND_PQCSCAN_TRACE",
                            {
                                "scan_id": scan_id,
                                "asset_id": asset_id_str,
                                "hostname": asset_hostname,
                                "raw_cbom_builder_output": cbom_data,
                                "raw_cbom_json_written": cbom_data.get("cbom_json"),
                                "cbom_file_path": file_path,
                                "db_payload_preview": {
                                    "cbom_record": {
                                        "scan_id": scan_id,
                                        "asset_id": asset_id_str,
                                        "total_components": (cbom_data.get("stats") or {}).get("total_components"),
                                        "vulnerable_components": (cbom_data.get("stats") or {}).get("vulnerable_count"),
                                        "quantum_ready_pct": (cbom_data.get("stats") or {}).get("quantum_ready_pct"),
                                        "file_path": file_path,
                                    },
                                    "cbom_components": cbom_data.get("components", []),
                                },
                                "frontend_payload_preview": {
                                    "components": cbom_data.get("components", []),
                                    "stats": cbom_data.get("stats", {}),
                                },
                                "raw_pqcscan_json_from_phase2": ((fp.get("pqc") or {}).get("pqcscan") or {}).get("raw_output_json"),
                            },
                        )
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
            if _check_cancelled(): return summary
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

            # ── CSV risk enrichment: adopt curated risk scores / classifications ──
            from app.models.risk import RiskScore as RiskModel
            risk_rows = db.query(RiskModel).filter(RiskModel.scan_id == scan_id).all()
            asset_hostname_map = {str(a.id): a.hostname for a in db_assets}
            for rs in risk_rows:
                hn = asset_hostname_map.get(str(rs.asset_id))
                if hn:
                    enrich_risk_score(hn, rs)
            db.commit()
            logger.info(f"{TAG} P4: CSV risk enrichment applied to {len(risk_rows)} scores")

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
                    pqc_fp = fp.get("pqc") or {}
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
                            "signature_algorithm_oid": first_cert.get("signature_algorithm_oid", "") or "",
                        },
                        "pqc_tls": {
                            "hybrid_algorithms": pqc_fp.get("hybrid_tls_algorithms") or [],
                            "pure_pqc_algorithms": pqc_fp.get("pure_pqc_tls_algorithms") or [],
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

            # Intentionally no auto-delete of older ScanJobs: the UI scan history lists
            # past runs by scan_id; pruning them broke FK-safe deletes and removed history.
            # To remove a scan explicitly, use a dedicated admin path + scan_cleanup.purge_scan_dependencies.

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
            import uuid
            scan_job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_id)).first()
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
