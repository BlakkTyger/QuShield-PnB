#!/usr/bin/env python3
"""
Standalone Deep Scan + SSE Test — validates that SSE events are emitted
during a deep scan, simulating the same async event loop that FastAPI provides.

This test:
1. Creates an asyncio event loop (like FastAPI/uvicorn does)
2. Registers an SSE listener on the scan_events manager
3. Runs the orchestrator in a background thread (like the API does)
4. Collects and validates all SSE events in real-time

Usage:
    cd backend
    python tests/standalone/test_deep_scan_sse.py [domain]
"""

import sys
import os
import time
import json
import asyncio
import threading
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.core.database import SessionLocal
from app.models.auth import ScanCache
from app.services.orchestrator import ScanOrchestrator
from app.services.scan_events import scan_events

# ─── Logging Setup ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-7s] %(name)-30s %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("tests/standalone/deep_scan_sse_debug.log", mode="w"),
    ],
)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("app.services.crypto_inspector").setLevel(logging.WARNING)
logging.getLogger("app.services.discovery_runner").setLevel(logging.WARNING)
logging.getLogger("app.services.cbom_builder").setLevel(logging.WARNING)
logging.getLogger("app.services.risk_engine").setLevel(logging.WARNING)
logging.getLogger("app.services.compliance").setLevel(logging.WARNING)
logging.getLogger("app.services.graph_builder").setLevel(logging.WARNING)
logging.getLogger("app.services.incremental").setLevel(logging.WARNING)

logger = logging.getLogger("test_sse")

DOMAIN = sys.argv[1] if len(sys.argv) > 1 else "pnb.bank.in"


async def sse_listener(scan_id: str, collected_events: list, stop_event: asyncio.Event):
    """Async task that listens for SSE events on the scan_events manager."""
    logger.info(f"[SSE-LISTENER] Subscribing to scan {scan_id[:8]}...")
    queue = await scan_events.add_client(scan_id)
    logger.info(f"[SSE-LISTENER] Subscribed. Waiting for events...")
    
    try:
        while not stop_event.is_set():
            try:
                event = await asyncio.wait_for(queue.get(), timeout=1.0)
                collected_events.append(event)
                etype = event.get("event_type", "?")
                phase = event.get("phase", "?")
                pct = event.get("progress_pct", "?")
                msg = event.get("message", "")[:80]
                logger.info(f"[SSE-EVENT] {etype:20s} phase={phase} pct={pct:>3} | {msg}")
                
                if etype in ("scan_complete", "scan_failed"):
                    logger.info(f"[SSE-LISTENER] Terminal event received: {etype}")
                    break
            except asyncio.TimeoutError:
                continue
    finally:
        await scan_events.remove_client(scan_id, queue)
        logger.info(f"[SSE-LISTENER] Unsubscribed from scan {scan_id[:8]}")


async def main_async():
    logger.info("=" * 70)
    logger.info(f"  STANDALONE DEEP SCAN + SSE TEST — {DOMAIN}")
    logger.info("=" * 70)

    orch = ScanOrchestrator()

    # Step 1: Create scan job
    logger.info("Step 1: Creating scan job...")
    scan_id = orch.start_scan([DOMAIN])
    logger.info(f"Scan job created: {scan_id}")

    # Step 2: Set up SSE listener
    collected_events = []
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()

    # Start SSE listener as an async task
    listener_task = asyncio.create_task(
        sse_listener(scan_id, collected_events, stop_event)
    )

    # Give the listener a moment to subscribe
    await asyncio.sleep(0.2)

    # Step 3: Run scan in background thread (same as FastAPI does)
    logger.info("Step 3: Starting scan in background thread...")
    scan_result = {}
    
    def _run_scan():
        try:
            result = orch.run_scan(scan_id, loop=loop)
            scan_result.update(result)
        except Exception as e:
            logger.error(f"Scan thread error: {e}", exc_info=True)
            scan_result["error"] = str(e)

    scan_thread = threading.Thread(target=_run_scan, daemon=True, name=f"scan-{scan_id[:8]}")
    scan_thread.start()
    logger.info(f"Scan thread started: {scan_thread.name}")

    # Step 4: Wait for scan to complete
    logger.info("Step 4: Waiting for scan to complete...")
    while scan_thread.is_alive():
        await asyncio.sleep(5)
        # Log progress
        phase_events = [e for e in collected_events if e.get("event_type") in ("phase_start", "phase_complete")]
        crypto_events = [e for e in collected_events if e.get("event_type") == "crypto_result"]
        logger.info(f"  ... waiting: {len(collected_events)} events total, "
                    f"{len(phase_events)} phase events, {len(crypto_events)} crypto events")

    scan_thread.join(timeout=5)
    
    # Give the listener a moment to receive the final event
    await asyncio.sleep(2)
    stop_event.set()
    
    try:
        await asyncio.wait_for(listener_task, timeout=5)
    except asyncio.TimeoutError:
        listener_task.cancel()

    # Step 5: Analyze SSE events
    logger.info("\n" + "=" * 70)
    logger.info(f"  SSE EVENT ANALYSIS")
    logger.info("=" * 70)
    logger.info(f"Total events received: {len(collected_events)}")
    
    if not collected_events:
        logger.error("❌ NO SSE EVENTS RECEIVED — SSE broadcasting is broken!")
        return

    # Event type distribution
    type_counts = {}
    for e in collected_events:
        et = e.get("event_type", "unknown")
        type_counts[et] = type_counts.get(et, 0) + 1
    logger.info(f"\nEvent type distribution:")
    for et, count in sorted(type_counts.items()):
        logger.info(f"  {et:25s} : {count}")

    # Phase progression
    phases_seen = []
    for e in collected_events:
        p = e.get("phase", 0)
        if p and (not phases_seen or phases_seen[-1] != p):
            phases_seen.append(p)
    logger.info(f"\nPhase progression: {phases_seen}")

    # First and last event
    first = collected_events[0]
    last = collected_events[-1]
    logger.info(f"\nFirst event: {first.get('event_type')} phase={first.get('phase')}")
    logger.info(f"Last event:  {last.get('event_type')} phase={last.get('phase')}")

    # Validate structure
    sample = collected_events[0]
    required_keys = ["event_type", "scan_id", "phase", "progress_pct", "message", "timestamp"]
    missing = [k for k in required_keys if k not in sample]
    if missing:
        logger.warning(f"❌ Event missing required keys: {missing}")
    else:
        logger.info(f"✅ All required keys present in events")

    # Check monotonic phases
    phase_values = [e.get("phase", 0) for e in collected_events]
    is_monotonic = all(phase_values[i] <= phase_values[i+1] for i in range(len(phase_values)-1))
    if is_monotonic:
        logger.info(f"✅ Phases are monotonically non-decreasing")
    else:
        logger.warning(f"❌ Phases are NOT monotonically non-decreasing")

    # Check terminal event
    if last.get("event_type") in ("scan_complete", "scan_failed"):
        logger.info(f"✅ Stream terminated with {last.get('event_type')}")
    else:
        logger.warning(f"❌ Stream did NOT terminate with scan_complete/scan_failed (got {last.get('event_type')})")

    # Check progress percentages
    pcts = [e.get("progress_pct", 0) for e in collected_events]
    if all(0 <= p <= 100 for p in pcts):
        logger.info(f"✅ All progress_pct values in 0-100 range")
    else:
        logger.warning(f"❌ Some progress_pct out of range: min={min(pcts)} max={max(pcts)}")

    # Scan result
    logger.info(f"\nScan result status: {scan_result.get('status', 'UNKNOWN')}")
    logger.info(f"Scan result phases: {scan_result.get('phases_completed', [])}")

    # Final verdict
    all_ok = (
        len(collected_events) > 10
        and scan_result.get("status") == "completed"
        and last.get("event_type") == "scan_complete"
        and not missing
        and is_monotonic
    )
    
    logger.info("\n" + "=" * 70)
    if all_ok:
        logger.info("  ✅ DEEP SCAN + SSE TEST: ALL CHECKS PASSED")
    else:
        logger.warning("  ❌ DEEP SCAN + SSE TEST: SOME CHECKS FAILED")
    logger.info("=" * 70)


def main():
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
