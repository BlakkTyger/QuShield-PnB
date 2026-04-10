"""
Standalone tests for Phase 8 Wave 3 features:
- Scan Events Manager (SSE Stream)
"""
import os
import sys
import asyncio
import uuid

# Ensure project root is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app.services.scan_events import ScanEventManager


# ─── Track A: Deep Scan Streaming Tests ──────────────────────────────────────


async def run_scan_events_test():
    manager = ScanEventManager()
    test_scan_id = str(uuid.uuid4())
    
    # Track results
    results = {
        "received_events": []
    }

    # Use the generator
    generator = manager.event_generator(test_scan_id)

    # Launch background consumer task
    async def consume():
        async for event_str in generator:
            results["received_events"].append(event_str)
            # Break manually when complete
            if '"event_type": "scan_complete"' in event_str:
                break

    consumer_task = asyncio.create_task(consume())

    # Wait for consumer to connect and register queue
    await asyncio.sleep(0.1)

    # Validate active queue
    if test_scan_id in manager._queues and len(manager._queues[test_scan_id]) == 1:
        print("  ✅ Client connected and queue registered")
    else:
        print("  ❌ Client queue registration failed")

    # Broadcast some test events
    await manager.broadcast(test_scan_id, "phase_start", phase=1, progress_pct=0, message="Starting Discovery")
    await manager.broadcast(test_scan_id, "asset_discovered", phase=1, progress_pct=50, data={"hostname": "api.bank.com"})
    await manager.broadcast(test_scan_id, "scan_complete", phase=6, progress_pct=100, message="Scan done")

    # Wait for consumer to finish
    await consumer_task
    
    # Verify received events
    events = results["received_events"]
    if len(events) == 3:
        print(f"  ✅ Received all 3 events successfully")
    else:
        print(f"  ❌ Expected 3 events, got {len(events)}")
        
    for ev in events:
        if not ev.startswith("event: "):
            print(f"  ❌ Invalid SSE format: {ev[:20]}")
            return
            
    if "event: phase_start" in events[0] and "event: scan_complete" in events[-1]:
        print("  ✅ SSE payloads formatted correctly")
        
    import json
    data_str = events[1].split("data: ")[1].strip()
    data = json.loads(data_str)
    
    if data["event_type"] == "asset_discovered" and data["data"]["hostname"] == "api.bank.com":
        print("  ✅ Event contents correct")


def test_sse_manager_end_to_end():
    """Run async test in sync wrapper."""
    asyncio.run(run_scan_events_test())


# ─── Runner ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        ("ScanEventManager (SSE) e2e", test_sse_manager_end_to_end),
    ]

    print(f"\n{'='*60}")
    print(f"Phase 8 Wave 3 — Standalone Tests ({len(tests)} tests)")
    print(f"{'='*60}")

    passed = 0
    failed = 0
    for name, test_fn in tests:
        try:
            print(f"\n🧪 {name}:")
            test_fn()
            passed += 1
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    print(f"\n{'='*60}")
    print(f"Results: {passed} passed, {failed} failed, {len(tests)} total")
    print(f"{'='*60}")

    sys.exit(0 if failed == 0 else 1)
