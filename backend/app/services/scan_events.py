"""
Scan Events Manager — Real-time progress streaming via Server-Sent Events (SSE).

Provides a centralized queue-based event bus for broadcasting deep scan progress
to connected frontend clients. Designed for FastAPI's StreamingResponse.
"""
import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Set, Any, AsyncGenerator

from app.core.logging import get_logger

logger = get_logger("scan_events")


class ScanEventManager:
    """
    Manages active SSE connections and routes scan progress events to the correct
    subscribers based on scan_id.
    """
    def __init__(self):
        # Maps scan_id -> set of active asyncio.Queue items
        self._queues: Dict[str, Set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()
        self._thread_lock = __import__('threading').Lock()  # For thread-safe access from sync code

    async def add_client(self, scan_id: str) -> asyncio.Queue:
        """Add a new client listener for a specific scan."""
        queue = asyncio.Queue()
        async with self._lock:
            with self._thread_lock:
                if scan_id not in self._queues:
                    self._queues[scan_id] = set()
                self._queues[scan_id].add(queue)
        
        logger.info(f"SSE client connected to scan {scan_id}")
        return queue

    async def remove_client(self, scan_id: str, queue: asyncio.Queue) -> None:
        """Remove a client listener."""
        async with self._lock:
            with self._thread_lock:
                if scan_id in self._queues and queue in self._queues[scan_id]:
                    self._queues[scan_id].remove(queue)
                    if not self._queues[scan_id]:
                        del self._queues[scan_id]
        logger.info(f"SSE client disconnected from scan {scan_id}")

    async def broadcast(
        self,
        scan_id: str,
        event_type: str,
        phase: int = 0,
        progress_pct: int = 0,
        message: str = "",
        data: dict = None,
    ) -> None:
        """
        Broadcast an event to all connected clients for a specific scan.
        
        Args:
            scan_id: The scan UUID string
            event_type: e.g., 'phase_start', 'asset_discovered', 'crypto_result', 'complete'
            phase: Current scan phase (1-6)
            progress_pct: Current progress percentage (0-100)
            message: Human-readable status update
            data: Arbitrary JSON-serializable payload
        """
        if data is None:
            data = {}

        event_payload = {
            "event_type": event_type,
            "scan_id": scan_id,
            "phase": phase,
            "progress_pct": progress_pct,
            "message": message,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        async with self._lock:
            if scan_id not in self._queues:
                logger.debug(f"Broadcast: no listeners for {scan_id} ({event_type})")
                return  # No active listeners, safe to ignore

            # Send to all connected queues for this scan
            queues = self._queues[scan_id].copy()
            n_queues = len(queues)

        for queue in queues:
            await queue.put(event_payload)
            
        logger.info(
            f"Broadcast → {n_queues} queue(s) for {scan_id[:8]}: {event_type} "
            f"(phase {phase}, {progress_pct}%) - {message}"
        )

    def broadcast_sync(
        self,
        scan_id: str,
        event_type: str,
        phase: int = 0,
        progress_pct: int = 0,
        message: str = "",
        data: dict = None,
        loop: Any = None,
    ) -> None:
        """
        Thread-safe broadcast — called from background scan threads.
        Uses loop.call_soon_threadsafe to put events directly into asyncio.Queues
        without needing to schedule a coroutine (avoids run_coroutine_threadsafe deadlocks).
        """
        if data is None:
            data = {}

        event_payload = {
            "event_type": event_type,
            "scan_id": scan_id,
            "phase": phase,
            "progress_pct": progress_pct,
            "message": message,
            "data": data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        with self._thread_lock:
            if scan_id not in self._queues:
                logger.debug(f"broadcast_sync: no listeners for {scan_id[:8]} ({event_type})")
                return
            queues = list(self._queues[scan_id])

        if not loop:
            logger.debug(f"broadcast_sync: no loop for {scan_id[:8]} ({event_type})")
            return

        for queue in queues:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, event_payload)
            except Exception as e:
                logger.warning(f"broadcast_sync: put failed for {scan_id[:8]}: {e}")

        logger.info(
            f"broadcast_sync → {len(queues)} queue(s) for {scan_id[:8]}: {event_type} "
            f"(phase {phase}, {progress_pct}%)"
        )

    async def event_generator(self, scan_id: str) -> AsyncGenerator[str, None]:
        """
        Async generator for FastAPI StreamingResponse.
        Yields Server-Sent Events formatted strings.
        """
        queue = await self.add_client(scan_id)
        logger.info(f"SSE generator started for scan {scan_id}")
        try:
            # Send initial keepalive comment to flush HTTP response headers
            yield ": connected\n\n"

            while True:
                try:
                    # Wait up to 15s for next event, send keepalive if timeout
                    event_dict = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # Send SSE comment as keepalive to prevent connection timeout
                    yield ": keepalive\n\n"
                    continue
                
                # Format as SSE standard string (data: <json>\n\n)
                json_str = json.dumps(event_dict)
                sse_str = f"event: {event_dict['event_type']}\ndata: {json_str}\n\n"
                logger.debug(f"SSE yield for {scan_id}: {event_dict['event_type']}")
                yield sse_str
                # yield f"data: {json_str}\n\n"

                
                # Close stream if scan is complete or failed
                if event_dict["event_type"] in ("scan_complete", "scan_failed"):
                    logger.info(f"SSE generator ending for scan {scan_id}: {event_dict['event_type']}")
                    break
        except asyncio.CancelledError:
            logger.info(f"SSE generator cancelled for scan {scan_id}")
        finally:
            await self.remove_client(scan_id, queue)


# Global singleton instance to be used across the app
scan_events = ScanEventManager()
