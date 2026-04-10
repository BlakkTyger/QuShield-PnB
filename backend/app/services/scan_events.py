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

    async def add_client(self, scan_id: str) -> asyncio.Queue:
        """Add a new client listener for a specific scan."""
        queue = asyncio.Queue()
        async with self._lock:
            if scan_id not in self._queues:
                self._queues[scan_id] = set()
            self._queues[scan_id].add(queue)
        
        logger.info(f"SSE client connected to scan {scan_id}")
        return queue

    async def remove_client(self, scan_id: str, queue: asyncio.Queue) -> None:
        """Remove a client listener."""
        async with self._lock:
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
                return  # No active listeners, safe to ignore

            # Send to all connected queues for this scan
            queues = self._queues[scan_id].copy()

        for queue in queues:
            await queue.put(event_payload)
            
        logger.debug(
            f"Broadcast SSE event for {scan_id}: {event_type} "
            f"(phase {phase}, {progress_pct}%) - {message}"
        )

    async def event_generator(self, scan_id: str) -> AsyncGenerator[str, None]:
        """
        Async generator for FastAPI StreamingResponse.
        Yields Server-Sent Events formatted strings.
        """
        queue = await self.add_client(scan_id)
        try:
            while True:
                # Wait for next event
                event_dict = await queue.get()
                
                # Format as SSE standard string (data: <json>\n\n)
                json_str = json.dumps(event_dict)
                yield f"event: {event_dict['event_type']}\ndata: {json_str}\n\n"
                
                # Close string if scan is complete or failed
                if event_dict["event_type"] in ("scan_complete", "scan_failed"):
                    break
        except asyncio.CancelledError:
            # Client disconnected
            pass
        finally:
            await self.remove_client(scan_id, queue)


# Global singleton instance to be used across the app
scan_events = ScanEventManager()
