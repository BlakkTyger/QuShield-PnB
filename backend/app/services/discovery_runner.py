"""
Discovery Runner — Python wrapper for the Go Discovery Engine binary.

Calls the Go binary via subprocess and returns structured results.
"""
import json
import os
import subprocess
import time
import uuid
import datetime
from pathlib import Path
from typing import Optional

from app.config import settings, PROJECT_ROOT
from app.core.logging import get_logger
from app.core.timing import timed

logger = get_logger("discovery_runner")

# Path to the Go binary
DISCOVERY_BINARY = PROJECT_ROOT / "discovery" / "bin" / "discovery-engine"


@timed
def run_discovery(
    domain: str,
    scan_id: Optional[str] = None,
    timeout_seconds: int = 400,
    port_mode: str = "top20",
) -> dict:
    """
    Run the Go Discovery Engine against a domain.

    Args:
        domain: Target domain (e.g., "example.com")
        scan_id: Scan ID for tracking (auto-generated if not provided)
        timeout_seconds: Max time to wait for discovery
        port_mode: "top20" or "top100"

    Returns:
        Discovery result dict with assets, stats, timing

    Raises:
        FileNotFoundError: If the Go binary is not built
        RuntimeError: If the binary fails
        TimeoutError: If it exceeds timeout
    """
    if not DISCOVERY_BINARY.exists():
        raise FileNotFoundError(
            f"Discovery binary not found at {DISCOVERY_BINARY}. "
            f"Build it: cd discovery && go build -o bin/discovery-engine ."
        )

    if scan_id is None:
        scan_id = f"sc_{uuid.uuid4().hex[:12]}"

    # Output file path
    output_dir = settings.data_dir_abs / "discovery"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_file = output_dir / f"{scan_id}.json"

    # Build command
    cmd = [
        str(DISCOVERY_BINARY),
        "--domain", domain,
        "--output", str(output_file),
        "--scan-id", scan_id,
        "--ports", port_mode,
    ]

    logger.info(
        f"Starting discovery for {domain}",
        extra={"scan_id": scan_id, "command": " ".join(cmd)},
    )

    # Run subprocess
    env = os.environ.copy()
    env["LOG_DIR"] = str(settings.log_dir_abs)

    try:
        # Use Popen instead of run() to allow for cancellation checks
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        
        # Poll for completion while checking for cancellation
        from app.core.database import SessionLocal
        from app.models.scan import ScanJob, ScanStatus
        
        start_wait = time.time()
        while process.poll() is None:
            # Check for timeout
            if time.time() - start_wait > timeout_seconds:
                process.kill()
                raise TimeoutError(f"Discovery timed out after {timeout_seconds}s")
            
            # Check for cancellation in DB every 2 seconds
            if scan_id:
                try:
                    db = SessionLocal()
                    job = db.query(ScanJob).filter(ScanJob.id == uuid.UUID(scan_id)).first()
                    if job and job.status == ScanStatus.CANCELLED:
                        logger.info(f"Cancellation detected for scan {scan_id}. Killing Go discovery process.")
                        process.kill()
                        db.close()
                        return {"assets": [], "stats": {}, "interrupted": True}
                    db.close()
                except Exception as e:
                    logger.warning(f"Failed to check cancellation status: {e}")
            
            time.sleep(2)
            
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            logger.error(
                f"Discovery failed with exit code {process.returncode}",
                extra={"stderr": stderr[:500], "domain": domain},
            )
            raise RuntimeError(f"Discovery failed: {stderr[:200]}")
    except Exception as e:
        logger.error(f"Discovery execution error: {e}", exc_info=True)
        raise

    # Read output JSON
    if not output_file.exists():
        raise RuntimeError(f"Discovery output file not created: {output_file}")

    with open(output_file) as f:
        discovery_data = json.load(f)

    asset_count = len(discovery_data.get("assets", []))
    logger.info(
        f"Discovery complete: {asset_count} assets for {domain}",
        extra={
            "scan_id": scan_id,
            "asset_count": asset_count,
            "stats": discovery_data.get("stats", {}),
        },
    )

    return discovery_data
