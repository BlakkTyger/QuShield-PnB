"""
Discovery Runner — Python wrapper for the Go Discovery Engine binary.

Calls the Go binary via subprocess and returns structured results.
"""
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Optional

from app.config import settings, PROJECT_ROOT
from app.core.logging import get_logger
from app.core.utils import check_binary_format
from app.core.timing import timed

logger = get_logger("discovery_runner")

# Path to the Go binary
_BIN_NAME = "discovery-engine.exe" if sys.platform == "win32" else "discovery-engine"
DISCOVERY_BINARY = PROJECT_ROOT / "discovery" / "bin" / _BIN_NAME


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
        # Fallback: check if the non-exe version exists (e.g. they built it without extension)
        alt_bin = DISCOVERY_BINARY.with_suffix("") if sys.platform == "win32" else DISCOVERY_BINARY.with_suffix(".exe")
        if alt_bin.exists():
            check_binary_format(alt_bin)
            raise FileNotFoundError(
                f"Discovery binary found without .exe extension at {alt_bin}. "
                f"Please rename it to {DISCOVERY_BINARY.name} or rebuild it."
            )

        raise FileNotFoundError(
            f"Discovery binary not found at {DISCOVERY_BINARY}. "
            f"Build it for Windows: cd discovery && go build -o bin/discovery-engine.exe ."
        )

    check_binary_format(DISCOVERY_BINARY)

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
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            env=env,
        )
    except subprocess.TimeoutExpired:
        logger.error(f"Discovery timed out after {timeout_seconds}s for {domain}")
        raise TimeoutError(f"Discovery timed out after {timeout_seconds}s")

    if result.returncode != 0:
        logger.error(
            f"Discovery failed with exit code {result.returncode}",
            extra={"stderr": result.stderr[:500], "domain": domain},
        )
        raise RuntimeError(f"Discovery failed: {result.stderr[:200]}")

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
