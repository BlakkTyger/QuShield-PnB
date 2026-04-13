"""
PQCscan binary integration — TLS hybrid / pure PQC KEX probing.

Runs the bundled Anvil PQCscan CLI (Linux: bin/pqcscan_bin, Windows: bin/pqcscan.exe)
and normalizes JSON output for crypto_inspector and compliance.
"""
from __future__ import annotations

import json
import logging
import subprocess
import sys
import uuid
from pathlib import Path
from typing import Any

from app.config import PROJECT_ROOT, get_settings

logger = logging.getLogger(__name__)


from app.core.utils import check_binary_format

def resolve_pqcscan_binary() -> Path | None:
    """Return path to PQCscan executable, or None if missing."""
    settings = get_settings()
    if getattr(settings, "PQCSCAN_BIN", ""):
        p = Path(settings.PQCSCAN_BIN)
        return p if p.is_file() else None
    name = "pqcscan.exe" if sys.platform == "win32" else "pqcscan_bin"
    # Search in backend/bin first, then root/bin
    search_paths = [
        PROJECT_ROOT / "bin" / name,
        PROJECT_ROOT.parent / "bin" / name,
    ]
    for p in search_paths:
        if p.is_file():
            check_binary_format(p)
            return p
    return None


def _validate_scan_target(hostname: str, port: int) -> None:
    if not isinstance(port, int) or port < 1 or port > 65535:
        raise ValueError("invalid port")
    if not hostname or len(hostname) > 253:
        raise ValueError("invalid hostname")
    for ch in hostname:
        if ch.isalnum() or ch in ".-":
            continue
        raise ValueError(f"invalid hostname character: {ch!r}")


def parse_pqcscan_tls_json(raw: dict[str, Any]) -> dict[str, Any]:
    """
    Parse PQCscan TLS JSON document into a stable dict (for tests and production).

    Expected shape (PQCscan 0.8.x):
      { "results": [ { "Tls": { ... } } ], "version": "..." }
    """
    out: dict[str, Any] = {
        "ok": False,
        "error": None,
        "tls_error": None,
        "pqc_supported": False,
        "hybrid_algos": [],
        "pqc_algos": [],
        "nonpqc_algos": [],
        "scan_version": raw.get("version"),
    }
    results = raw.get("results")
    if not isinstance(results, list) or not results:
        out["error"] = "PQCscan JSON missing results[]"
        return out

    tls_block = None
    for item in results:
        if not isinstance(item, dict):
            continue
        tls_block = item.get("Tls") or item.get("tls")
        if tls_block is not None:
            break

    if not isinstance(tls_block, dict):
        out["error"] = "PQCscan JSON missing Tls object"
        return out

    err = tls_block.get("error")
    if err:
        out["tls_error"] = str(err)

    out["hybrid_algos"] = list(tls_block.get("hybrid_algos") or [])
    out["pqc_algos"] = list(tls_block.get("pqc_algos") or [])
    out["nonpqc_algos"] = list(tls_block.get("nonpqc_algos") or [])
    out["pqc_supported"] = bool(tls_block.get("pqc_supported"))
    out["ok"] = True
    return out


def run_pqcscan_tls(hostname: str, port: int = 443) -> dict[str, Any]:
    """
    Execute `pqcscan tls-scan -t host:port -o <tmp.json> --num-threads 1`.

    Returns parse_pqcscan_tls_json structure plus keys:
      performed: True
      subprocess_error: str if spawn/parse failed
    """
    settings = get_settings()
    base: dict[str, Any] = {
        "ok": False,
        "error": None,
        "tls_error": None,
        "pqc_supported": False,
        "hybrid_algos": [],
        "pqc_algos": [],
        "nonpqc_algos": [],
        "scan_version": None,
        "performed": True,
        "subprocess_error": None,
        "raw_output_json": None,
        "command": None,
        "target": f"{hostname}:{port}",
    }

    if not getattr(settings, "PQCSCAN_ENABLED", True):
        base["error"] = "PQCscan disabled via PQCSCAN_ENABLED"
        base["performed"] = False
        return base

    binary = resolve_pqcscan_binary()
    if binary is None:
        base["error"] = "PQCscan binary not found (set PQCSCAN_BIN or add bin/pqcscan_bin)"
        return base

    try:
        _validate_scan_target(hostname, port)
    except ValueError as e:
        base["error"] = str(e)
        return base

    data_dir = get_settings().data_dir_abs
    data_dir.mkdir(parents=True, exist_ok=True)
    out_path = data_dir / f".pqcscan_{uuid.uuid4().hex}.json"
    timeout = int(getattr(settings, "PQCSCAN_TIMEOUT_SEC", 45) or 45)
    target = f"{hostname}:{port}"
    cmd = [
        str(binary),
        "tls-scan",
        "-t",
        target,
        "-o",
        str(out_path),
        "--num-threads",
        "1",
    ]
    base["command"] = cmd

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0:
            tail = (completed.stderr or completed.stdout or "").strip()[:500]
            base["subprocess_error"] = f"pqcscan exit {completed.returncode}: {tail or 'no output'}"
            logger.warning("PQCscan failed for %s: %s", target, base["subprocess_error"])
            return base
        if not out_path.is_file():
            base["subprocess_error"] = "PQCscan did not write output file"
            return base
        raw = json.loads(out_path.read_text(encoding="utf-8"))
        base["raw_output_json"] = raw
    except subprocess.TimeoutExpired:
        base["subprocess_error"] = f"PQCscan timed out after {timeout}s"
        logger.warning("PQCscan timeout for %s", target)
        return base
    except json.JSONDecodeError as e:
        base["subprocess_error"] = f"Invalid PQCscan JSON: {e}"
        return base
    except OSError as e:
        base["subprocess_error"] = f"PQCscan I/O error: {e}"
        return base
    finally:
        try:
            out_path.unlink(missing_ok=True)
        except OSError:
            pass

    parsed = parse_pqcscan_tls_json(raw)
    parsed["performed"] = True
    parsed["raw_output_json"] = base.get("raw_output_json")
    parsed["command"] = base.get("command")
    parsed["target"] = base.get("target")
    if base.get("subprocess_error"):
        parsed["subprocess_error"] = base["subprocess_error"]
    return parsed


def maybe_run_pqcscan_tls(hostname: str, port: int = 443, *, for_quick_scan: bool = False) -> dict[str, Any] | None:
    """
    Run PQCscan unless disabled or (quick scan path and PQCSCAN_IN_QUICK_SCAN is False).
    Returns None when skipped so callers can avoid merging.
    """
    settings = get_settings()
    if not getattr(settings, "PQCSCAN_ENABLED", True):
        return None
    if for_quick_scan and not getattr(settings, "PQCSCAN_IN_QUICK_SCAN", False):
        return None
    return run_pqcscan_tls(hostname, port)
