"""
testssl_service.py — Run testssl.sh against a host and parse the JSON output
into structured sections for the TLS Deep Inspection dashboard.
"""
import json
import logging
import os
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.models.tls_inspection import TLSInspection, TLSInspectionStatus

logger = logging.getLogger(__name__)

TESTSSL_BIN = os.environ.get("TESTSSL_BIN", "/app/testssl.sh/testssl.sh")
TESTSSL_TIMEOUT = int(os.environ.get("TESTSSL_TIMEOUT", "600"))  # 10 min default
TESTSSL_DEBUG_DIR = os.environ.get("TESTSSL_DEBUG_DIR", "/app/data/testssl")


# ─── Categories for classifying testssl.sh finding IDs ─────────────────────────

_PROTOCOL_IDS = {
    "SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3",
    "NPN", "ALPN", "ALPN_HTTP2",
}

_VULN_IDS = {
    "heartbleed", "CCS", "ticketbleed", "ROBOT", "secure_renego",
    "secure_client_renego", "CRIME_TLS", "BREACH", "POODLE_SSL",
    "fallback_SCSV", "SWEET32", "FREAK", "DROWN", "DROWN_hint",
    "LOGJAM", "LOGJAM-common_primes", "BEAST", "LUCKY13",
    "winshock", "RC4", "GREASE",
    "opossum",
}

_HEADER_IDS = {
    "HSTS", "HSTS_time", "HPKP", "HPKP_SPKIs",
    "X-Frame-Options", "X-Content-Type-Options",
    "Content-Security-Policy", "X-XSS-Protection",
    "Referrer-Policy", "Permissions-Policy", "Feature-Policy",
    "Expect-CT",
    "banner_server", "banner_application", "banner_reverseproxy",
    "cookie_count", "cookie_secure", "cookie_httponly",
}

_HEADER_PREFIXES = (
    "HTTP_", "cookie_",
)

_CERT_IDS_PREFIXES = (
    "cert", "intermediate_cert", "chain_of_trust", "cert_",
    "OCSP", "ocsp", "crl", "CT",
)

_SERVER_PREF_IDS_PREFIXES = (
    "server_defaults", "cipher_order", "protocol_negotiated",
    "TLS_session_ticket", "Session_Tickets", "TLS_extensions",
    "TLS_misses_",
    "server_pref", "cipher-",
)

_FS_IDS_PREFIXES = (
    "FS", "fs_", "PFS",
)

_SKIP_PREFIXES = (
    "clientsimulation-", "rating_",
)

_SKIP_IDS = {
    "scanTime", "engine_problem", "scanProblem", "pre_test",
    "pre_128cipher", "rating_spec", "rating_doc",
    "__testssl_grade__",
}

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "WARN": 4, "INFO": 5, "OK": 6}


def _classify_finding(finding_id: str) -> str:
    """Return the dashboard section for a testssl.sh finding ID."""
    # Skip browser simulations and rating metadata
    for prefix in _SKIP_PREFIXES:
        if finding_id.startswith(prefix):
            return "skip"
    if finding_id in _SKIP_IDS:
        return "skip"
    if finding_id in _PROTOCOL_IDS:
        return "protocols"
    if finding_id in _VULN_IDS:
        return "vulnerabilities"
    if finding_id in _HEADER_IDS:
        return "headers"
    for prefix in _HEADER_PREFIXES:
        if finding_id.startswith(prefix):
            return "headers"
    for prefix in _CERT_IDS_PREFIXES:
        if finding_id.startswith(prefix):
            return "certificates"
    for prefix in _FS_IDS_PREFIXES:
        if finding_id.startswith(prefix):
            return "forward_secrecy"
    for prefix in _SERVER_PREF_IDS_PREFIXES:
        if finding_id.startswith(prefix):
            return "server_preferences"
    if finding_id.startswith("cipher"):
        return "ciphers"
    return "other"


def _severity_label(sev: str) -> str:
    """Normalise severity strings from testssl.sh."""
    s = sev.strip().upper()
    if s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "WARN", "INFO", "OK"):
        return s
    if s == "NOT OK" or s == "NOT ok":
        return "HIGH"
    if "FATAL" in s:
        return "CRITICAL"
    return "INFO"


def _compute_grade(severity_counts: dict) -> str:
    """Compute a letter grade from severity distribution."""
    crit = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    med = severity_counts.get("MEDIUM", 0)
    low = severity_counts.get("LOW", 0)
    if crit > 0:
        return "F"
    if high > 2:
        return "D"
    if high > 0:
        return "C"
    if med > 3:
        return "C"
    if med > 0:
        return "B"
    if low > 2:
        return "B"
    return "A"


def parse_testssl_json(raw_findings: list[dict]) -> dict:
    """
    Parse testssl.sh JSON array into structured dashboard sections.

    Returns a summary dict with:
      - grade, severity_counts
      - protocols, vulnerabilities, ciphers, certificates,
        headers, server_preferences, forward_secrecy, other
      - Each section is a list of {id, severity, finding, cve, cwe, hint}
    """
    sections: dict[str, list] = {
        "protocols": [],
        "vulnerabilities": [],
        "ciphers": [],
        "certificates": [],
        "headers": [],
        "server_preferences": [],
        "forward_secrecy": [],
        "other": [],
    }

    severity_counts: dict[str, int] = {}
    all_findings: list[dict] = []
    skipped_meta = 0
    unclassified_ids: list[str] = []

    logger.info(f"[parse] Starting parse of {len(raw_findings)} raw findings")

    for item in raw_findings:
        fid = item.get("id", "")
        sev = _severity_label(item.get("severity", "INFO"))
        finding_text = item.get("finding", "")
        cve = item.get("cve", "")
        cwe = item.get("cwe", "")
        hint = item.get("hint", "")

        section = _classify_finding(fid)
        if section == "skip":
            skipped_meta += 1
            continue
        if section == "other":
            unclassified_ids.append(fid)
        entry = {
            "id": fid,
            "severity": sev,
            "finding": finding_text,
            "cve": cve,
            "cwe": cwe,
            "hint": hint,
        }
        sections[section].append(entry)
        all_findings.append(entry)
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Protocol support matrix
    protocol_support = {}
    for p in sections["protocols"]:
        pid = p["id"]
        is_offered = "offered" in p["finding"].lower() or "yes" in p["finding"].lower()
        is_not_offered = "not offered" in p["finding"].lower() or "not" in p["finding"].lower()
        protocol_support[pid] = {
            "offered": is_offered and not is_not_offered,
            "severity": p["severity"],
            "detail": p["finding"],
        }

    # Vulnerability status map
    vuln_status = {}
    for v in sections["vulnerabilities"]:
        is_vuln = v["severity"] in ("CRITICAL", "HIGH", "MEDIUM")
        vuln_status[v["id"]] = {
            "vulnerable": is_vuln,
            "severity": v["severity"],
            "detail": v["finding"],
            "cve": v["cve"],
        }

    # Cipher strength breakdown
    cipher_strength = {"strong": 0, "acceptable": 0, "weak": 0, "insecure": 0}
    for c in sections["ciphers"]:
        sev = c["severity"]
        if sev in ("CRITICAL", "HIGH"):
            cipher_strength["insecure"] += 1
        elif sev == "MEDIUM":
            cipher_strength["weak"] += 1
        elif sev in ("LOW", "WARN"):
            cipher_strength["acceptable"] += 1
        else:
            cipher_strength["strong"] += 1

    # Prefer testssl.sh's own grade if present, else compute
    testssl_grade_entry = next((f for f in raw_findings if f.get("id") == "__testssl_grade__"), None)
    if testssl_grade_entry:
        grade = testssl_grade_entry["finding"].strip()
        logger.info(f"[parse] Using testssl.sh native grade: {grade}")
    else:
        grade = _compute_grade(severity_counts)
        logger.info(f"[parse] Computed grade: {grade}")

    logger.info(f"[parse] RESULT: grade={grade}, total={len(all_findings)}, skipped_meta={skipped_meta}")
    logger.info(f"[parse] Severity counts: {severity_counts}")
    logger.info(f"[parse] Sections: { {k: len(v) for k, v in sections.items()} }")
    if unclassified_ids:
        logger.info(f"[parse] Unclassified IDs ({len(unclassified_ids)}): {unclassified_ids[:20]}")

    return {
        "grade": grade,
        "severity_counts": severity_counts,
        "total_findings": len(all_findings),
        "protocol_support": protocol_support,
        "vuln_status": vuln_status,
        "cipher_strength": cipher_strength,
        "sections": {k: v for k, v in sections.items()},
        "all_findings": all_findings,
    }


def _flatten_pretty_json(raw: dict) -> tuple[list[dict], Optional[str]]:
    """
    Flatten the nested --jsonfile-pretty JSON structure into a flat list of findings.

    testssl.sh --jsonfile-pretty produces:
      { "scanResult": [ { "targetHost": ..., "protocols": [...], "vulnerabilities": [...], ... } ] }
    Each section value is a list of {id, severity, finding, cve?, cwe?, hint?} dicts.

    Returns (findings_list, testssl_grade_or_none)
    """
    findings: list[dict] = []
    testssl_grade: Optional[str] = None

    scan_results = raw.get("scanResult", raw.get("scanresult", []))
    if not isinstance(scan_results, list):
        logger.warning(f"_flatten_pretty_json: scanResult is {type(scan_results).__name__}, expected list")
        return findings, None

    for host_obj in scan_results:
        if not isinstance(host_obj, dict):
            continue
        for section_key, section_val in host_obj.items():
            # Skip metadata fields (strings)
            if not isinstance(section_val, list):
                continue
            for item in section_val:
                if isinstance(item, dict) and "id" in item:
                    findings.append(item)
                    # Extract testssl.sh's own grade
                    if item.get("id") == "overall_grade":
                        testssl_grade = item.get("finding", "").strip()

    logger.info(f"_flatten_pretty_json: extracted {len(findings)} findings from {len(scan_results)} host(s), testssl_grade={testssl_grade}")
    return findings, testssl_grade


def _save_debug_json(hostname: str, data: object, suffix: str = "raw") -> str:
    """Save a debug copy of JSON data. Returns the file path."""
    try:
        os.makedirs(TESTSSL_DEBUG_DIR, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        safe_host = hostname.replace(".", "_").replace("/", "_")
        path = os.path.join(TESTSSL_DEBUG_DIR, f"{safe_host}_{ts}_{suffix}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info(f"Debug JSON saved: {path} ({os.path.getsize(path)} bytes)")
        return path
    except Exception as e:
        logger.warning(f"Failed to save debug JSON: {e}")
        return ""


def run_testssl(hostname: str, port: str = "443") -> tuple[list[dict], Optional[str]]:
    """
    Execute testssl.sh against hostname:port.
    Returns (raw_json_findings, error_or_none).
    """
    if not os.path.isfile(TESTSSL_BIN):
        return [], f"testssl.sh not found at {TESTSSL_BIN}"

    target = f"{hostname}:{port}" if port != "443" else hostname

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tmp:
        json_path = tmp.name

    try:
        cmd = [
            TESTSSL_BIN,
            "--jsonfile-pretty", json_path,
            "--warnings", "batch",
            "--openssl-timeout", "120",
            "--socket-timeout", "120",
            target,
        ]
        logger.info(f"[testssl] START: {' '.join(cmd)}")
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TESTSSL_TIMEOUT,
            env={**os.environ, "TERM": "dumb"},
        )
        logger.info(f"[testssl] DONE: exit_code={result.returncode}, host={hostname}")
        if result.stderr:
            logger.debug(f"[testssl] stderr (last 500): {result.stderr[-500:]}")

        # Read JSON output
        if os.path.isfile(json_path) and os.path.getsize(json_path) > 0:
            file_size = os.path.getsize(json_path)
            logger.info(f"[testssl] JSON file: {json_path}, size={file_size} bytes")

            with open(json_path, "r") as f:
                raw = json.load(f)

            logger.info(f"[testssl] Parsed JSON type={type(raw).__name__}" +
                        (f", keys={list(raw.keys())}" if isinstance(raw, dict) else f", len={len(raw)}"))

            # Save debug copy
            _save_debug_json(hostname, raw, "raw")

            # --jsonfile (flat list)
            if isinstance(raw, list):
                logger.info(f"[testssl] Flat list format: {len(raw)} findings")
                return raw, None

            # --jsonfile-pretty (nested dict with scanResult)
            if isinstance(raw, dict):
                findings, testssl_grade = _flatten_pretty_json(raw)
                if findings:
                    logger.info(f"[testssl] Flattened {len(findings)} findings from pretty JSON, testssl_grade={testssl_grade}")
                    _save_debug_json(hostname, findings, "flattened")
                    # Stash the grade in a sentinel finding so parse_testssl_json can use it
                    if testssl_grade:
                        findings.append({"id": "__testssl_grade__", "severity": "INFO", "finding": testssl_grade})
                    return findings, None
                else:
                    # Check for fatal scan problems
                    for key in ["clientProblem1", "scanResult"]:
                        items = raw.get(key, [])
                        if isinstance(items, list):
                            for item in items:
                                if isinstance(item, dict) and item.get("severity") == "FATAL":
                                    return [], f"testssl.sh FATAL: {item.get('finding', 'unknown')}"
                    return [], f"No findings extracted from JSON (keys: {list(raw.keys())})"

            return [], f"Unexpected JSON format: {type(raw)}"
        else:
            err = result.stderr.strip() or result.stdout.strip() or "No output file generated"
            return [], f"testssl.sh produced no JSON: {err[:300]}"
    except subprocess.TimeoutExpired:
        return [], f"testssl.sh timed out after {TESTSSL_TIMEOUT}s"
    except Exception as e:
        logger.error(f"[testssl] Execution error: {e}", exc_info=True)
        return [], f"testssl.sh execution error: {e}"
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass


def start_inspection(db: Session, asset_id: str, hostname: str, port: str = "443") -> TLSInspection:
    """Create an inspection record and run testssl.sh synchronously (meant for background thread)."""
    inspection = TLSInspection(
        id=uuid.uuid4(),
        asset_id=asset_id,
        hostname=hostname,
        port=port,
        status=TLSInspectionStatus.RUNNING,
        started_at=datetime.now(timezone.utc),
    )
    db.add(inspection)
    db.commit()
    db.refresh(inspection)

    raw_findings, error = run_testssl(hostname, port)

    if error:
        inspection.status = TLSInspectionStatus.FAILED
        inspection.error_message = error
        inspection.completed_at = datetime.now(timezone.utc)
        db.commit()
        return inspection

    try:
        summary = parse_testssl_json(raw_findings)
    except Exception as e:
        inspection.status = TLSInspectionStatus.FAILED
        inspection.error_message = f"Parse error: {e}"
        inspection.completed_at = datetime.now(timezone.utc)
        db.commit()
        return inspection

    inspection.raw_json = raw_findings
    inspection.summary = summary
    inspection.status = TLSInspectionStatus.COMPLETED
    inspection.completed_at = datetime.now(timezone.utc)
    db.commit()
    return inspection


def get_latest_inspection(db: Session, asset_id: str) -> Optional[TLSInspection]:
    """Get the most recent inspection for an asset."""
    return (
        db.query(TLSInspection)
        .filter(TLSInspection.asset_id == asset_id)
        .order_by(TLSInspection.created_at.desc())
        .first()
    )


def get_inspection_history(db: Session, asset_id: str, limit: int = 10) -> list[TLSInspection]:
    """Get inspection history for an asset."""
    return (
        db.query(TLSInspection)
        .filter(TLSInspection.asset_id == asset_id)
        .order_by(TLSInspection.created_at.desc())
        .limit(limit)
        .all()
    )
