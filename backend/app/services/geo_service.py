"""
GeoIP Service — IP-to-location resolution for asset mapping.

Primary: MaxMind GeoLite2-City database (if available).
Fallback: ip-api.com free API (no key required, 45 req/min limit).

Provides: latitude, longitude, city, state, country, org, ISP, AS number.
"""
import os
import socket
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

from app.core.logging import get_logger

logger = get_logger("geo_service")

# MaxMind database path (configurable via env)
GEOIP_DB_PATH = os.environ.get(
    "GEOIP_DB_PATH",
    os.path.join(os.path.dirname(__file__), "..", "..", "data", "GeoLite2-City.mmdb"),
)

# Check if MaxMind database is available
_maxmind_reader = None
try:
    import geoip2.database
    if os.path.exists(GEOIP_DB_PATH):
        _maxmind_reader = geoip2.database.Reader(GEOIP_DB_PATH)
        logger.info(f"MaxMind GeoLite2 database loaded from {GEOIP_DB_PATH}")
    else:
        logger.info(f"MaxMind DB not found at {GEOIP_DB_PATH}, using ip-api.com fallback")
except ImportError:
    logger.info("geoip2 not installed, using ip-api.com fallback")


def _geolocate_maxmind(ip: str) -> Optional[dict]:
    """Geolocate IP using MaxMind GeoLite2 database."""
    if not _maxmind_reader:
        return None
    try:
        resp = _maxmind_reader.city(ip)
        return {
            "ip": ip,
            "latitude": resp.location.latitude,
            "longitude": resp.location.longitude,
            "city": resp.city.name,
            "state": resp.subdivisions.most_specific.name if resp.subdivisions else None,
            "country": resp.country.name,
            "country_code": resp.country.iso_code,
            "org": resp.traits.organization if hasattr(resp.traits, "organization") else None,
            "isp": resp.traits.isp if hasattr(resp.traits, "isp") else None,
            "as_number": resp.traits.autonomous_system_number if hasattr(resp.traits, "autonomous_system_number") else None,
            "source": "maxmind",
        }
    except Exception as e:
        logger.debug(f"MaxMind lookup failed for {ip}: {e}")
        return None


def _geolocate_ipapi(ip: str, timeout: float = 5.0) -> Optional[dict]:
    """Geolocate IP using ip-api.com free API (no key required)."""
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    return {
                        "ip": ip,
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "city": data.get("city"),
                        "state": data.get("regionName"),
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "org": data.get("org"),
                        "isp": data.get("isp"),
                        "as_number": data.get("as"),
                        "source": "ip-api.com",
                    }
    except Exception as e:
        logger.debug(f"ip-api.com lookup failed for {ip}: {e}")
    return None


def geolocate_ip(ip: str) -> Optional[dict]:
    """
    Geolocate a single IP address.

    Tries MaxMind first, falls back to ip-api.com.
    """
    # Try MaxMind first
    result = _geolocate_maxmind(ip)
    if result:
        return result

    # Fallback to ip-api.com
    result = _geolocate_ipapi(ip)
    return result


def resolve_and_geolocate(hostname: str) -> Optional[dict]:
    """Resolve hostname to IP and geolocate it."""
    try:
        ip = socket.gethostbyname(hostname)
    except (socket.gaierror, socket.timeout, OSError):
        return None

    geo = geolocate_ip(ip)
    if geo:
        geo["hostname"] = hostname
    return geo


def geolocate_batch(
    assets: list[dict],
    max_workers: int = 5,
) -> list[dict]:
    """
    Geolocate a batch of assets using MaxMind (local) and ip-api.com (batched).
    """
    import time
    results = []
    unresolved_assets = []

    # 1. Resolve hostnames & Try MaxMind first locally
    for asset in assets:
        hostname = asset.get("hostname", "")
        ip = asset.get("ip")
        if not ip:
            try:
                ip = socket.gethostbyname(hostname)
            except (socket.gaierror, socket.timeout, OSError):
                continue

        geo = _geolocate_maxmind(ip)
        if geo:
            geo["hostname"] = hostname
            geo["asset_id"] = asset.get("asset_id")
            results.append(geo)
        else:
            unresolved_assets.append({
                "ip": ip,
                "hostname": hostname,
                "asset_id": asset.get("asset_id"),
            })

    # 2. Batch resolve remaining via ip-api.com
    chunk_size = 90  # API allows up to 100 per request
    for i in range(0, len(unresolved_assets), chunk_size):
        chunk = unresolved_assets[i:i + chunk_size]
        ips = [a["ip"] for a in chunk]

        try:
            with httpx.Client(timeout=10.0) as client:
                url = "http://ip-api.com/batch?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,query"
                resp = client.post(url, json=ips)
                
                if resp.status_code == 200:
                    api_results = resp.json()
                    for api_res, asset_info in zip(api_results, chunk):
                        if api_res.get("status") == "success":
                            geo = {
                                "ip": api_res.get("query") or asset_info["ip"],
                                "latitude": api_res.get("lat"),
                                "longitude": api_res.get("lon"),
                                "city": api_res.get("city"),
                                "state": api_res.get("regionName"),
                                "country": api_res.get("country"),
                                "country_code": api_res.get("countryCode"),
                                "org": api_res.get("org"),
                                "isp": api_res.get("isp"),
                                "as_number": api_res.get("as"),
                                "source": "ip-api.com",
                                "hostname": asset_info["hostname"],
                                "asset_id": asset_info["asset_id"],
                            }
                            results.append(geo)
        except Exception as e:
            logger.debug(f"ip-api.com batch lookup failed for chunk: {e}")
            
        if len(unresolved_assets) > chunk_size and i + chunk_size < len(unresolved_assets):
            time.sleep(2.0)  # Rate limit protection

    logger.info(f"Geolocated {len(results)}/{len(assets)} assets")
    return results
