# Phase 7B — Feature Expansion Plan

> Detailed phase plan for all new backend features. See `PROMPT.md` for checkpoint tracking.

---

## Overview

Phase 7B adds: scan tiers (Quick/Shallow/Deep), authentication, GeoIP mapping, hybrid PQC detection, cipher suite decomposition, HNDL sensitivity multiplier, migration complexity scoring, scan caching, and incremental scanning.

## New Dependencies

| Package | Purpose | Version |
|---|---|---|
| `passlib[bcrypt]` | Password hashing | latest |
| `python-jose[cryptography]` | JWT token generation/validation | latest |
| `geoip2` | MaxMind GeoLite2 lookups | already in requirements.txt |
| `httpx` | crt.sh API calls for shallow scan | already in requirements.txt |

## New Models

### User
```
id: UUID (PK)
email: String (unique, indexed)
password_hash: String
email_verified: Boolean (default=False)
created_at: DateTime
```

### EmailVerification
```
id: UUID (PK)
user_id: UUID (FK → User)
token: String (unique, indexed)
expires_at: DateTime
created_at: DateTime
```

### GeoLocation
```
id: UUID (PK)
asset_id: UUID (FK → Asset)
scan_id: UUID (FK → ScanJob)
ip_address: String
latitude: Float
longitude: Float
city: String (nullable)
state: String (nullable)
country: String (nullable)
organization: String (nullable)
isp: String (nullable)
asn: Integer (nullable)
```

### ScanCache
```
id: UUID (PK)
domain: String (indexed)
scan_type: String (quick/shallow/deep)
scan_id: UUID (FK → ScanJob)
user_id: UUID (FK → User, nullable)
cached_at: DateTime
expires_at: DateTime
```

## Model Updates

### ScanJob
- Add `scan_type: String` (quick/shallow/deep, default="deep")
- Add `user_id: UUID` (FK → User, nullable for backward compat)

### Asset
- Add `fingerprint_hash: String` (nullable, for incremental scanning)

### RiskScore
- Add `migration_complexity_years: Float` (nullable)
- Add `sensitivity_multiplier: Float` (nullable)

## New API Endpoints

| Method | Path | Auth Required | Description |
|---|---|---|---|
| POST | `/api/v1/auth/register` | No | Register new user |
| POST | `/api/v1/auth/login` | No | Login, returns JWT |
| POST | `/api/v1/auth/verify-email/{token}` | No | Verify email |
| POST | `/api/v1/auth/refresh` | Yes | Refresh access token |
| GET | `/api/v1/auth/me` | Yes | Current user info |
| POST | `/api/v1/scans/quick` | No | Synchronous quick scan |
| POST | `/api/v1/scans/shallow` | Yes | Background shallow scan |
| GET | `/api/v1/scans/my` | Yes | User's scan history |
| GET | `/api/v1/geo/scan/{id}` | No | GeoJSON for all IPs in scan |
| GET | `/api/v1/geo/scan/{id}/map-data` | No | Map-ready IP location data |

## New Services

### `quick_scanner.py`
- `quick_scan(domain: str) -> dict` — single SSL connection, cert parse, risk score, compliance snapshot
- Returns structured result synchronously (no DB persistence for anonymous quick scans)
- For authenticated users, results are persisted as a `quick` type ScanJob

### `shallow_scanner.py`
- `shallow_scan(domain: str, scan_id: str) -> dict` — crt.sh discovery + top-N TLS scans
- Runs as background task, persists to DB
- Uses stdlib ssl only (no SSLyze) for speed

### `auth_service.py`
- `register_user(email, password) -> User`
- `authenticate_user(email, password) -> User`
- `create_access_token(user_id) -> str`
- `create_refresh_token(user_id) -> str`
- `verify_token(token) -> dict`
- `send_verification_email(user, token)` — sends via SMTP or logs to console in dev

### `geo_service.py`
- `geolocate_ip(ip: str) -> dict` — MaxMind lookup
- `geolocate_assets(scan_id, db) -> list[GeoLocation]` — bulk geolocate all IPs in a scan

## Testing Strategy

Every new service gets a standalone test script in `tests/standalone/` that runs independently of the API:
- `test_quick_scan.py` — test against pnb.bank.in, verify <8s, verify output structure
- `test_shallow_scan.py` — test crt.sh discovery, verify subdomain count
- `test_auth_service.py` — test register/login/verify flow
- `test_geo_service.py` — test IP geolocation with known IPs
- `test_cipher_decomposition.py` — test with known cipher suite strings
- `test_hndl_sensitivity.py` — test multiplier application
- `test_migration_complexity.py` — test dynamic complexity calculation

After standalone tests pass, features are integrated into the API and tested via `tests/integration/test_api.py`.
