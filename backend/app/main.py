"""
QuShield-PnB — FastAPI Application Entry Point

Exposes all scan pipeline data via REST API with Swagger documentation.
"""
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.core.database import check_connection, init_db
from app.core.logging import get_logger
from app.core.exceptions import QuShieldError, ScanError

logger = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic."""
    logger.info("QuShield-PnB starting up...")
    # Initialize database tables if needed
    try:
        tables = init_db()
        logger.info(f"Database ready: {len(tables)} tables")
    except Exception as e:
        logger.error(f"Database init failed: {e}")
    yield
    logger.info("QuShield-PnB shutting down...")


app = FastAPI(
    title="QuShield-PnB",
    description=(
        "Post-Quantum Cryptographic Bill of Materials (CBOM) Scanner for Indian Banking Infrastructure. "
        "Discovers external attack surfaces, inventories cryptographic algorithms, assesses quantum risk "
        "via Mosca's theorem, and evaluates compliance against FIPS 203/204/205, RBI, SEBI, PCI DSS 4.0."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# CORS — allow Next.js frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Exception Handlers ─────────────────────────────────────────────────────

@app.exception_handler(QuShieldError)
async def qushield_error_handler(request: Request, exc: QuShieldError):
    return JSONResponse(
        status_code=400,
        content={"error": type(exc).__name__, "detail": str(exc)},
    )


@app.exception_handler(ScanError)
async def scan_error_handler(request: Request, exc: ScanError):
    return JSONResponse(
        status_code=422,
        content={"error": type(exc).__name__, "detail": str(exc)},
    )


@app.exception_handler(Exception)
async def general_error_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "detail": "An unexpected error occurred."},
    )


# ─── Health Check ────────────────────────────────────────────────────────────

@app.get("/health", tags=["System"])
def health_check():
    """Health check endpoint — verifies API and database connectivity."""
    db_ok = check_connection()
    return {
        "status": "ok" if db_ok else "degraded",
        "db": "connected" if db_ok else "disconnected",
        "version": "0.1.0",
    }


# ─── Mount API Routers ──────────────────────────────────────────────────────

from app.api.v1.scans import router as scans_router
from app.api.v1.assets import router as assets_router
from app.api.v1.cbom import router as cbom_router
from app.api.v1.risk import router as risk_router
from app.api.v1.compliance import router as compliance_router
from app.api.v1.topology import router as topology_router
from app.api.v1.geo import router as geo_router
from app.api.v1.auth import router as auth_router

app.include_router(auth_router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(scans_router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(assets_router, prefix="/api/v1/assets", tags=["Assets"])
app.include_router(cbom_router, prefix="/api/v1/cbom", tags=["CBOM"])
app.include_router(risk_router, prefix="/api/v1/risk", tags=["Risk"])
app.include_router(compliance_router, prefix="/api/v1/compliance", tags=["Compliance"])
app.include_router(topology_router, prefix="/api/v1/topology", tags=["Topology"])
app.include_router(geo_router, prefix="/api/v1/geo", tags=["GeoIP"])
