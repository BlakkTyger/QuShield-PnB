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
from app.services.scheduler import start_scheduler, stop_scheduler

logger = get_logger("api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown logic."""
    logger.info("QuShield-PnB starting up...")
    # Initialize database tables if needed
    try:
        tables = init_db()
        logger.info(f"Database ready: {len(tables)} tables")
        start_scheduler()
    except Exception as e:
        logger.error(f"Database init failed: {e}")

    # ── ChromaDB: initialise singleton on the main thread (ChromaDB 1.1+ Rust binding) ──
    # All background threads must be spawned AFTER this so they reuse the cached object.
    _chroma_client = None
    try:
        from app.services.vector_store import get_chroma_client
        _chroma_client = get_chroma_client()
        if _chroma_client:
            logger.info("ChromaDB initialised on main thread.")
    except Exception as e:
        logger.warning(f"ChromaDB main-thread init failed (non-fatal): {e}")

    # Pre-warm the default embedding model (all-MiniLM-L6-v2 ONNX) in a background thread.
    # Safe now that the Rust bindings are already initialised on the main thread above.
    def _warm_embeddings():
        try:
            col = _chroma_client.get_or_create_collection("warmup-probe")
            try:
                col.add(ids=["__warmup__"], documents=["QuShield embedding warmup"])
            except Exception:
                pass  # already exists — that's fine
            col.query(query_texts=["warmup"], n_results=1)
            logger.info("ChromaDB embedding model warmed up successfully.")
        except Exception as e:
            logger.warning(f"Embedding warmup failed (non-fatal): {e}")

    if _chroma_client:
        threading.Thread(target=_warm_embeddings, daemon=True, name="embed-warmup").start()

    # Seed global knowledge base in background (non-blocking)
    def _seed_kb():
        try:
            from app.services.knowledge_seeder import seed_knowledge_base
            count = seed_knowledge_base()
            if count:
                logger.info(f"Knowledge base seeded: {count} chunks embedded.")
        except Exception as e:
            logger.warning(f"Knowledge base seeding failed (non-fatal): {e}")

    threading.Thread(target=_seed_kb, daemon=True, name="kb-seeder").start()
    yield
    stop_scheduler()
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

# CORS — allow Next.js frontend dev server and local network
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://0.0.0.0:3000",
        "http://0.0.0.0:8000",
        "*" # Allow all for production-ready simplicity in this POC, or restrict in staging
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
from app.api.v1.ai import router as ai_router
from app.api.v1.reports import router as reports_router
from app.api.v1.testssl import router as testssl_router

app.include_router(auth_router, prefix="/api/v1/auth", tags=["Auth"])
app.include_router(scans_router, prefix="/api/v1/scans", tags=["Scans"])
app.include_router(assets_router, prefix="/api/v1/assets", tags=["Assets"])
app.include_router(cbom_router, prefix="/api/v1/cbom", tags=["CBOM"])
app.include_router(risk_router, prefix="/api/v1/risk", tags=["Risk"])
app.include_router(compliance_router, prefix="/api/v1/compliance", tags=["Compliance"])
app.include_router(topology_router, prefix="/api/v1/topology", tags=["Topology"])
app.include_router(geo_router, prefix="/api/v1/geo", tags=["GeoIP"])
app.include_router(ai_router, prefix="/api/v1/ai", tags=["AI"])
app.include_router(reports_router, prefix="/api/v1/reports", tags=["Reports"])
app.include_router(testssl_router, prefix="/api/v1/testssl", tags=["TLS Inspection"])
