"""
main.py — FastAPI entrypoint for the Mitigation Engine.

Start:
    uvicorn src.main:app --host 0.0.0.0 --port 9000 --reload

Swagger UI (auto-generated):
    http://localhost:9000/docs

What happens at startup (lifespan):
  1. Create DB tables if they don't exist (dev convenience).
     In production use: alembic upgrade head
  2. Log config summary so you can see what's active at a glance.

What happens at shutdown:
  1. Close the Ryu HTTP client connection pool cleanly.
"""

import logging
import secrets
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.config import get_settings
from src.db.database import create_tables
from src.actions.ryu_client import close_client
from src.api.alert import router as alert_router
from src.api.rules import router as rules_router
from src.api.health import health_router, alerts_router

settings = get_settings()

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)-30s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
log = logging.getLogger(__name__)


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("=== Mitigation Engine starting ===")
    log.info("  DB URL   : %s", settings.DATABASE_URL[:40] + "...")
    log.info("  Ryu URL  : %s", settings.RYU_BASE_URL)
    log.info("  Port     : %d", settings.APP_PORT)
    log.info("  Cooldown : %ds", settings.DEDUP_COOLDOWN_S)

    # Create DB tables on startup (dev mode)
    await create_tables()
    log.info("Database tables ready")

    yield

    # Shutdown
    await close_client()
    log.info("=== Mitigation Engine stopped ===")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Mitigation Engine",
    description=(
        "SDN-based intelligent network security platform — Mitigation Engine. "
        "Receives alerts from ML engine and IDS, decides mitigation actions, "
        "installs OpenFlow rules via Ryu, and persists everything to PostgreSQL."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Auth middleware ───────────────────────────────────────────────────────────
@app.middleware("http")
async def check_api_key(request: Request, call_next):
    """
    Validate X-API-Key header on all requests except /health and /docs.
    """
    skip_prefixes = ("/health", "/docs", "/openapi.json", "/redoc")
    if request.url.path.startswith(skip_prefixes):
        return await call_next(request)
    if not settings.API_KEY:
        return await call_next(request)   # auth disabled

    key = request.headers.get("X-API-Key", "")
    if not secrets.compare_digest(key, settings.API_KEY):
        return JSONResponse(
            status_code=401,
            content={"error": "unauthorized — invalid X-API-Key"},
        )
    return await call_next(request)


# ── Global exception handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("Unhandled exception on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"error": "internal server error", "detail": str(exc)},
    )


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(alert_router)
app.include_router(rules_router)
app.include_router(health_router)
app.include_router(alerts_router)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
    )