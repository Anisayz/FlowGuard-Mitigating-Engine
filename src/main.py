import logging
import sys
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src.config import get_settings
from src.db.database import create_tables

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

    await create_tables()
    log.info("Database tables ready")

    yield


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


# ── Global exception handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    log.error("Unhandled exception on %s: %s", request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content={"error": "internal server error", "detail": str(exc)},
    )



# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "src.main:app",
        host=settings.APP_HOST,
        port=settings.APP_PORT,
        reload=False,
        log_level=settings.LOG_LEVEL.lower(),
    )