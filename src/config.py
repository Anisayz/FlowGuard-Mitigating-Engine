import os
from functools import lru_cache
from pydantic_settings import BaseSettings

class Settings(BaseSettings):

    # ── FastAPI ───────────────────────────────────────────────────────
    APP_HOST: str =os.getenv("APP_HOST" , "0.0.0.0")
    APP_PORT: int = os.getenv("APP_PORT", "9000")
    API_KEY:  str = os.getenv("API_KEY","mitigation-engine-2026")
   
    # ── PostgreSQL ────────────────────────────────────────────────────

    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: str = os.getenv("DB_PORT", "5432")
    DB_NAME: str = os.getenv("DB_NAME", "mitigation")
    DB_PASS: str = os.getenv("DB_PASS", "mitigation")
    DATABASE_URL: str = (
        f"postgresql+asyncpg://mitigation_engine:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    )
    # ── Ryu REST API ─────────────────────────────────────────────────
    RYU_BASE_URL: str  = os.getenv("RYU_BASE_URL","http://localhost:8080")
    RYU_API_KEY:  str  = os.getenv("RYU_BASE_URL" , "sdn-lab-secret-2025")
    RYU_TIMEOUT:  float = os.getenv("RYU_TIMEOUT" , 5.0)

    # ── Deduplication / cooldown ──────────────────────────────────────

    DEDUP_COOLDOWN_S: int =  os.getenv("DEDUP_COOLDOWN" , 30)


    # ── Default flow rule timeouts ────────────────────────────────────

    DEFAULT_IDLE_TIMEOUT: int = os.getenv("DEFAULT_IDLE_TIMEOUT" , 300)
    DEFAULT_HARD_TIMEOUT: int = os.getenv("DEFAULT_HARD_TIMEOUT" , 3600)  # 1 hour

    # ── Decision engine confidence thresholds ─────────────────────────

    BRUTE_FORCE_CONF_THRESHOLD: float = os.getenv("BRUTE_FORCE_CONF_THRESHOLD" , 0.7)

    # ── Logging ───────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    return Settings()
