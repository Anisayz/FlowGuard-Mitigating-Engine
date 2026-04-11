from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from src.config import get_settings

settings = get_settings()

# Async engine — asyncpg driver handles the connection pool
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,          # set True to log all SQL queries (useful for debugging)
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,  # test connections before using them (handles restarts)
)

# Session factory — every request gets a fresh session
AsyncSessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,   # keep objects accessible after commit
    autocommit=False,
    autoflush=False,
)


class Base(DeclarativeBase):

    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_tables():
    from src.db import models  # noqa: F401 — import triggers model registration
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)