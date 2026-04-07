from collections.abc import AsyncIterator
from typing import Any

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

# SQLite-specific engine. Notes:
#   - check_same_thread=False is required because aiosqlite hands the
#     connection across threads internally.
#   - We don't tune pool size: SQLite is single-writer, and the default
#     pool is fine for an async app of this scale.
#   - We ensure the parent directory exists at import time so the very
#     first connection doesn't fail in a fresh checkout.
settings.sqlite_file.parent.mkdir(parents=True, exist_ok=True)

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    future=True,
    connect_args={"check_same_thread": False},
)


@event.listens_for(Engine, "connect")
def _enable_sqlite_pragmas(dbapi_connection: Any, _: Any) -> None:
    """Apply sane defaults for every SQLite connection.

    - WAL gives concurrent readers while a writer is active.
    - foreign_keys=ON is off by default in SQLite (!) and must be re-enabled.
    - NORMAL synchronous trades a tiny crash-recovery window for big writes.
    """
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
        cursor.execute("PRAGMA foreign_keys=ON")
    finally:
        cursor.close()


SessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    bind=engine,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding an AsyncSession with rollback-on-error."""
    async with SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
