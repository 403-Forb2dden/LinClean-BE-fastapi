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

# aiosqlite는 스레드 간 커넥션 전달하므로 check_same_thread=False 필수.
# 데이터 디렉토리 없으면 첫 연결에서 터지니까 미리 생성.
settings.sqlite_file.parent.mkdir(parents=True, exist_ok=True)

engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    future=True,
    connect_args={"check_same_thread": False},
)


@event.listens_for(Engine, "connect")
def _enable_sqlite_pragmas(dbapi_connection: Any, _: Any) -> None:
    """WAL 모드로 동시 읽기 지원, foreign_keys=ON (SQLite 기본값은 OFF)."""
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
    """AsyncSession 제공. 미처리 예외 시 롤백."""
    async with SessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
