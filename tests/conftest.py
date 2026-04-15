"""공용 테스트 픽스처."""

from __future__ import annotations

from collections.abc import AsyncIterator

# 모델 로드 (metadata 등록용)
import app.models  # noqa: F401
import pytest
import pytest_asyncio
from app.core.config import settings
from app.db.base import Base
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


@pytest.fixture(autouse=True)
def _disable_scheduler(monkeypatch: pytest.MonkeyPatch) -> None:
    """테스트에서는 APScheduler 기동 금지."""
    monkeypatch.setattr(settings, "scheduler_enabled", False)


@pytest_asyncio.fixture
async def async_session() -> AsyncIterator[AsyncSession]:
    """인메모리 SQLite 세션 — 테스트마다 새 DB."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(
        bind=engine, expire_on_commit=False, autoflush=False
    )
    async with session_maker() as session:
        yield session

    await engine.dispose()
