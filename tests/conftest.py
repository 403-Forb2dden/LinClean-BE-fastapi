"""공용 테스트 픽스처."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING

os.environ.setdefault("TLDEXTRACT_CACHE", "/private/tmp/linclean-tldextract-cache")

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


@pytest.fixture(autouse=True)
def _disable_scheduler(monkeypatch: pytest.MonkeyPatch) -> None:
    """테스트에서는 APScheduler 기동 금지."""
    from app.core.config import settings

    monkeypatch.setattr(settings, "scheduler_enabled", False)


@pytest_asyncio.fixture
async def async_session() -> AsyncIterator[AsyncSession]:
    """인메모리 SQLite 세션 — 테스트마다 새 DB."""
    # 모델 로드는 DB fixture 가 필요한 테스트에서만 수행한다.
    import app.models  # noqa: F401
    from app.db.base import Base
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    async with session_maker() as session:
        yield session

    await engine.dispose()
