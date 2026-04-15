"""URLhaus 동기화 단위 테스트 — 인메모리 SQLite + httpx 픽스처."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from app.db.base import Base
from app.models.urlhaus_entry import URLhausEntry
from app.services.threat_db import urlhaus_sync as sync_module
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

SAMPLE_CSV = """# URLhaus recent URLs
# id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
1,2026-04-14 00:00:00,https://evil.test/a.exe,online,,malware_download,"exe,emotet",https://urlhaus.abuse.ch/url/1/,tester
2,2026-04-14 00:05:00,https://github.com/bad/repo/raw/main/x.sh,online,,malware_download,"sh",https://urlhaus.abuse.ch/url/2/,tester
"""


@pytest.fixture
async def sync_engine_patch(monkeypatch: pytest.MonkeyPatch):
    """SessionLocal 을 인메모리 DB 로 치환."""
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(sync_module, "SessionLocal", maker)
    yield maker
    await engine.dispose()


def _mock_csv_response(text: str, status: int = 200) -> AsyncMock:
    resp = httpx.Response(
        status, text=text, request=httpx.Request("GET", "https://x/"),
    )
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get = AsyncMock(return_value=resp)
    return client


async def test_sync_inserts_rows(sync_engine_patch) -> None:
    with patch(
        "app.services.threat_db.urlhaus_sync.httpx.AsyncClient",
        return_value=_mock_csv_response(SAMPLE_CSV),
    ):
        stats = await sync_module.sync_urlhaus()

    assert stats["total"] == 2
    assert stats["inserted"] + stats["updated"] == 2
    assert stats["failed"] == 0

    async with sync_engine_patch() as session:
        rows = (await session.execute(select(URLhausEntry))).scalars().all()
    assert len(rows) == 2
    by_id = {r.id: r for r in rows}
    assert by_id[1].host == "evil.test"
    assert by_id[1].match_key == "evil.test"
    assert by_id[2].match_key == "github.com/bad/repo"


async def test_sync_idempotent(sync_engine_patch) -> None:
    with patch(
        "app.services.threat_db.urlhaus_sync.httpx.AsyncClient",
        return_value=_mock_csv_response(SAMPLE_CSV),
    ):
        await sync_module.sync_urlhaus()
        stats2 = await sync_module.sync_urlhaus()

    # 재실행 시 row 수 유지 — upsert 가 insert 중복 없이 동작.
    async with sync_engine_patch() as session:
        rows = (await session.execute(select(URLhausEntry))).scalars().all()
    assert len(rows) == 2
    assert stats2["total"] == 2


async def test_sync_network_failure_returns_empty_stats(
    sync_engine_patch,
) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get = AsyncMock(side_effect=httpx.HTTPError("net"))
    with patch(
        "app.services.threat_db.urlhaus_sync.httpx.AsyncClient", return_value=client
    ):
        stats = await sync_module.sync_urlhaus()
    assert stats["total"] == 0
    assert stats["inserted"] == 0
