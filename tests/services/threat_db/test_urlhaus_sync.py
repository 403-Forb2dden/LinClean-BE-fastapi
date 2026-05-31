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
3,2026-04-14 00:10:00,https://www.dropbox.com/scl/fi/bad/payload.exe,online,,malware_download,"exe",https://urlhaus.abuse.ch/url/3/,tester
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
        status,
        text=text,
        request=httpx.Request("GET", "https://x/"),
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

    # 최초 실행 — 모두 insert, update 는 0 이어야 한다(C1 회귀 방지).
    assert stats["total"] == 3
    assert stats["inserted"] == 3
    assert stats["updated"] == 0
    assert stats["failed"] == 0

    async with sync_engine_patch() as session:
        rows = (await session.execute(select(URLhausEntry))).scalars().all()
    assert len(rows) == 3
    by_id = {r.id: r for r in rows}
    assert by_id[1].host == "evil.test"
    assert by_id[1].match_key == "evil.test"
    assert by_id[2].match_key == "github.com/bad/repo"
    assert by_id[3].match_key == "www.dropbox.com/scl/fi"


async def test_sync_idempotent(sync_engine_patch) -> None:
    with patch(
        "app.services.threat_db.urlhaus_sync.httpx.AsyncClient",
        return_value=_mock_csv_response(SAMPLE_CSV),
    ):
        await sync_module.sync_urlhaus()
        stats2 = await sync_module.sync_urlhaus()

    # 두 번째 실행은 모두 update 여야 한다 — insert/update 분류가 맞는지 검증.
    async with sync_engine_patch() as session:
        rows = (await session.execute(select(URLhausEntry))).scalars().all()
    assert len(rows) == 3
    assert stats2["total"] == 3
    assert stats2["inserted"] == 0
    assert stats2["updated"] == 3
    assert stats2["failed"] == 0


async def test_sync_short_row_counts_failed(sync_engine_patch) -> None:
    # 필드 수가 모자라는 행은 스킵하되 failed 로 카운트되어야 한다(I6).
    bad_csv = (
        "# header comment\n"
        "1,2026-04-14 00:00:00,https://evil.test/a.exe\n"  # 필드 부족
        '2,2026-04-14 00:05:00,https://good.test/b,online,,malware_download,"",'
        "https://urlhaus.abuse.ch/url/2/,tester\n"
    )
    with patch(
        "app.services.threat_db.urlhaus_sync.httpx.AsyncClient",
        return_value=_mock_csv_response(bad_csv),
    ):
        stats = await sync_module.sync_urlhaus()
    assert stats["total"] == 2
    assert stats["failed"] == 1
    assert stats["inserted"] == 1


async def test_sync_network_failure_returns_empty_stats(
    sync_engine_patch,
) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.get = AsyncMock(side_effect=httpx.HTTPError("net"))
    with patch("app.services.threat_db.urlhaus_sync.httpx.AsyncClient", return_value=client):
        stats = await sync_module.sync_urlhaus()
    assert stats["total"] == 0
    assert stats["inserted"] == 0
