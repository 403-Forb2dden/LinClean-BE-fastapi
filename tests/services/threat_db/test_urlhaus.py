"""URLhaus 조회 단위 테스트 — 인메모리 SQLite 시딩."""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, patch

from app.models.urlhaus_entry import URLhausEntry
from app.services.threat_db.urlhaus import check_urlhaus
from sqlalchemy.ext.asyncio import AsyncSession


async def _seed(session: AsyncSession, **kwargs) -> None:
    defaults = {
        "threat": "malware_download",
        "tags": "exe,emotet",
        "url_status": "online",
        "date_added": datetime(2026, 4, 10, 0, 0, 0),
        "last_online": None,
        "urlhaus_link": "https://urlhaus.abuse.ch/url/1/",
        "reporter": "tester",
        "synced_at": datetime(2026, 4, 15, 0, 0, 0),
    }
    defaults.update(kwargs)
    session.add(URLhausEntry(**defaults))
    await session.flush()


async def test_exact_url_match(async_session: AsyncSession) -> None:
    await _seed(
        async_session,
        id=1,
        url="https://evil.test/malware.exe",
        host="evil.test",
        match_key="evil.test",
    )
    result = await check_urlhaus(async_session, "https://evil.test/malware.exe")
    assert result.is_threat is True
    assert result.match_type == "url"
    assert result.threat == "malware_download"
    assert result.tags == ["exe", "emotet"]


async def test_host_match(async_session: AsyncSession) -> None:
    await _seed(
        async_session,
        id=2,
        url="https://evil.test/other.bin",
        host="evil.test",
        match_key="evil.test",
    )
    result = await check_urlhaus(async_session, "https://evil.test/something-else")
    assert result.is_threat is True
    assert result.match_type == "host"
    assert result.matched_key == "evil.test"


async def test_host_path_match_github(async_session: AsyncSession) -> None:
    await _seed(
        async_session,
        id=3,
        url="https://github.com/bad/repo/raw/main/x.exe",
        host="github.com",
        match_key="github.com/bad/repo",
    )
    result = await check_urlhaus(async_session, "https://github.com/bad/repo/issues/1")
    assert result.is_threat is True
    assert result.match_type == "host_path"
    assert result.matched_key == "github.com/bad/repo"


async def test_multitenant_host_does_not_match_host_only_entry(
    async_session: AsyncSession,
) -> None:
    await _seed(
        async_session,
        id=6,
        url="https://www.dropbox.com/scl/fi/bad/payload.exe",
        host="www.dropbox.com",
        match_key="www.dropbox.com",
    )

    result = await check_urlhaus(async_session, "https://www.dropbox.com/")

    assert result.checked is True
    assert result.is_threat is False


async def test_multitenant_host_path_match_dropbox(async_session: AsyncSession) -> None:
    await _seed(
        async_session,
        id=7,
        url="https://www.dropbox.com/scl/fi/bad/payload.exe",
        host="www.dropbox.com",
        match_key="www.dropbox.com/scl/fi",
    )

    result = await check_urlhaus(
        async_session,
        "https://www.dropbox.com/scl/fi/bad/readme.txt",
    )

    assert result.is_threat is True
    assert result.match_type == "host_path"
    assert result.matched_key == "www.dropbox.com/scl/fi"


async def test_no_match(async_session: AsyncSession) -> None:
    result = await check_urlhaus(async_session, "https://clean.test/")
    assert result.checked is True
    assert result.is_threat is False


async def test_db_error_returns_checked_false(async_session: AsyncSession) -> None:
    from sqlalchemy.exc import SQLAlchemyError

    with patch.object(async_session, "execute", AsyncMock(side_effect=SQLAlchemyError("boom"))):
        result = await check_urlhaus(async_session, "https://x.test/")
    assert result.checked is False
    assert result.error == "db_error"
