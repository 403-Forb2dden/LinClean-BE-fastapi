"""check_threat_db 병렬 조회·폴백 검증."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from app.schemas.analysis import GSBMatch, GSBResult, URLhausResult
from app.services.threat_db.check import check_threat_db
from sqlalchemy.ext.asyncio import AsyncSession


async def _run(
    session: AsyncSession,
    gsb: GSBResult,
    urlhaus: URLhausResult,
    url: str = "https://x.test/",
):
    with (
        patch("app.services.threat_db.check.check_gsb", AsyncMock(return_value=gsb)),
        patch(
            "app.services.threat_db.check.check_urlhaus",
            AsyncMock(return_value=urlhaus),
        ),
    ):
        return await check_threat_db(session, url)


async def test_both_clean(async_session: AsyncSession) -> None:
    result = await _run(
        async_session,
        GSBResult(checked=True, is_threat=False),
        URLhausResult(checked=True, is_threat=False),
    )
    assert result.is_malicious is False
    assert result.sources_checked == 2
    assert result.threat_types == []


async def test_gsb_hit_marks_malicious(async_session: AsyncSession) -> None:
    gsb = GSBResult(
        checked=True,
        is_threat=True,
        matches=[GSBMatch(threat_type="MALWARE")],
    )
    result = await _run(
        async_session,
        gsb,
        URLhausResult(checked=True, is_threat=False),
    )
    assert result.is_malicious is True
    assert "MALWARE" in result.threat_types


async def test_urlhaus_hit_with_gsb_error(async_session: AsyncSession) -> None:
    """GSB 실패 + URLhaus 히트 → 여전히 malicious 판정."""
    result = await _run(
        async_session,
        GSBResult(checked=False, is_threat=False, error="timeout"),
        URLhausResult(
            checked=True,
            is_threat=True,
            match_type="host",
            matched_key="evil.test",
            threat="malware_download",
        ),
    )
    assert result.is_malicious is True
    assert result.sources_checked == 1
    assert "malware_download" in result.threat_types


async def test_both_fail_returns_clean_zero_sources(
    async_session: AsyncSession,
) -> None:
    result = await _run(
        async_session,
        GSBResult(checked=False, is_threat=False, error="timeout"),
        URLhausResult(checked=False, is_threat=False, error="db_error"),
    )
    assert result.is_malicious is False
    assert result.sources_checked == 0


async def test_exception_is_caught(async_session: AsyncSession) -> None:
    with (
        patch(
            "app.services.threat_db.check.check_gsb",
            AsyncMock(side_effect=RuntimeError("boom")),
        ),
        patch(
            "app.services.threat_db.check.check_urlhaus",
            AsyncMock(return_value=URLhausResult(checked=True, is_threat=False)),
        ),
    ):
        result = await check_threat_db(async_session, "https://x.test/")
    assert result.gsb.checked is False
    assert result.gsb.error == "unexpected"
    assert result.sources_checked == 1


async def test_cancelled_error_propagates(async_session: AsyncSession) -> None:
    # 상위 shutdown/timeout 신호(CancelledError)는 절대 삼키지 않는다.
    with (
        patch(
            "app.services.threat_db.check.check_gsb",
            AsyncMock(side_effect=asyncio.CancelledError()),
        ),
        patch(
            "app.services.threat_db.check.check_urlhaus",
            AsyncMock(return_value=URLhausResult(checked=True, is_threat=False)),
        ),
        pytest.raises(asyncio.CancelledError),
    ):
        await check_threat_db(async_session, "https://x.test/")
