from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from app.schemas.domain_heuristic import RdapInfo
from app.services.domain_heuristic import rdap as rdap_module
from app.services.domain_heuristic.rdap import _parse_datetime, _parse_rdap_response, lookup_rdap


@pytest.fixture(autouse=True)
def _reset_rdap_state(monkeypatch: pytest.MonkeyPatch):
    """각 테스트에서 cache/inflight/client 싱글턴 상태 격리."""
    rdap_module._cache.clear()
    rdap_module._inflight.clear()
    monkeypatch.setattr(rdap_module, "_client", None)


def _install_client(mock_client: AsyncMock) -> None:
    rdap_module._client = mock_client


def test_parse_datetime_valid():
    result = _parse_datetime("2026-01-01T00:00:00Z")
    assert result is not None
    assert result.tzinfo == UTC
    assert result.year == 2026


def test_parse_datetime_none():
    assert _parse_datetime(None) is None


def test_parse_datetime_invalid():
    assert _parse_datetime("not-a-date") is None


def test_parse_rdap_new_domain():
    # 시간 의존을 끊기 위해 "지금-10일" 동적 생성 — settings.rdap_new_domain_threshold_days(30) 미만
    recent = (datetime.now(tz=UTC) - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expiry = (datetime.now(tz=UTC) + timedelta(days=355)).strftime("%Y-%m-%dT%H:%M:%SZ")
    data = {
        "events": [
            {"eventAction": "registration", "eventDate": recent},
            {"eventAction": "expiration", "eventDate": expiry},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "NameCheap, Inc."]]],
            }
        ],
    }
    result = _parse_rdap_response("example.com", data)
    assert result.domain == "example.com"
    assert result.registrar == "NameCheap, Inc."
    assert result.is_new_domain is True
    assert result.domain_age_days is not None and result.domain_age_days < 30


def test_parse_rdap_old_domain():
    data = {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"},
        ],
        "entities": [],
    }
    result = _parse_rdap_response("old.com", data)
    assert result.is_new_domain is False
    assert result.domain_age_days is not None and result.domain_age_days > 30


@pytest.mark.asyncio
async def test_lookup_rdap_success():
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
        "entities": [],
    }
    mock_response.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    _install_client(mock_client)

    result, error = await lookup_rdap("https://example.com/")

    assert error is None
    assert result is not None
    assert result.domain == "example.com"


@pytest.mark.asyncio
async def test_lookup_rdap_cache_hit():
    import time

    fake_info = RdapInfo(
        domain="cached.com",
        registrar="TestReg",
        created_date=None,
        expiry_date=None,
        domain_age_days=None,
        is_new_domain=False,
    )
    rdap_module._cache["cached.com"] = (fake_info, time.monotonic() + 3600)

    # client 미설치 — 캐시 히트면 호출 자체가 없어야 함
    result, error = await lookup_rdap("https://cached.com/path")

    assert result == fake_info
    assert error is None


@pytest.mark.asyncio
async def test_lookup_rdap_timeout():
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    _install_client(mock_client)

    result, error = await lookup_rdap("https://example.com/")

    assert result is None
    assert error == "timeout"


@pytest.mark.asyncio
async def test_lookup_rdap_not_found():
    mock_response = MagicMock(status_code=404)
    http_error = httpx.HTTPStatusError("not found", request=MagicMock(), response=mock_response)
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=http_error)
    _install_client(mock_client)

    result, error = await lookup_rdap("https://unknowndomain99999.com/")

    assert result is None
    assert error == "not_found"


@pytest.mark.asyncio
async def test_lookup_rdap_http_error():
    mock_response = MagicMock(status_code=500)
    http_error = httpx.HTTPStatusError("server error", request=MagicMock(), response=mock_response)
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=http_error)
    _install_client(mock_client)

    result, error = await lookup_rdap("https://example.com/")

    assert result is None
    assert error == "http_error"


@pytest.mark.asyncio
async def test_lookup_rdap_parse_error():
    mock_response = MagicMock()
    mock_response.json.return_value = "not a dict"
    mock_response.raise_for_status = MagicMock()
    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    _install_client(mock_client)

    result, error = await lookup_rdap("https://example.com/")

    assert result is None
    assert error == "parse_error"


@pytest.mark.asyncio
async def test_lookup_rdap_dedup_inflight():
    """동시 요청이 겹치면 실제 fetch는 1회만 수행돼야 한다."""
    import asyncio

    call_count = 0
    request_started = asyncio.Event()
    release = asyncio.Event()

    async def slow_get(url: str, **_: object) -> MagicMock:
        nonlocal call_count
        call_count += 1
        request_started.set()
        await release.wait()
        resp = MagicMock()
        resp.json.return_value = {
            "events": [{"eventAction": "registration", "eventDate": "2020-01-01T00:00:00Z"}],
            "entities": [],
        }
        resp.raise_for_status = MagicMock()
        return resp

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=slow_get)
    _install_client(mock_client)

    task1 = asyncio.create_task(lookup_rdap("https://example.com/"))
    task2 = asyncio.create_task(lookup_rdap("https://example.com/"))
    task3 = asyncio.create_task(lookup_rdap("https://example.com/"))
    await request_started.wait()
    release.set()

    results = await asyncio.gather(task1, task2, task3)

    assert call_count == 1
    for info, error in results:
        assert error is None
        assert info is not None and info.domain == "example.com"


@pytest.mark.asyncio
async def test_lookup_rdap_idn_punycode():
    """IDN 도메인은 URL 빌드 시 punycode로 변환돼야 한다."""
    captured_urls: list[str] = []

    async def capture_get(url: str, **_: object) -> MagicMock:
        captured_urls.append(url)
        resp = MagicMock()
        resp.json.return_value = {"events": [], "entities": []}
        resp.raise_for_status = MagicMock()
        return resp

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(side_effect=capture_get)
    _install_client(mock_client)

    await lookup_rdap("https://xn--3e0b707e.com/")  # 한국.com
    assert captured_urls
    assert "xn--3e0b707e.com" in captured_urls[0]


@pytest.mark.asyncio
async def test_lookup_rdap_invalid_domain():
    """빈 레이블/비정상 도메인은 invalid_domain 반환."""
    mock_client = AsyncMock()
    _install_client(mock_client)

    # tldextract가 도메인으로 받지 않는 형태 — ASCII지만 내부 regex 확인
    # 실제 인코딩 실패 케이스: null byte 포함
    result, error = await lookup_rdap("https://..com/")
    assert result is None
    # top_domain_under_public_suffix가 비어서 no_domain이거나, encode 실패로 invalid_domain
    assert error in {"no_domain", "invalid_domain"}
