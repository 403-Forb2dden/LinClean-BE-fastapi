"""GSB check_gsb 단위 테스트 — httpx 모킹으로 각 실패 분기 검증."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest
from app.core.config import settings
from app.services.threat_db import gsb as gsb_module
from app.services.threat_db.gsb import check_gsb


@pytest.fixture(autouse=True)
def _with_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "gsb_api_key", "test-key")
    # "키 값별 1회 경고" throttle 초기화 — 테스트 간 상태 누수 방지.
    gsb_module.reset_missing_key_warning()


def _mock_post_response(resp: httpx.Response) -> AsyncMock:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post = AsyncMock(return_value=resp)
    return client


async def test_no_api_key_returns_not_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "gsb_api_key", None)
    result = await check_gsb("https://example.com")
    assert result.checked is False
    assert result.error == "not_configured"


async def test_match_returns_is_threat() -> None:
    body = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "cacheDuration": "300s",
            }
        ]
    }
    resp = httpx.Response(200, json=body, request=httpx.Request("POST", "x"))
    with patch(
        "app.services.threat_db.gsb.httpx.AsyncClient",
        return_value=_mock_post_response(resp),
    ):
        result = await check_gsb("https://evil.test/")
    assert result.checked is True
    assert result.is_threat is True
    assert result.matches[0].threat_type == "MALWARE"


async def test_no_match_returns_safe() -> None:
    resp = httpx.Response(200, json={}, request=httpx.Request("POST", "x"))
    with patch(
        "app.services.threat_db.gsb.httpx.AsyncClient",
        return_value=_mock_post_response(resp),
    ):
        result = await check_gsb("https://safe.test/")
    assert result.checked is True
    assert result.is_threat is False
    assert result.matches == []


async def test_timeout_mapped_to_error() -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
    with patch("app.services.threat_db.gsb.httpx.AsyncClient", return_value=client):
        result = await check_gsb("https://x.test/")
    assert result.checked is False
    assert result.error == "timeout"


@pytest.mark.parametrize(
    "status,expected",
    [
        (400, "auth_error"),
        (401, "auth_error"),
        (403, "auth_error"),
        (429, "rate_limited"),
        (500, "server_error_500"),
        (503, "server_error_503"),
    ],
)
async def test_http_status_errors(status: int, expected: str) -> None:
    resp = httpx.Response(status, request=httpx.Request("POST", "x"))
    with patch(
        "app.services.threat_db.gsb.httpx.AsyncClient",
        return_value=_mock_post_response(resp),
    ):
        result = await check_gsb("https://x.test/")
    assert result.checked is False
    assert result.error == expected


async def test_invalid_json() -> None:
    resp = httpx.Response(200, content=b"not json", request=httpx.Request("POST", "x"))
    with patch(
        "app.services.threat_db.gsb.httpx.AsyncClient",
        return_value=_mock_post_response(resp),
    ):
        result = await check_gsb("https://x.test/")
    assert result.checked is False
    assert result.error == "invalid_response"


async def test_unmapped_non_200_returns_http_error() -> None:
    # 3xx/기타 비매핑 상태코드는 스펙대로 "http_error" 로 평탄화된다.
    resp = httpx.Response(301, request=httpx.Request("POST", "x"))
    with patch(
        "app.services.threat_db.gsb.httpx.AsyncClient",
        return_value=_mock_post_response(resp),
    ):
        result = await check_gsb("https://x.test/")
    assert result.checked is False
    assert result.error == "http_error"


async def test_missing_key_warning_throttled_per_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 같은 키 상태로 두 번 호출해도 경고는 1회. 키 값이 바뀌면 다시 1회.
    warnings: list[str] = []
    monkeypatch.setattr(settings, "gsb_api_key", None)
    gsb_module.reset_missing_key_warning()
    monkeypatch.setattr(gsb_module.logger, "warning", lambda event, **kw: warnings.append(event))
    await check_gsb("https://x.test/")
    await check_gsb("https://y.test/")
    assert warnings.count("gsb.api_key_not_configured") == 1


async def test_generic_http_error() -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.__aexit__.return_value = None
    client.post = AsyncMock(side_effect=httpx.HTTPError("boom"))
    with patch("app.services.threat_db.gsb.httpx.AsyncClient", return_value=client):
        result = await check_gsb("https://x.test/")
    assert result.checked is False
    assert result.error == "http_error"
