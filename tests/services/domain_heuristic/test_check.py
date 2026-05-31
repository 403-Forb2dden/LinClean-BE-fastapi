from __future__ import annotations

from datetime import UTC
from unittest.mock import AsyncMock, patch

import pytest
from app.schemas.domain_heuristic import DomainHeuristicResult, DomainHeuristicSignal, RdapInfo
from app.services.domain_heuristic.check import check_domain_heuristic

_RDAP_PATH = "app.services.domain_heuristic.check.lookup_rdap"


@pytest.mark.asyncio
async def test_ip_direct_url():
    result = await check_domain_heuristic("http://192.168.1.1/login")
    assert isinstance(result, DomainHeuristicResult)
    assert DomainHeuristicSignal.IP_DIRECT in result.signals
    assert result.score == 40  # IP_DIRECT만 발동
    assert result.rdap is None  # IP면 RDAP 조회 안 함


@pytest.mark.asyncio
async def test_score_accumulates():
    # http + .xyz TLD → NO_HTTPS(20) + SUSPICIOUS_TLD(25) = 45
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (None, "not_found")
        result = await check_domain_heuristic("http://example.xyz/")

    assert DomainHeuristicSignal.NO_HTTPS in result.signals
    assert DomainHeuristicSignal.SUSPICIOUS_TLD in result.signals
    assert result.score == 45


@pytest.mark.asyncio
async def test_rdap_failure_does_not_break_pipeline():
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (None, "timeout")
        result = await check_domain_heuristic("https://example.com/")

    assert isinstance(result, DomainHeuristicResult)
    assert result.rdap is None
    assert result.rdap_error == "timeout"
    assert DomainHeuristicSignal.NEW_DOMAIN not in result.signals


@pytest.mark.asyncio
async def test_rdap_timeout_preserves_pattern_signals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def slow_rdap(_: str):
        import asyncio

        await asyncio.sleep(1)
        return None, None

    monkeypatch.setattr("app.services.domain_heuristic.check.lookup_rdap", slow_rdap)
    monkeypatch.setattr("app.services.domain_heuristic.check.settings.rdap_timeout_seconds", 0.001)

    result = await check_domain_heuristic("https://t-mobile.htufgk.top/pay/")

    assert result.rdap_error == "timeout"
    assert DomainHeuristicSignal.SUSPICIOUS_TLD in result.signals
    assert DomainHeuristicSignal.SENSITIVE_PATH in result.signals
    assert DomainHeuristicSignal.BRAND_IN_URL in result.signals
    assert result.score >= 61


@pytest.mark.asyncio
async def test_new_domain_signal_from_rdap():
    from datetime import datetime

    fake_rdap = RdapInfo(
        domain="example.com",
        registrar="TestReg",
        created_date=datetime(2026, 4, 15, tzinfo=UTC),
        expiry_date=None,
        domain_age_days=5,
        is_new_domain=True,
    )
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (fake_rdap, None)
        result = await check_domain_heuristic("https://example.com/")

    assert DomainHeuristicSignal.NEW_DOMAIN in result.signals
    assert result.rdap == fake_rdap


@pytest.mark.asyncio
async def test_result_domain_field():
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (None, "timeout")
        result = await check_domain_heuristic("https://login.naver.com/")

    assert result.domain == "naver.com"


@pytest.mark.asyncio
async def test_hosting_platform_skips_typosquatting():
    # github.io / netlify.app 같은 호스팅 플랫폼은 타이포스쿼팅 판정에서 제외돼야 함
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (None, "not_found")
        r1 = await check_domain_heuristic("https://user.github.io/repo")
        r2 = await check_domain_heuristic("https://myapp.netlify.app/")

    assert DomainHeuristicSignal.HOSTING_PLATFORM in r1.signals
    assert DomainHeuristicSignal.TYPO_DOMAIN not in r1.signals
    assert DomainHeuristicSignal.HOSTING_PLATFORM in r2.signals
    assert DomainHeuristicSignal.TYPO_DOMAIN not in r2.signals


@pytest.mark.asyncio
async def test_score_clamped_to_cap():
    # 다중 신호가 캡(80)을 넘어도 응답 score는 캡으로 고정돼야 한다.
    # http + .xyz + 4-segment subdomain + open-redirect param + 긴 라벨
    # = NO_HTTPS(30) + SUSPICIOUS_TLD(20) + SUBDOMAIN_OVERUSE(25) + OPEN_REDIRECT_PARAM(20)
    #   + HYPHEN_OVERUSE(20) = 115 → 80으로 클램프
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (None, "not_found")
        result = await check_domain_heuristic(
            "http://a.b.c.d.averylongsingledomainlabelname.xyz/?redirect=evil"
        )

    assert result.score == 80


@pytest.mark.asyncio
async def test_known_safe_domains_not_malicious():
    # 실제 정상 도메인들이 score_malicious_threshold(50) 미만으로 분류돼야 함
    safe_urls = [
        "https://bing.com/",
        "https://cnn.com/",
        "https://bbc.com/",
        "https://mit.edu/",
        "https://netflix.com/",
        "https://spotify.com/",
    ]
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (None, "not_found")
        for url in safe_urls:
            result = await check_domain_heuristic(url)
            assert result.score < 50, f"{url} score={result.score}, signals={result.signals}"


@pytest.mark.asyncio
async def test_known_safe_dga_like_domains_are_not_flagged():
    safe_urls = [
        "https://www.stackoverflow.com/",
        "https://www.postgresql.org/",
        "https://www.typescriptlang.org/",
    ]
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (None, "not_found")
        for url in safe_urls:
            result = await check_domain_heuristic(url)
            assert DomainHeuristicSignal.DGA_LIKE not in result.signals, (
                f"{url} score={result.score}, signals={result.signals}"
            )
            assert result.score < 31


@pytest.mark.asyncio
async def test_known_safe_alias_domain_is_not_typo():
    with patch(_RDAP_PATH, new_callable=AsyncMock) as mock_rdap:
        mock_rdap.return_value = (None, "not_found")
        result = await check_domain_heuristic("https://www.notion.com/")

    assert DomainHeuristicSignal.TYPO_DOMAIN not in result.signals
    assert result.score < 31
