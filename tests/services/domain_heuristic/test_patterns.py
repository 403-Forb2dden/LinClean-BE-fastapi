from __future__ import annotations

from app.schemas.domain_heuristic import DomainHeuristicSignal
from app.services.domain_heuristic.patterns import check_patterns


def test_ip_direct_ipv4() -> None:
    signals = check_patterns("http://192.168.1.1/login")
    assert DomainHeuristicSignal.IP_DIRECT in signals


def test_ip_direct_ipv6() -> None:
    signals = check_patterns("http://[::1]/login")
    assert DomainHeuristicSignal.IP_DIRECT in signals


def test_ip_direct_returns_only_ip_signal() -> None:
    # IP 감지 시 다른 도메인 신호는 분석하지 않음
    signals = check_patterns("http://192.168.1.1/login?redirect=evil")
    assert signals == [DomainHeuristicSignal.IP_DIRECT]


def test_no_https() -> None:
    signals = check_patterns("http://example.com/")
    assert DomainHeuristicSignal.NO_HTTPS in signals


def test_https_no_flag() -> None:
    signals = check_patterns("https://example.com/")
    assert DomainHeuristicSignal.NO_HTTPS not in signals


def test_subdomain_overuse() -> None:
    signals = check_patterns("https://a.b.c.d.example.com/")
    assert DomainHeuristicSignal.SUBDOMAIN_OVERUSE in signals


def test_subdomain_normal() -> None:
    signals = check_patterns("https://login.naver.com/")
    assert DomainHeuristicSignal.SUBDOMAIN_OVERUSE not in signals


def test_punycode_idn() -> None:
    signals = check_patterns("https://xn--naver-zk5b.com/")
    assert DomainHeuristicSignal.PUNYCODE_IDN in signals


def test_hyphen_overuse_count() -> None:
    signals = check_patterns("https://login-secure-naver-auth.com/")
    assert DomainHeuristicSignal.HYPHEN_OVERUSE in signals


def test_hyphen_overuse_length() -> None:
    # 20자 이상 레이블 → HYPHEN_OVERUSE 발동
    signals = check_patterns("https://averylongsingledomainlabelname.com/")
    assert DomainHeuristicSignal.HYPHEN_OVERUSE in signals


def test_no_hyphen_overuse() -> None:
    signals = check_patterns("https://naver.com/")
    assert DomainHeuristicSignal.HYPHEN_OVERUSE not in signals


def test_suspicious_tld_xyz() -> None:
    signals = check_patterns("https://example.xyz/")
    assert DomainHeuristicSignal.SUSPICIOUS_TLD in signals


def test_suspicious_tld_zip() -> None:
    signals = check_patterns("https://example.zip/")
    assert DomainHeuristicSignal.SUSPICIOUS_TLD in signals


def test_normal_tld() -> None:
    signals = check_patterns("https://example.com/")
    assert DomainHeuristicSignal.SUSPICIOUS_TLD not in signals


def test_open_redirect_param() -> None:
    signals = check_patterns("https://example.com/login?redirect=http://evil.com")
    assert DomainHeuristicSignal.OPEN_REDIRECT_PARAM in signals


def test_open_redirect_param_url() -> None:
    signals = check_patterns("https://example.com/go?url=http://evil.com")
    assert DomainHeuristicSignal.OPEN_REDIRECT_PARAM in signals


def test_no_open_redirect_param() -> None:
    signals = check_patterns("https://example.com/search?q=hello")
    assert DomainHeuristicSignal.OPEN_REDIRECT_PARAM not in signals


def test_hosting_platform_netlify() -> None:
    signals = check_patterns("https://myapp.netlify.app/")
    assert DomainHeuristicSignal.HOSTING_PLATFORM in signals


def test_hosting_platform_github_io() -> None:
    signals = check_patterns("https://user.github.io/repo")
    assert DomainHeuristicSignal.HOSTING_PLATFORM in signals


def test_normal_domain_no_hosting_flag() -> None:
    signals = check_patterns("https://naver.com/")
    assert DomainHeuristicSignal.HOSTING_PLATFORM not in signals


def test_hosting_platform_root_not_flagged() -> None:
    # 플랫폼 자체 홈페이지는 HOSTING_PLATFORM 미발동
    signals = check_patterns("https://netlify.com/")
    assert DomainHeuristicSignal.HOSTING_PLATFORM not in signals
