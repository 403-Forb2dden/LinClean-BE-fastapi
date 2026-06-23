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


def test_same_registered_domain_redirect_param_is_not_open_redirect_signal() -> None:
    signals = check_patterns(
        "https://link.naver.com/bridge?"
        "url=https%3A%2F%2Fm.naver.com%2Fshorts%2F%3FserviceType%3DCHZZK"
    )
    assert DomainHeuristicSignal.OPEN_REDIRECT_PARAM not in signals


def test_external_redirect_param_on_trusted_domain_remains_open_redirect_signal() -> None:
    signals = check_patterns("https://link.naver.com/bridge?url=https%3A%2F%2Fevil.test%2F")
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


def test_private_suffix_user_space_without_subdomain_is_hosting_platform() -> None:
    signals = check_patterns("https://datrucsmain.wasmer.app/")
    assert DomainHeuristicSignal.HOSTING_PLATFORM in signals


def test_normal_domain_no_hosting_flag() -> None:
    signals = check_patterns("https://naver.com/")
    assert DomainHeuristicSignal.HOSTING_PLATFORM not in signals


def test_hosting_platform_root_not_flagged() -> None:
    # 플랫폼 자체 홈페이지는 HOSTING_PLATFORM 미발동
    signals = check_patterns("https://netlify.com/")
    assert DomainHeuristicSignal.HOSTING_PLATFORM not in signals


def test_userinfo_is_high_risk_url_signal() -> None:
    signals = check_patterns("https://google.com@evil-login.example.com/session")
    assert DomainHeuristicSignal.URL_USERINFO in signals


def test_brand_in_untrusted_url_is_signal() -> None:
    signals = check_patterns("https://amazon-clone-kappa-ashen.vercel.app/login")
    assert DomainHeuristicSignal.BRAND_IN_URL in signals
    assert DomainHeuristicSignal.FREE_HOSTING_LURE in signals


def test_shortener_is_signal() -> None:
    signals = check_patterns("https://qrco.de/bgoz9a")
    assert DomainHeuristicSignal.URL_SHORTENER in signals


def test_trusted_brand_login_path_not_sensitive_path() -> None:
    signals = check_patterns("https://naver.com/login")
    assert DomainHeuristicSignal.SENSITIVE_PATH not in signals


def test_generic_brand_labels_do_not_flag_public_normal_sites() -> None:
    assert DomainHeuristicSignal.BRAND_IN_URL not in check_patterns("https://www.nasa.gov/")
    assert DomainHeuristicSignal.BRAND_IN_URL not in check_patterns("https://apnews.com/")


def test_openphish_like_brand_on_private_hosting_is_lure() -> None:
    signals = check_patterns("https://www.findmyiphone.vercel.app/")
    assert DomainHeuristicSignal.HOSTING_PLATFORM in signals
    assert DomainHeuristicSignal.BRAND_IN_URL in signals
    assert DomainHeuristicSignal.FREE_HOSTING_LURE in signals


def test_sensitive_login_path_on_untrusted_domain_is_signal() -> None:
    signals = check_patterns("https://www.driegang.nl/new-fr-societegenerale/sg/login/fr/login.php")
    assert DomainHeuristicSignal.SENSITIVE_PATH in signals
    assert DomainHeuristicSignal.BRAND_IN_URL in signals


def test_tmobile_pay_on_suspicious_tld_is_high_signal() -> None:
    signals = check_patterns("https://t-mobile.htufgk.top/pay/")
    assert DomainHeuristicSignal.SUSPICIOUS_TLD in signals
    assert DomainHeuristicSignal.SENSITIVE_PATH in signals
    assert DomainHeuristicSignal.BRAND_IN_URL in signals


def test_cfd_and_help_are_suspicious_tlds() -> None:
    assert DomainHeuristicSignal.SUSPICIOUS_TLD in check_patterns("https://dpd.yzqpkmr.cfd/com/")
    assert DomainHeuristicSignal.SUSPICIOUS_TLD in check_patterns(
        "https://t-mobile.converselidom.help/pay/"
    )
