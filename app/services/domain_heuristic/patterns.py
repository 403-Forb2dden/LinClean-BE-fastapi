from __future__ import annotations

import ipaddress
from urllib.parse import parse_qs, urlparse

from app.core.config import settings
from app.core.tld import extract_url_parts
from app.schemas.domain_heuristic import DomainHeuristicSignal

_SUSPICIOUS_TLDS = frozenset(
    {
        "zip",
        "mov",
        "xyz",
        "top",
        "pw",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "fit",
        "work",
        "surf",
        "click",
        "link",
        "loan",
        "download",
        "stream",
        "racing",
        "review",
        "trade",
        "win",
        "bid",
        "party",
        "date",
        "faith",
        "science",
        "cricket",
        "accountant",
        "men",
    }
)

HOSTING_PLATFORMS = frozenset(
    {
        "netlify.app",
        "vercel.app",
        "pages.dev",
        "github.io",
        "gitlab.io",
        "web.app",
        "firebaseapp.com",
        "amazonaws.com",
        "azurewebsites.net",
        "herokuapp.com",
        "glitch.me",
        "replit.app",
        "surge.sh",
        "render.com",
        "fly.dev",
        "railway.app",
        "cyclic.app",
    }
)

_OPEN_REDIRECT_PARAMS = frozenset(
    {
        "url",
        "redirect",
        "redirect_url",
        "redirect_uri",
        "next",
        "return",
        "return_url",
        "returnurl",
        "goto",
        "destination",
        "target",
        "link",
        "forward",
        "continue",
        "redir",
        "out",
    }
)


def _is_ip_address(host: str) -> bool:
    # IPv6는 urlparse가 [] 제거하지 않으므로 strip 필요
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_patterns(url: str) -> list[DomainHeuristicSignal]:
    signals: list[DomainHeuristicSignal] = []
    parsed = urlparse(url)
    host = parsed.hostname or ""

    if _is_ip_address(host):
        signals.append(DomainHeuristicSignal.IP_DIRECT)
        return signals  # IP면 도메인 기반 신호 분석 불필요

    if parsed.scheme == "http":
        signals.append(DomainHeuristicSignal.NO_HTTPS)

    ext = extract_url_parts(url)

    # 서브도메인 레이블 과다
    subdomain_labels = [s for s in ext.subdomain.split(".") if s]
    if len(subdomain_labels) >= settings.subdomain_label_threshold:
        signals.append(DomainHeuristicSignal.SUBDOMAIN_OVERUSE)

    # Punycode/IDN 호모글리프
    if "xn--" in host:
        signals.append(DomainHeuristicSignal.PUNYCODE_IDN)

    # 하이픈 과다 (등록 도메인 레이블 기준)
    domain_label = ext.domain
    hyphen_count = domain_label.count("-")
    if (
        hyphen_count >= settings.hyphen_count_threshold
        or len(domain_label) >= settings.domain_label_length_threshold
    ):
        signals.append(DomainHeuristicSignal.HYPHEN_OVERUSE)

    # 의심 TLD
    if ext.suffix in _SUSPICIOUS_TLDS:
        signals.append(DomainHeuristicSignal.SUSPICIOUS_TLD)

    # 오픈 리다이렉트 파라미터
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if any(k.lower() in _OPEN_REDIRECT_PARAMS for k in qs):
        signals.append(DomainHeuristicSignal.OPEN_REDIRECT_PARAM)

    # 합법 호스팅 플랫폼 (domain.suffix 조합으로 검사)
    if ext.suffix and ext.subdomain:
        domain_suffix = f"{ext.domain}.{ext.suffix}"
        if domain_suffix in HOSTING_PLATFORMS or ext.suffix in HOSTING_PLATFORMS:
            signals.append(DomainHeuristicSignal.HOSTING_PLATFORM)

    return signals
