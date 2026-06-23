from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from app.core.config import settings
from app.core.tld import extract_url_parts
from app.schemas.domain_heuristic import DomainHeuristicSignal

_BRANDS_FILE = Path(__file__).parent / "brands.txt"

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
        "cfd",
        "gq",
        "help",
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
        "workers.dev",
        "wasmer.app",
        "godaddysites.com",
        "duckdns.org",
        "free.nf",
        "my.id",
        "backblazeb2.com",
    }
)

_URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "cutt.ly",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "qrco.de",
        "rebrand.ly",
        "shorturl.at",
        "t.co",
        "tinyurl.com",
    }
)

_TRUSTED_BENIGN_DOMAINS = frozenset(
    {
        "example.com",
        "httpbin.org",
    }
)

_SENSITIVE_PATH_TOKENS = frozenset(
    {
        "account",
        "admin",
        "auth",
        "billing",
        "claim",
        "confirm",
        "credential",
        "invoice",
        "login",
        "password",
        "pay",
        "portal",
        "recover",
        "secure",
        "session",
        "signin",
        "support",
        "suporte",
        "validate",
        "verification",
        "verify",
        "wallet",
    }
)

_SEEDED_BRAND_LABELS = frozenset(
    {
        "adobe",
        "amazon",
        "apple",
        "binance",
        "coinbase",
        "discord",
        "dpd",
        "facebook",
        "google",
        "instagram",
        "iphone",
        "metamask",
        "microsoft",
        "netflix",
        "office",
        "outlook",
        "paypal",
        "roblox",
        "societegenerale",
        "telegram",
        "tmobile",
        "t-mobile",
        "trezor",
        "whatsapp",
        "wps",
        "yahoo",
    }
)

_GENERIC_BRAND_LABELS = frozenset(
    {
        "bank",
        "blog",
        "cafe",
        "card",
        "cloud",
        "finance",
        "gov",
        "home",
        "map",
        "mvno",
        "news",
        "pay",
        "place",
        "shop",
        "shopping",
        "support",
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


@lru_cache(maxsize=1)
def _brand_labels() -> frozenset[str]:
    labels = set(_SEEDED_BRAND_LABELS)
    if not _BRANDS_FILE.exists():
        return frozenset(labels)
    for line in _BRANDS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        label = line.split(".", 1)[0].lower()
        if len(label) >= 3 and label not in _GENERIC_BRAND_LABELS:
            labels.add(label)
    return frozenset(labels)


@lru_cache(maxsize=1)
def _trusted_brand_domains() -> frozenset[str]:
    domains: set[str] = set()
    if not _BRANDS_FILE.exists():
        return frozenset(domains)
    for line in _BRANDS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        domains.add(line.lower())
    return frozenset(domains)


def is_trusted_registered_domain(url: str) -> bool:
    ext = extract_url_parts(url)
    registered_domain = (ext.top_domain_under_public_suffix or "").lower()
    return bool(
        registered_domain
        and (
            registered_domain in _trusted_brand_domains()
            or registered_domain in _TRUSTED_BENIGN_DOMAINS
        )
    )


def _brand_labels_in_url_text(text: str) -> set[str]:
    lowered = text.lower()
    tokens = re.findall(r"[a-z0-9]+", lowered)
    found: set[str] = set()
    for label in _brand_labels():
        if len(label) < 3:
            continue
        if label in lowered or label in tokens:
            found.add(label)
    return found


def _registered_domain_from_url(url: str) -> str:
    ext = extract_url_parts(url)
    return (ext.top_domain_under_public_suffix or urlparse(url).hostname or "").lower()


def _has_external_open_redirect_target(qs: dict[str, list[str]], registered_domain: str) -> bool:
    for key, values in qs.items():
        if key.lower() not in _OPEN_REDIRECT_PARAMS:
            continue
        if not values:
            return True
        for value in values:
            parsed_value = urlparse(value)
            if parsed_value.scheme not in {"http", "https"} or not parsed_value.hostname:
                return True
            if _registered_domain_from_url(value) != registered_domain:
                return True
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
    registered_domain = (ext.top_domain_under_public_suffix or host).lower()
    registered_label = ext.domain.lower()
    is_trusted_brand_domain = registered_domain in _trusted_brand_domains()

    if parsed.username or parsed.password or "@" in parsed.netloc:
        signals.append(DomainHeuristicSignal.URL_USERINFO)

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
    if _has_external_open_redirect_target(qs, registered_domain):
        signals.append(DomainHeuristicSignal.OPEN_REDIRECT_PARAM)

    # private suffix(github.io, vercel.app 등)는 tld parser에서 suffix로 잡히므로
    # user.github.io처럼 subdomain이 없어도 플랫폼 사용자 공간으로 본다.
    is_hosting_platform = False
    if ext.suffix:
        domain_suffix = f"{ext.domain}.{ext.suffix}"
        if ext.suffix in HOSTING_PLATFORMS or (
            ext.subdomain and domain_suffix in HOSTING_PLATFORMS
        ):
            signals.append(DomainHeuristicSignal.HOSTING_PLATFORM)
            is_hosting_platform = True

    if registered_domain in _URL_SHORTENERS:
        signals.append(DomainHeuristicSignal.URL_SHORTENER)

    url_text = " ".join(part for part in (host, parsed.path, parsed.query) if part)
    url_tokens = set(re.findall(r"[a-z]+", url_text.lower()))
    sensitive_path = bool(url_tokens & _SENSITIVE_PATH_TOKENS)
    url_brands = _brand_labels_in_url_text(url_text)

    if sensitive_path and not is_trusted_brand_domain:
        signals.append(DomainHeuristicSignal.SENSITIVE_PATH)

    if url_brands and not is_trusted_brand_domain and registered_label not in url_brands:
        signals.append(DomainHeuristicSignal.BRAND_IN_URL)

    if is_hosting_platform and (url_brands or sensitive_path):
        signals.append(DomainHeuristicSignal.FREE_HOSTING_LURE)

    return signals
