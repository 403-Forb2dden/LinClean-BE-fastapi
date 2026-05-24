from __future__ import annotations

from pathlib import Path

from app.core.logging import get_logger
from app.core.tld import extract_url_parts
from app.schemas.domain_heuristic import DomainHeuristicSignal
from app.services.domain_heuristic.patterns import HOSTING_PLATFORMS

logger = get_logger(__name__)

_BRANDS_FILE = Path(__file__).parent / "brands.txt"


def _load_brands() -> list[tuple[str, str]]:
    """brands.txt를 읽어 (domain_label, tld) 튜플 리스트로 반환. 모듈 로드 시 1회 실행."""
    if not _BRANDS_FILE.exists():
        # silent fail은 typosquatting 검사 영구 무력화로 이어져 false negative 폭증 — 명시적 로깅
        logger.error("typosquatting.brands_file_missing", path=str(_BRANDS_FILE))
        return []
    seen: set[tuple[str, str]] = set()
    brands: list[tuple[str, str]] = []
    for line in _BRANDS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ext = extract_url_parts(f"https://{line}")
        if ext.domain and ext.suffix:
            key = (ext.domain, ext.suffix)
            if key not in seen:
                seen.add(key)
                brands.append(key)
    if not brands:
        logger.error("typosquatting.brands_empty", path=str(_BRANDS_FILE))
    return brands


_BRANDS: list[tuple[str, str]] = _load_brands()


def _levenshtein(a: str, b: str) -> int:
    """레벤슈타인 거리 — 외부 라이브러리 없이 DP로 구현."""
    m, n = len(a), len(b)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if a[i - 1] == b[j - 1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j - 1])
            prev = temp
    return dp[n]


_MIN_FUZZY_LEN = 5  # 4자 이하 브랜드는 편집거리 1~2 오탐이 심해 완전일치만 인정


def check_typosquatting(url: str) -> DomainHeuristicSignal | None:
    ext = extract_url_parts(url)
    if not ext.top_domain_under_public_suffix:
        return None

    target_domain = ext.domain
    target_suffix = ext.suffix

    # 호스팅 플랫폼 자체 도메인(netlify.app, vercel.app 등)은 brand 변종(netlify.com)과
    # label 동일 + suffix 상이로 TYPO_DOMAIN 오탐되므로 조기 컷아웃
    if ext.top_domain_under_public_suffix in HOSTING_PLATFORMS:
        return None

    is_typo = False
    for brand_domain, brand_suffix in _BRANDS:
        if target_domain == brand_domain and target_suffix == brand_suffix:
            return None  # 완전 일치 → 정상 도메인

        if abs(len(target_domain) - len(brand_domain)) > 2:
            continue  # 길이 차이가 2 초과면 거리가 반드시 2 초과 → 스킵

        distance = _levenshtein(target_domain, brand_domain)
        if distance == 0 and target_suffix != brand_suffix:
            is_typo = True
        elif 1 <= distance <= 2 and min(len(target_domain), len(brand_domain)) >= _MIN_FUZZY_LEN:
            # "ing" vs "bing", "kb" vs "kbx" 같은 단어가 정상 도메인을 오탐하는 문제 차단
            is_typo = True

    return DomainHeuristicSignal.TYPO_DOMAIN if is_typo else None
