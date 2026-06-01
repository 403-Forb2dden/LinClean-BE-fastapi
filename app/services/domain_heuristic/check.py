from __future__ import annotations

import asyncio
from functools import lru_cache
from urllib.parse import urlparse

from app.core.config import settings
from app.core.logging import get_logger
from app.core.tld import extract_url_parts
from app.schemas.domain_heuristic import DomainHeuristicResult, DomainHeuristicSignal
from app.services.domain_heuristic.dga import check_dga
from app.services.domain_heuristic.patterns import check_patterns
from app.services.domain_heuristic.rdap import lookup_rdap
from app.services.domain_heuristic.typosquatting import check_typosquatting

logger = get_logger(__name__)


@lru_cache(maxsize=1)
def _signal_scores() -> dict[DomainHeuristicSignal, int]:
    """시그널 → 점수 매핑을 lazy 하게 1회만 빌드.

    예전엔 모듈 import 시점에 settings 값을 dict 로 캡처했는데, 그러면 테스트의
    monkeypatch 와 운영의 env 갱신이 다른 모듈(signals.py 등 lazy 경로)과
    비대칭적으로 반영됐다. 호출 단계에서 캐시된 dict 를 받도록 옮겨 일관성 확보.
    """
    return {
        DomainHeuristicSignal.IP_DIRECT: settings.score_weight_ip_direct,
        DomainHeuristicSignal.TYPO_DOMAIN: settings.score_weight_typo_domain,
        DomainHeuristicSignal.PUNYCODE_IDN: settings.score_weight_punycode_idn,
        DomainHeuristicSignal.NEW_DOMAIN: settings.score_weight_new_domain,
        DomainHeuristicSignal.SUBDOMAIN_OVERUSE: settings.score_weight_subdomain_overuse,
        DomainHeuristicSignal.NO_HTTPS: settings.score_weight_no_https,
        DomainHeuristicSignal.OPEN_REDIRECT_PARAM: settings.score_weight_open_redirect_param,
        DomainHeuristicSignal.HYPHEN_OVERUSE: settings.score_weight_hyphen_overuse,
        DomainHeuristicSignal.SUSPICIOUS_TLD: settings.score_weight_suspicious_tld,
        DomainHeuristicSignal.DGA_LIKE: settings.score_weight_dga_like,
        DomainHeuristicSignal.HOSTING_PLATFORM: settings.score_weight_hosting_platform,
        DomainHeuristicSignal.URL_USERINFO: settings.score_weight_url_userinfo,
        DomainHeuristicSignal.BRAND_IN_URL: settings.score_weight_brand_in_url,
        DomainHeuristicSignal.FREE_HOSTING_LURE: settings.score_weight_free_hosting_lure,
        DomainHeuristicSignal.SENSITIVE_PATH: settings.score_weight_sensitive_path,
        DomainHeuristicSignal.URL_SHORTENER: settings.score_weight_url_shortener,
        DomainHeuristicSignal.REDIRECT_CROSS_ORIGIN: settings.score_weight_redirect_cross_origin,
    }


async def check_domain_heuristic(url: str) -> DomainHeuristicResult:
    ext = extract_url_parts(url)
    domain = ext.top_domain_under_public_suffix or (urlparse(url).hostname or "")

    signals: list[DomainHeuristicSignal] = []
    rdap_info = None
    rdap_error = None

    try:
        pattern_signals = check_patterns(url)
        signals.extend(pattern_signals)
    except Exception as exc:
        logger.warning("domain_heuristic.patterns_error", error=str(exc))

    # IP 직접 접근이면 도메인 기반 신호 분석 불필요
    if DomainHeuristicSignal.IP_DIRECT not in signals:
        try:
            dga_signal = check_dga(url)
            if dga_signal:
                signals.append(dga_signal)
        except Exception as exc:
            logger.warning("domain_heuristic.dga_error", error=str(exc))

        # 호스팅 플랫폼(github.io, netlify.app 등)은 suffix가 브랜드의 suffix와
        # 다른 것이 정상 → 타이포스쿼팅 판정에서 제외
        if DomainHeuristicSignal.HOSTING_PLATFORM not in signals:
            try:
                typo_signal = check_typosquatting(url)
                if typo_signal:
                    signals.append(typo_signal)
            except Exception as exc:
                logger.warning("domain_heuristic.typo_error", error=str(exc))

        # RDAP은 보조 신호다. RDAP이 느려져도 앞에서 이미 잡은 URL 패턴/DGA/typo
        # 신호를 잃지 않도록 내부 timeout으로 격리한다.
        try:
            timeout_seconds = min(
                settings.rdap_timeout_seconds,
                settings.pipeline_domain_timeout_seconds - 0.25,
            )
            rdap_info, rdap_error = await asyncio.wait_for(
                lookup_rdap(url),
                timeout=timeout_seconds,
            )
        except TimeoutError:
            rdap_info, rdap_error = None, "timeout"
        if rdap_info and rdap_info.is_new_domain:
            signals.append(DomainHeuristicSignal.NEW_DOMAIN)

    # 휴리스틱은 보조 시그널이라 합산이 GSB/URLhaus를 압도하지 않도록 캡 적용
    score_map = _signal_scores()
    raw_score = sum(score_map.get(s, 0) for s in signals)
    score = min(raw_score, settings.domain_heuristic_score_cap)

    return DomainHeuristicResult(
        domain=domain,
        score=score,
        signals=signals,
        rdap=rdap_info,
        rdap_error=rdap_error,
    )
