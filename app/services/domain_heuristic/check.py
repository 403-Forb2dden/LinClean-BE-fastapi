from __future__ import annotations

from urllib.parse import urlparse

import tldextract

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.domain_heuristic import DomainHeuristicResult, DomainHeuristicSignal
from app.services.domain_heuristic.dga import check_dga
from app.services.domain_heuristic.patterns import check_patterns
from app.services.domain_heuristic.rdap import lookup_rdap
from app.services.domain_heuristic.typosquatting import check_typosquatting

logger = get_logger(__name__)


# 모듈 로드 시 1회 구성 — 호출당 dict 재생성 비용 제거. settings hot-reload는 사용하지 않는다.
_SIGNAL_SCORES: dict[DomainHeuristicSignal, int] = {
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
}


async def check_domain_heuristic(url: str) -> DomainHeuristicResult:
    ext = tldextract.extract(url)
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

        # lookup_rdap은 내부에서 모든 예외를 error_code로 변환하므로 재래핑 불필요
        rdap_info, rdap_error = await lookup_rdap(url)
        if rdap_info and rdap_info.is_new_domain:
            signals.append(DomainHeuristicSignal.NEW_DOMAIN)

    # 휴리스틱은 보조 시그널이라 합산이 GSB/URLhaus를 압도하지 않도록 캡 적용
    raw_score = sum(_SIGNAL_SCORES.get(s, 0) for s in signals)
    score = min(raw_score, settings.domain_heuristic_score_cap)

    return DomainHeuristicResult(
        domain=domain,
        score=score,
        signals=signals,
        rdap=rdap_info,
        rdap_error=rdap_error,
    )
