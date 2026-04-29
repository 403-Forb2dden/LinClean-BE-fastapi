"""콘텐츠 정적 분석 오케스트레이터 — 4단계 진입점.

fetch · extract · signals · AI 를 순차 호출하고 ContentAnalysisResult 로 병합한다.
외부 의존성(네트워크·AI) 실패는 degraded 결과로 흡수하되,
asyncio.CancelledError 는 반드시 re-raise 해서 상위 shutdown/timeout 신호가 살아있게 한다.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterable

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.content_analysis import (
    AIVerdict,
    ContentAnalysisResult,
    ContentSignal,
    TokenUsage,
)
from app.services.content_analyzer.ai import AIPromptContext, AIProvider, get_ai_provider
from app.services.content_analyzer.extract import ExtractedFeatures, extract_features_async
from app.services.content_analyzer.fetch import fetch_page
from app.services.content_analyzer.signals import ContentScoring, score_content

logger = get_logger(__name__)


def _build_prompt_context(
    final_url: str,
    features: ExtractedFeatures,
    upstream_signals: tuple[str, ...],
) -> AIPromptContext:
    return AIPromptContext(
        final_url=final_url,
        title=features.title,
        has_password_field=features.has_password_field,
        has_meta_refresh=features.has_meta_refresh,
        image_alts=tuple(features.image_alts),
        external_link_ratio=features.external_link_ratio,
        is_spa_shell=features.is_spa_shell,
        upstream_signals=upstream_signals,
    )


def _ai_score_weight(verdict: AIVerdict) -> int:
    # benign 은 규칙 점수를 감점하지 않는다 — AI 오탐이 정상 점수까지 깎을 수 있기 때문
    if verdict == AIVerdict.PHISHING:
        return settings.score_weight_ai_phishing
    if verdict == AIVerdict.SUSPICIOUS:
        return settings.score_weight_ai_suspicious
    return 0


# 정상 컨텐츠(이미지·PDF·대용량 정적 페이지) 또는 파이프라인 정합성 이슈(unchainer 가 놓친 3xx)는
# 악성 신호로 보지 않는다 — FETCH_FAILED 시그널만 남기고 점수는 가산하지 않는다.
# 그 외(timeout/connect_error/http_error 등)는 보수적으로 settings 의 가중치를 가산.
_FETCH_ERROR_NO_SCORE: frozenset[str] = frozenset(
    {"not_html", "too_large", "unexpected_redirect"}
)


def _fetch_failed_score(error: str | None) -> int:
    if error in _FETCH_ERROR_NO_SCORE:
        return 0
    return settings.score_weight_content_fetch_failed


def _fetch_failed_result(final_url: str, error: str | None) -> ContentAnalysisResult:
    return ContentAnalysisResult(
        final_url=final_url,
        fetched=False,
        score=_fetch_failed_score(error),
        signals=[ContentSignal.FETCH_FAILED],
        error=error,
    )


def skipped_already_danger(final_url: str) -> ContentAnalysisResult:
    """선행 단계에서 이미 danger 판정 — 네트워크·AI 비용을 아끼기 위해 분석을 건너뛴 상태.

    점수는 0으로 두어 상위 합산에 왜곡을 주지 않는다. 이미 다른 신호로 danger 가
    확정돼 있으므로 여기서 추가 가산할 필요가 없다.
    """
    return ContentAnalysisResult(
        final_url=final_url,
        fetched=False,
        score=0,
        signals=[ContentSignal.SKIPPED_ALREADY_DANGER],
        error="skipped_already_danger",
    )


async def analyze_content(
    final_url: str,
    *,
    provider: AIProvider | None = None,
    upstream_signals: Iterable[str] = (),
) -> ContentAnalysisResult:
    """콘텐츠 정적 분석 진입점.

    provider 를 명시하면 전역 프로바이더 대신 그것을 사용한다 — 모델 비교/디버그용.
    None(기본)이면 set_ai_provider() 로 설정된 전역 값을 쓴다.
    upstream_signals 는 도메인 휴리스틱·threat_db 등 선행 단계에서 잡힌 시그널 코드.
    AI 프롬프트에 사전 정보로 실어 보내 단독 페이지 피처보다 강한 판정이 가능하게 한다.
    """
    fetch_result = await fetch_page(final_url)
    if not fetch_result.ok:
        logger.info(
            "content_analysis.fetch_failed",
            url=final_url,
            error=fetch_result.error,
            status=fetch_result.status_code,
        )
        return _fetch_failed_result(final_url, fetch_result.error)

    features = await extract_features_async(fetch_result.html, base_url=final_url)
    scoring: ContentScoring = score_content(features, final_url)

    ai_verdict: AIVerdict | None = None
    ai_reason: str | None = None
    ai_error: str | None = None
    ai_model: str | None = None
    ai_token_usage: TokenUsage | None = None

    active_provider = provider if provider is not None else get_ai_provider()
    upstream_tuple = tuple(upstream_signals)
    try:
        inference = await active_provider.infer(
            _build_prompt_context(final_url, features, upstream_tuple)
        )
    except asyncio.CancelledError:
        # shutdown / 요청 타임아웃 신호는 degraded 결과로 흡수하지 않는다
        raise
    except Exception as exc:
        logger.warning(
            "content_analysis.ai_error",
            url=final_url,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        ai_error = "ai_unavailable"
        inference = None

    score = scoring.score
    if inference is not None:
        ai_verdict = inference.verdict
        ai_reason = inference.reason
        ai_model = inference.model
        ai_token_usage = inference.token_usage
        score += _ai_score_weight(inference.verdict)
    elif ai_error is None:
        # 추론이 None 인데 호출 단계 예외도 없었다면 NullAIProvider 동작.
        # 부팅 시 misconfiguration 으로 폴백된 NullProvider 면 fallback_reason 을 응답에 노출.
        # 정상 NullProvider 는 fallback_reason=None 이라 ai_error 가 None 으로 유지된다.
        ai_error = getattr(active_provider, "fallback_reason", None)

    score = min(score, settings.content_analysis_score_cap)

    return ContentAnalysisResult(
        final_url=final_url,
        fetched=True,
        score=score,
        signals=list(scoring.signals),
        title=features.title,
        has_password_field=features.has_password_field,
        has_meta_refresh=features.has_meta_refresh,
        external_link_ratio=features.external_link_ratio,
        brand_impersonation=scoring.brand_impersonation,
        logo_alt_impersonation=scoring.logo_alt_impersonation,
        is_spa_shell=features.is_spa_shell,
        ai_verdict=ai_verdict,
        ai_reason=ai_reason,
        ai_error=ai_error,
        ai_model=ai_model,
        ai_token_usage=ai_token_usage,
    )
