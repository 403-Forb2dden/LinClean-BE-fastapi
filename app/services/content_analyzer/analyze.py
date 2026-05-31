"""콘텐츠 정적 분석 오케스트레이터 — 4단계 진입점.

fetch · extract · signals · AI 를 순차 호출하고 ContentAnalysisResult 로 병합한다.
외부 의존성(네트워크·AI) 실패는 degraded 결과로 흡수하되,
asyncio.CancelledError 는 반드시 re-raise 해서 상위 shutdown/timeout 신호가 살아있게 한다.
"""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Iterable

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
from app.services.content_analyzer.render import render_page
from app.services.content_analyzer.signals import ContentScoring, score_content
from app.services.domain_heuristic.patterns import is_trusted_registered_domain

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
        has_password_form_external_action=features.has_password_form_external_action,
        has_external_meta_refresh=features.has_external_meta_refresh,
        upstream_signals=upstream_signals,
        body_text_snippets=tuple(features.body_text_snippets),
        form_field_summaries=tuple(features.form_field_summaries),
        cta_texts=tuple(features.cta_texts),
        download_links=tuple(features.download_links),
        sensitive_field_types=tuple(features.sensitive_field_types),
        korean_lure_keywords=tuple(features.korean_lure_keywords),
        public_agency_keywords=tuple(features.public_agency_keywords),
    )


def _ai_score_weight(verdict: AIVerdict) -> int:
    # benign 은 규칙 점수를 감점하지 않는다 — AI 오탐이 정상 점수까지 깎을 수 있기 때문
    if verdict == AIVerdict.PHISHING:
        return settings.score_weight_ai_phishing
    if verdict == AIVerdict.SUSPICIOUS:
        return settings.score_weight_ai_suspicious
    return 0


_HIGH_RISK_CONTENT_SIGNALS: frozenset[str] = frozenset(
    {
        ContentSignal.BRAND_IMPERSONATION_FORM.value,
        ContentSignal.CREDENTIAL_FORM_EXTERNAL.value,
        ContentSignal.SENSITIVE_ID_FIELD.value,
        ContentSignal.FINANCIAL_FIELD.value,
        ContentSignal.RISKY_DOWNLOAD_LINK.value,
        ContentSignal.EXTERNAL_META_REFRESH.value,
    }
)
_HIGH_RISK_UPSTREAM_SIGNALS: frozenset[str] = frozenset(
    {
        "URL_USERINFO",
        "OPEN_REDIRECT_PARAM",
        "BRAND_IN_URL",
        "FREE_HOSTING_LURE",
        "SENSITIVE_PATH",
        "SUSPICIOUS_TLD",
        "PUNYCODE_IDN",
        "TYPO_DOMAIN",
    }
)


def _should_apply_ai_suspicious_score(
    final_url: str,
    scoring: ContentScoring,
    upstream_signals: tuple[str, ...],
) -> bool:
    if not is_trusted_registered_domain(final_url):
        return True
    content_signal_values = {signal.value for signal in scoring.signals}
    if content_signal_values & _HIGH_RISK_CONTENT_SIGNALS:
        return True
    if set(upstream_signals) & _HIGH_RISK_UPSTREAM_SIGNALS:
        return True
    return False


def _unique_merge(left: list[str], right: list[str]) -> list[str]:
    merged = list(left)
    for item in right:
        if item not in merged:
            merged.append(item)
    return merged


def _merge_features(static: ExtractedFeatures, rendered: ExtractedFeatures) -> ExtractedFeatures:
    return ExtractedFeatures(
        title=rendered.title or static.title,
        has_password_field=static.has_password_field or rendered.has_password_field,
        has_password_form_external_action=(
            static.has_password_form_external_action
            or rendered.has_password_form_external_action
        ),
        has_meta_refresh=static.has_meta_refresh or rendered.has_meta_refresh,
        has_external_meta_refresh=(
            static.has_external_meta_refresh or rendered.has_external_meta_refresh
        ),
        external_link_ratio=(
            rendered.external_link_ratio
            if rendered.external_link_ratio is not None
            else static.external_link_ratio
        ),
        image_alts=_unique_merge(static.image_alts, rendered.image_alts),
        is_spa_shell=rendered.is_spa_shell,
        body_text_snippets=_unique_merge(
            static.body_text_snippets,
            rendered.body_text_snippets,
        ),
        form_field_summaries=_unique_merge(
            static.form_field_summaries,
            rendered.form_field_summaries,
        ),
        cta_texts=_unique_merge(static.cta_texts, rendered.cta_texts),
        download_links=_unique_merge(static.download_links, rendered.download_links),
        sensitive_field_types=_unique_merge(
            static.sensitive_field_types,
            rendered.sensitive_field_types,
        ),
        korean_lure_keywords=_unique_merge(
            static.korean_lure_keywords,
            rendered.korean_lure_keywords,
        ),
        public_agency_keywords=_unique_merge(
            static.public_agency_keywords,
            rendered.public_agency_keywords,
        ),
    )


def _should_run_precision_analysis(
    features: ExtractedFeatures,
    scoring: ContentScoring,
) -> bool:
    if not settings.content_precision_enabled:
        return False
    if scoring.score >= settings.score_danger_threshold:
        return False
    if features.is_spa_shell:
        return True
    if scoring.score >= settings.content_precision_min_score:
        return True
    return bool(
        features.download_links
        or features.sensitive_field_types
        or features.korean_lure_keywords
        or features.public_agency_keywords
    )


# 정상 컨텐츠(이미지·PDF·대용량 정적 페이지) 또는 파이프라인 정합성 이슈(unchainer 가 놓친 3xx)는
# 악성 신호로 보지 않는다 — FETCH_FAILED 시그널만 남기고 점수는 가산하지 않는다.
# blocked_host 는 우리가 SSRF 1·2선에서 차단한 결과지 페이지의 악성 신호가 아니라 동일하게 0 가산.
# 그 외(timeout/connect_error/http_error 등)는 보수적으로 settings 의 가중치를 가산.
_FETCH_ERROR_NO_SCORE: frozenset[str] = frozenset(
    {"not_html", "too_large", "unexpected_redirect", "blocked_host"}
)
_SKIPPED_ALREADY_DANGER_REASON = "위험성이 확인된 URL입니다. 페이지를 열지 않는 것이 좋습니다."


def _fetch_failed_score(error: str | None) -> int:
    if error in _FETCH_ERROR_NO_SCORE:
        return 0
    return settings.score_weight_content_fetch_failed


def _fetch_failed_reason(error: str | None) -> str:
    if error == "http_error_404":
        return "페이지를 찾을 수 없습니다."
    if error and error.startswith("http_error_4"):
        return "페이지 요청이 거부되었거나 찾을 수 없습니다."
    if error and error.startswith("http_error_5"):
        return "대상 서버 오류로 페이지를 확인할 수 없습니다."
    if error == "timeout":
        return "페이지 응답 시간이 초과되었습니다."
    if error == "connect_error":
        return "페이지에 연결할 수 없습니다."
    if error == "dns_failure":
        return "도메인 주소를 확인할 수 없습니다."
    if error == "not_html":
        return "분석 가능한 HTML 페이지가 아닙니다."
    if error == "too_large":
        return "페이지가 너무 커서 분석하지 않았습니다."
    if error == "blocked_host":
        return "내부망 또는 차단된 호스트라 분석하지 않았습니다."
    if error == "unexpected_redirect":
        return "예상하지 못한 리다이렉트 응답으로 페이지를 분석하지 못했습니다."
    return "페이지를 가져오지 못했습니다."


def _fetch_failed_result(final_url: str, error: str | None) -> ContentAnalysisResult:
    return ContentAnalysisResult(
        final_url=final_url,
        fetched=False,
        status_code=None,
        score=_fetch_failed_score(error),
        signals=[ContentSignal.FETCH_FAILED],
        reason=_fetch_failed_reason(error),
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
        reason=_SKIPPED_ALREADY_DANGER_REASON,
        error="skipped_already_danger",
    )


async def analyze_content(
    final_url: str,
    *,
    provider: AIProvider | None = None,
    upstream_signals: Iterable[str] | Awaitable[Iterable[str]] = (),
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
        result = _fetch_failed_result(final_url, fetch_result.error)
        result.status_code = fetch_result.status_code
        return result

    features = await extract_features_async(fetch_result.html, base_url=final_url)
    scoring: ContentScoring = score_content(features, final_url)
    precision_analysis_used = False
    precision_analysis_error: str | None = None

    if _should_run_precision_analysis(features, scoring):
        precision_analysis_used = True
        render_result = await render_page(final_url)
        if render_result.ok:
            rendered_features = await extract_features_async(render_result.html, base_url=final_url)
            features = _merge_features(features, rendered_features)
            scoring = score_content(features, final_url)
            if ContentSignal.RENDERED_DOM_ANALYZED not in scoring.signals:
                scoring.signals.append(ContentSignal.RENDERED_DOM_ANALYZED)
        else:
            precision_analysis_error = render_result.error

    ai_verdict: AIVerdict | None = None
    ai_reason: str | None = None
    ai_error: str | None = None
    ai_model: str | None = None
    ai_token_usage: TokenUsage | None = None

    active_provider = provider if provider is not None else get_ai_provider()
    if inspect.isawaitable(upstream_signals):
        upstream_tuple = tuple(await upstream_signals)
    else:
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
        if inference.verdict != AIVerdict.SUSPICIOUS or _should_apply_ai_suspicious_score(
            final_url,
            scoring,
            upstream_tuple,
        ):
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
        status_code=fetch_result.status_code,
        score=score,
        signals=list(scoring.signals),
        title=features.title,
        has_password_field=features.has_password_field,
        has_password_form_external_action=features.has_password_form_external_action,
        has_meta_refresh=features.has_meta_refresh,
        has_external_meta_refresh=features.has_external_meta_refresh,
        external_link_ratio=features.external_link_ratio,
        brand_impersonation=scoring.brand_impersonation,
        logo_alt_impersonation=scoring.logo_alt_impersonation,
        is_spa_shell=features.is_spa_shell,
        body_text_snippets=features.body_text_snippets,
        form_field_summaries=features.form_field_summaries,
        cta_texts=features.cta_texts,
        download_links=features.download_links,
        sensitive_field_types=features.sensitive_field_types,
        korean_lure_keywords=features.korean_lure_keywords,
        public_agency_keywords=features.public_agency_keywords,
        precision_analysis_used=precision_analysis_used,
        precision_analysis_error=precision_analysis_error,
        ai_verdict=ai_verdict,
        ai_reason=ai_reason,
        ai_error=ai_error,
        ai_model=ai_model,
        ai_token_usage=ai_token_usage,
    )
