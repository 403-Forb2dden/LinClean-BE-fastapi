from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.pipeline import PipelineFailure, PipelineStage, PipelineSuccess
from app.services.analysis_summary import build_analysis_summary

logger = get_logger(__name__)

_CALLBACK_PATH = "/internal/analysis-result"
_MAX_ATTEMPTS = 3

_STAGE_NUMBERS: dict[PipelineStage, int] = {
    PipelineStage.NORMALIZE: 1,
    PipelineStage.UNCHAIN: 1,
    PipelineStage.THREAT_DB: 2,
    PipelineStage.DOMAIN_HEURISTIC: 3,
    PipelineStage.CONTENT_ANALYSIS: 4,
}

_DOMAIN_REASON_MESSAGES: dict[str, str] = {
    "IP_DIRECT": "IP 주소로 직접 접근하는 URL입니다.",
    "TYPO_DOMAIN": "유명 서비스와 유사한 도메인입니다.",
    "PUNYCODE_IDN": "문자 혼동을 유도할 수 있는 국제화 도메인입니다.",
    "NEW_DOMAIN": "최근 등록된 도메인입니다.",
    "SUBDOMAIN_OVERUSE": "하위 도메인을 과도하게 사용합니다.",
    "NO_HTTPS": "HTTPS가 아닌 연결을 사용합니다.",
    "OPEN_REDIRECT_PARAM": "오픈 리다이렉트에 악용될 수 있는 파라미터가 있습니다.",
    "HYPHEN_OVERUSE": "하이픈을 과도하게 사용한 도메인입니다.",
    "SUSPICIOUS_TLD": "피싱에 자주 악용되는 최상위 도메인입니다.",
    "DGA_LIKE": "자동 생성된 것으로 의심되는 도메인입니다.",
    "HOSTING_PLATFORM": "무료 호스팅 플랫폼을 사용합니다.",
    "URL_USERINFO": "URL에 사용자 정보 형식이 포함되어 있습니다.",
    "BRAND_IN_URL": "URL에 브랜드명을 포함해 신뢰를 유도합니다.",
    "FREE_HOSTING_LURE": "무료 호스팅 주소에서 신뢰를 유도하는 문구를 사용합니다.",
    "SENSITIVE_PATH": "로그인 또는 인증 관련 경로를 사용합니다.",
    "URL_SHORTENER": "단축 URL 서비스를 사용합니다.",
    "REDIRECT_CROSS_ORIGIN": "입력 URL이 다른 사이트로 이동합니다.",
}

_CONTENT_REASON_MESSAGES: dict[str, str] = {
    "BRAND_IMPERSONATION_FORM": "브랜드를 사칭하는 로그인 폼이 확인되었습니다.",
    "LOGO_ALT_IMPERSONATION": "브랜드 로고 또는 이미지 설명을 사칭합니다.",
    "CREDENTIAL_FORM_EXTERNAL": "로그인 정보가 외부 주소로 전송될 수 있습니다.",
    "PII_COLLECTION_FORM": "개인정보 입력을 유도하는 폼이 있습니다.",
    "SENSITIVE_ID_FIELD": "민감 식별정보 입력을 요구합니다.",
    "FINANCIAL_FIELD": "금융정보 입력을 요구합니다.",
    "RISKY_DOWNLOAD_LINK": "위험한 파일 다운로드를 유도합니다.",
    "PUBLIC_AGENCY_LURE": "공공기관을 사칭하는 문구가 있습니다.",
    "KOREAN_LURE_TEXT": "국내 사용자를 노린 유인 문구가 있습니다.",
    "META_REFRESH": "자동 이동 태그가 포함되어 있습니다.",
    "EXTERNAL_META_REFRESH": "외부 사이트로 자동 이동할 수 있습니다.",
    "EXTERNAL_LINK_OVERUSE": "외부 링크 비율이 높습니다.",
    "SPA_SHELL": "정적 분석만으로는 페이지 내용을 확인하기 어렵습니다.",
    "FETCH_FAILED": "페이지 내용을 가져오지 못했습니다.",
    "SKIPPED_ALREADY_DANGER": "선행 단계에서 위험성이 확인되어 콘텐츠 분석을 생략했습니다.",
}


def _iso_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _callback_url() -> str:
    return f"{settings.spring_internal_url.rstrip('/')}{_CALLBACK_PATH}"


def _enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def _host(url: str) -> str | None:
    return urlparse(url).hostname


def _signal_weight(code: str) -> int:
    domain_weights = {
        "IP_DIRECT": settings.score_weight_ip_direct,
        "TYPO_DOMAIN": settings.score_weight_typo_domain,
        "PUNYCODE_IDN": settings.score_weight_punycode_idn,
        "NEW_DOMAIN": settings.score_weight_new_domain,
        "SUBDOMAIN_OVERUSE": settings.score_weight_subdomain_overuse,
        "NO_HTTPS": settings.score_weight_no_https,
        "OPEN_REDIRECT_PARAM": settings.score_weight_open_redirect_param,
        "HYPHEN_OVERUSE": settings.score_weight_hyphen_overuse,
        "SUSPICIOUS_TLD": settings.score_weight_suspicious_tld,
        "DGA_LIKE": settings.score_weight_dga_like,
        "HOSTING_PLATFORM": settings.score_weight_hosting_platform,
        "URL_USERINFO": settings.score_weight_url_userinfo,
        "BRAND_IN_URL": settings.score_weight_brand_in_url,
        "FREE_HOSTING_LURE": settings.score_weight_free_hosting_lure,
        "SENSITIVE_PATH": settings.score_weight_sensitive_path,
        "URL_SHORTENER": settings.score_weight_url_shortener,
        "REDIRECT_CROSS_ORIGIN": settings.score_weight_redirect_cross_origin,
    }
    content_weights = {
        "BRAND_IMPERSONATION_FORM": settings.score_weight_brand_impersonation,
        "LOGO_ALT_IMPERSONATION": settings.score_weight_logo_alt_impersonation,
        "CREDENTIAL_FORM_EXTERNAL": settings.score_weight_credential_form_external,
        "PII_COLLECTION_FORM": settings.score_weight_pii_collection_form,
        "SENSITIVE_ID_FIELD": settings.score_weight_sensitive_id_field,
        "FINANCIAL_FIELD": settings.score_weight_financial_field,
        "RISKY_DOWNLOAD_LINK": settings.score_weight_risky_download_link,
        "PUBLIC_AGENCY_LURE": settings.score_weight_public_agency_lure,
        "KOREAN_LURE_TEXT": settings.score_weight_korean_lure,
        "META_REFRESH": settings.score_weight_meta_refresh,
        "EXTERNAL_META_REFRESH": settings.score_weight_external_meta_refresh,
        "EXTERNAL_LINK_OVERUSE": settings.score_weight_external_link_overuse,
        "FETCH_FAILED": settings.score_weight_content_fetch_failed,
    }
    return domain_weights.get(code) or content_weights.get(code) or 0


def _add_reason(
    reasons: list[dict[str, Any]],
    *,
    code: str,
    stage: int,
    weight: int,
    message: str,
) -> None:
    if weight <= 0 and code not in {"GSB_MATCH", "URLHAUS_MATCH"}:
        return
    reasons.append(
        {
            "code": code,
            "stage": stage,
            "weight": weight,
            "message": message,
        }
    )


def _callback_reasons(result: PipelineSuccess) -> list[dict[str, Any]]:
    stages = result.stages
    reasons: list[dict[str, Any]] = []

    if stages.threat_db.gsb.is_threat:
        _add_reason(
            reasons,
            code="GSB_MATCH",
            stage=2,
            weight=settings.score_weight_gsb,
            message="Google Safe Browsing에 악성 URL로 등록되어 있습니다.",
        )
    if stages.threat_db.urlhaus.is_threat:
        _add_reason(
            reasons,
            code="URLHAUS_MATCH",
            stage=2,
            weight=settings.score_weight_urlhaus,
            message="URLhaus에 악성 URL로 등록되어 있습니다.",
        )

    for signal in stages.domain_heuristic.signals:
        code = _enum_value(signal)
        _add_reason(
            reasons,
            code=code,
            stage=3,
            weight=_signal_weight(code),
            message=_DOMAIN_REASON_MESSAGES.get(code, "도메인 휴리스틱 위험 신호가 있습니다."),
        )

    for signal in stages.content_analysis.signals:
        code = _enum_value(signal)
        _add_reason(
            reasons,
            code=code,
            stage=4,
            weight=_signal_weight(code),
            message=_CONTENT_REASON_MESSAGES.get(code, "콘텐츠 분석 위험 신호가 있습니다."),
        )

    ai_verdict = stages.content_analysis.ai_verdict
    if ai_verdict is not None:
        verdict = _enum_value(ai_verdict)
        if verdict == "phishing":
            _add_reason(
                reasons,
                code="AI_PHISHING",
                stage=4,
                weight=settings.score_weight_ai_phishing,
                message=(
                    stages.content_analysis.ai_reason or "AI가 피싱 가능성이 높다고 판단했습니다."
                ),
            )
        elif verdict == "suspicious":
            _add_reason(
                reasons,
                code="AI_SUSPICIOUS",
                stage=4,
                weight=settings.score_weight_ai_suspicious,
                message=(
                    stages.content_analysis.ai_reason or "AI가 의심스러운 페이지로 판단했습니다."
                ),
            )

    return reasons


def _callback_summary(result: PipelineSuccess) -> str:
    if result.summary:
        return result.summary
    return build_analysis_summary(
        verdict=result.verdict,
        threat=result.stages.threat_db,
        heuristic=result.stages.domain_heuristic,
        content=result.stages.content_analysis,
    )


def _spring_stages(result: PipelineSuccess) -> dict[str, Any]:
    stages = result.stages
    gsb_matches = [match.threat_type for match in stages.threat_db.gsb.matches if match.threat_type]

    chain = [hop.url for hop in stages.unchain.hops]
    if not chain:
        chain.append(stages.unchain.input_url)
    if stages.unchain.final_url not in chain:
        chain.append(stages.unchain.final_url)

    rdap = stages.domain_heuristic.rdap
    rdap_payload = None
    if rdap is not None:
        rdap_payload = {
            "domain": rdap.domain,
            "registrar": rdap.registrar,
            "createdDate": _iso_z(rdap.created_date) if rdap.created_date else None,
            "domainAgeDays": rdap.domain_age_days,
            "isNewDomain": rdap.is_new_domain,
        }

    content = stages.content_analysis
    return {
        "externalDb": {
            "gsb": {
                "isThreat": stages.threat_db.gsb.is_threat,
                "matchedTypes": gsb_matches,
            },
            "urlhaus": {
                "isThreat": stages.threat_db.urlhaus.is_threat,
                "host": _host(stages.threat_db.final_url),
            },
        },
        "unchain": {
            "hops": stages.unchain.hop_count,
            "chain": chain,
        },
        "domainHeuristic": {
            "rdap": rdap_payload,
            "signals": [_enum_value(signal) for signal in stages.domain_heuristic.signals],
        },
        "contentAnalysis": {
            "fetched": content.fetched,
            "hasPasswordField": content.has_password_field,
            "aiVerdict": _enum_value(content.ai_verdict) if content.ai_verdict else None,
            "aiReason": content.ai_reason,
        },
    }


def _error_stage(stage: PipelineStage) -> int:
    return _STAGE_NUMBERS[stage]


def _success_payload(
    result: PipelineSuccess,
    *,
    request_id: str,
    elapsed_ms: int,
    analyzed_at: datetime,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "analysisId": result.analysis_id,
        "requestId": request_id,
        "status": "succeeded",
        "originalUrl": result.original_url,
        "finalUrl": result.final_url,
        "verdict": result.verdict.value,
        "score": result.score,
        "reasons": _callback_reasons(result),
        "stages": _spring_stages(result),
        "summary": _callback_summary(result),
        "engineVersion": settings.app_version,
        "analyzedAt": _iso_z(analyzed_at),
        "elapsedMs": elapsed_ms,
    }
    return payload


def _failure_payload(
    result: PipelineFailure,
    *,
    request_id: str,
    elapsed_ms: int,
    analyzed_at: datetime,
) -> dict[str, Any]:
    error: dict[str, Any] = {
        "code": result.error_code or f"{result.failed_at_stage.value.upper()}_FAILED",
        "stage": _error_stage(result.failed_at_stage),
        "message": result.error,
    }
    if result.status_code is not None:
        error["statusCode"] = result.status_code

    payload: dict[str, Any] = {
        "analysisId": result.analysis_id,
        "requestId": request_id,
        "status": "failed",
        "originalUrl": result.original_url,
        "error": error,
        "engineVersion": settings.app_version,
        "analyzedAt": _iso_z(analyzed_at),
        "elapsedMs": elapsed_ms,
    }
    if result.final_url is not None:
        payload["finalUrl"] = result.final_url
    return payload


def build_analysis_callback_payload(
    result: PipelineSuccess | PipelineFailure,
    *,
    request_id: str,
    elapsed_ms: int,
    analyzed_at: datetime,
) -> dict[str, Any]:
    if isinstance(result, PipelineSuccess):
        return _success_payload(
            result,
            request_id=request_id,
            elapsed_ms=elapsed_ms,
            analyzed_at=analyzed_at,
        )
    return _failure_payload(
        result,
        request_id=request_id,
        elapsed_ms=elapsed_ms,
        analyzed_at=analyzed_at,
    )


async def post_analysis_callback(
    result: PipelineSuccess | PipelineFailure,
    *,
    request_id: str,
    elapsed_ms: int,
    analyzed_at: datetime,
) -> bool:
    payload = build_analysis_callback_payload(
        result,
        request_id=request_id,
        elapsed_ms=elapsed_ms,
        analyzed_at=analyzed_at,
    )
    headers = {
        "Content-Type": "application/json",
        "X-Internal-Api-Key": settings.internal_api_key,
        "X-Request-ID": request_id,
    }
    url = _callback_url()

    async with httpx.AsyncClient(timeout=10.0) as client:
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                resp = await client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                logger.warning(
                    "analysis_callback.request_failed",
                    analysis_id=result.analysis_id,
                    attempt=attempt,
                    error=str(exc),
                )
            else:
                if 200 <= resp.status_code < 300:
                    logger.info(
                        "analysis_callback.delivered",
                        analysis_id=result.analysis_id,
                        attempt=attempt,
                    )
                    return True
                logger.warning(
                    "analysis_callback.bad_status",
                    analysis_id=result.analysis_id,
                    attempt=attempt,
                    status_code=resp.status_code,
                )

            if attempt < _MAX_ATTEMPTS:
                await asyncio.sleep(0.5 * (2 ** (attempt - 1)))

    logger.error(
        "analysis_callback.dead_letter",
        analysis_id=result.analysis_id,
        callback_url=url,
        attempts=_MAX_ATTEMPTS,
        payload=payload,
    )
    return False
