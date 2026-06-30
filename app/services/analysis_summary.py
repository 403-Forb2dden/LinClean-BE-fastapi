from __future__ import annotations

from typing import Any

from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.domain_heuristic import DomainHeuristicResult
from app.schemas.threat_db import ThreatDbResult

KNOWN_MALICIOUS_SUMMARY = "악성으로 알려진 페이지 입니다."
SAFE_SUMMARY = "현재 분석 기준에서 뚜렷한 위험 신호가 확인되지 않았습니다."
CAUTION_SUMMARY = "주의가 필요한 페이지입니다. 링크와 입력 정보를 한 번 더 확인하세요."
DANGER_SUMMARY = "위험성이 높은 페이지입니다. 접속과 정보 입력을 피하세요."


def _code(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def build_analysis_summary(
    *,
    verdict: Any,
    threat: ThreatDbResult,
    heuristic: DomainHeuristicResult,
    content: ContentAnalysisResult,
) -> str:
    if threat.is_malicious:
        return KNOWN_MALICIOUS_SUMMARY
    if content.ai_reason:
        return content.ai_reason

    domain_signals = {_code(signal) for signal in heuristic.signals}
    content_signals = {_code(signal) for signal in content.signals}

    if "FETCH_FAILED" in content_signals:
        return content.reason or "페이지를 확인할 수 없어 안전 여부를 판단하기 어렵습니다."
    if "SKIPPED_ALREADY_DANGER" in content_signals:
        return content.reason or DANGER_SUMMARY

    if "BRAND_IMPERSONATION_FORM" in content_signals and (
        content.has_password_field or "SENSITIVE_PATH" in domain_signals
    ):
        return "브랜드 사칭과 로그인 정보 입력 유도 정황이 있어 비밀번호를 입력하지 마세요."
    if "CREDENTIAL_FORM_EXTERNAL" in content_signals:
        return "로그인 정보가 외부 주소로 전송될 수 있어 계정 정보를 입력하지 마세요."
    if "BRAND_IMPERSONATION_FORM" in content_signals or "LOGO_ALT_IMPERSONATION" in content_signals:
        return "브랜드 사칭 정황이 있어 링크와 입력 정보를 신중히 확인하세요."
    if {"PII_COLLECTION_FORM", "SENSITIVE_ID_FIELD", "FINANCIAL_FIELD"} & content_signals:
        return "민감정보 입력을 유도하는 정황이 있어 개인정보나 결제 정보를 입력하지 마세요."
    if "RISKY_DOWNLOAD_LINK" in content_signals:
        return "위험한 파일 다운로드를 유도할 수 있어 파일을 열지 마세요."
    if {"PUBLIC_AGENCY_LURE", "KOREAN_LURE_TEXT"} & content_signals:
        return "국내 사용자 또는 공공기관을 사칭하는 유인 문구가 있어 주의하세요."

    if "TYPO_DOMAIN" in domain_signals:
        return "유명 서비스와 유사한 도메인이므로 로그인이나 결제 정보를 입력하지 마세요."
    if {"URL_USERINFO", "OPEN_REDIRECT_PARAM", "REDIRECT_CROSS_ORIGIN"} & domain_signals:
        return "URL이 다른 사이트 이동이나 위장에 악용될 수 있어 접속 전 주소를 확인하세요."
    if {"NEW_DOMAIN", "SUSPICIOUS_TLD", "DGA_LIKE"} & domain_signals:
        return "신뢰도가 낮은 도메인 특성이 있어 링크와 입력 정보를 한 번 더 확인하세요."

    if content.reason:
        return content.reason
    verdict_code = _code(verdict)
    if verdict_code == "danger":
        return DANGER_SUMMARY
    if verdict_code == "caution":
        return CAUTION_SUMMARY
    return SAFE_SUMMARY
