"""추출된 피처 + 도메인을 바탕으로 규칙 기반 점수와 신호 코드를 산출한다.

AI 추론 가산은 analyze.py 에서 합산한다 — 여기서는 순수 규칙 레이어만 담당.

브랜드 매칭 전략 — ASCII 라벨은 단어 경계(\b) 매칭, 비-ASCII(한국어 등)는 substring fallback.
영문은 토큰 경계가 명확해 'pineapple' 이 'apple', 'naverstore' 가 'naver' 로 잡히는
substring false-positive 를 경계 매칭으로 차단한다. 형태소 경계가 어려운 한국어/한자
라벨은 substring 으로 받도록 코드 경로가 준비돼 있다. 다만 현재 brands.txt 는 ASCII
라벨만 들어 있어 substring 분기는 dead path 다 — 한국어 라벨 추가 시 자동 활성화된다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from app.core.config import settings
from app.core.tld import extract_url_parts
from app.schemas.content_analysis import ContentSignal
from app.services.content_analyzer.extract import ExtractedFeatures

# typosquatting.py 와 동일한 brands.txt 를 재사용. 경로 변경 시 양쪽을 함께 수정해야 한다.
_BRANDS_FILE = Path(__file__).resolve().parents[1] / "domain_heuristic" / "brands.txt"

# 짧은 브랜드 라벨(kb, sk 등)은 일반 영단어로 오탐되므로 4자 이상만 매칭에 사용.
_MIN_BRAND_LEN = 4


def _read_brand_labels() -> frozenset[str]:
    # BRAND_IMPERSONATION 은 4단계 최고 가중치 시그널 — 라벨이 비면 silent 하게
    # 무력화돼 안전 분석이 약해진다. 여기서 강하게 raise 해 부팅 실패로 만든다.
    if not _BRANDS_FILE.exists():
        raise RuntimeError(
            f"brand labels file missing: {_BRANDS_FILE}. "
            "BRAND_IMPERSONATION/LOGO_ALT_IMPERSONATION 시그널이 무력화된다."
        )
    labels: set[str] = set()
    for line in _BRANDS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ext = extract_url_parts(f"https://{line}")
        if ext.domain and len(ext.domain) >= _MIN_BRAND_LEN:
            labels.add(ext.domain.lower())
    if not labels:
        raise RuntimeError(
            f"brand labels file produced zero labels: {_BRANDS_FILE}"
        )
    return frozenset(labels)


@lru_cache(maxsize=1)
def _brand_label_index() -> tuple[frozenset[str], frozenset[str], re.Pattern[str] | None]:
    """라벨을 lazy 하게 1회만 로드해 (ASCII set, non-ASCII set, ASCII alternation 패턴) 으로 반환.

    예전엔 모듈 임포트 시점에 즉시 raise 하는 방식이라 라벨 파일 경로 변경/스왑 시
    테스트 픽스처 단계에서 import 자체가 죽는 문제가 있었다. lru_cache 로 첫 호출
    시점까지 미루고, 테스트는 `_brand_label_index.cache_clear()` 로 리셋하면 된다.

    운영 정책 — brands.txt 갱신은 프로세스 재시작으로 반영. 핫 리로드는 지원하지 않는다.
    런타임 갱신이 필요해지면 SIGHUP 핸들러나 admin endpoint 로 cache_clear() 를 호출하는
    경로를 별도로 도입해야 한다.
    """
    labels = _read_brand_labels()
    ascii_labels = frozenset(label for label in labels if label.isascii())
    non_ascii_labels = labels - ascii_labels
    pattern = (
        re.compile(r"\b(" + "|".join(re.escape(label) for label in ascii_labels) + r")\b")
        if ascii_labels
        else None
    )
    return ascii_labels, non_ascii_labels, pattern


@dataclass
class ContentScoring:
    score: int = 0
    signals: list[ContentSignal] = field(default_factory=list)
    brand_impersonation: bool = False
    logo_alt_impersonation: bool = False


_SENSITIVE_ID_TYPES: frozenset[str] = frozenset({"resident_registration_number", "otp"})
_PII_FIELD_TYPES: frozenset[str] = frozenset(
    {"resident_registration_number", "phone", "otp"}
)
_FINANCIAL_FIELD_TYPES: frozenset[str] = frozenset({"card", "cvc", "account"})


def _add_signal(result: ContentScoring, signal: ContentSignal, score: int = 0) -> None:
    if signal not in result.signals:
        result.signals.append(signal)
    result.score += score


def _url_brand_label(final_url: str) -> str:
    ext = extract_url_parts(final_url)
    return (ext.domain or "").lower()


def _brands_in_text(text: str | None) -> set[str]:
    # 영문은 \b 경계로만 매치 — 'pineapple' → 'apple', 'naverstore' → 'naver' 같은
    # substring false-positive 차단. 한국어 등 비-ASCII 라벨은 본문에 분리 없이 박히므로 substring.
    # 4자 미만 라벨은 로드 단계에서 이미 제외됐다.
    if not text:
        return set()
    _ascii_labels, non_ascii_labels, ascii_pattern = _brand_label_index()
    lowered = text.lower()
    found: set[str] = set()
    if ascii_pattern is not None:
        found.update(ascii_pattern.findall(lowered))
    for label in non_ascii_labels:
        if label in lowered:
            found.add(label)
    return found


def score_content(features: ExtractedFeatures, final_url: str) -> ContentScoring:
    result = ContentScoring()
    own_label = _url_brand_label(final_url)

    # SPA 셸은 "판정 불가" 표식일 뿐 — 점수는 주지 않는다.
    # 정상 SPA 가 대부분이라 가산하면 오탐이 크다.
    if features.is_spa_shell:
        result.signals.append(ContentSignal.SPA_SHELL)

    if features.has_password_field:
        # 자기 도메인 라벨이 매칭된 브랜드에 있으면 정상.
        # 그 외 브랜드가 하나라도 섞이면 위장으로 판단한다.
        title_brands = _brands_in_text(features.title)
        if title_brands and own_label not in title_brands:
            result.brand_impersonation = True
            result.signals.append(ContentSignal.BRAND_IMPERSONATION_FORM)
            result.score += settings.score_weight_brand_impersonation

    if features.has_password_form_external_action:
        _add_signal(
            result,
            ContentSignal.CREDENTIAL_FORM_EXTERNAL,
            settings.score_weight_credential_form_external,
        )

    sensitive_types = set(features.sensitive_field_types)
    has_pii_fields = bool(sensitive_types & _PII_FIELD_TYPES)
    has_sensitive_id_fields = bool(sensitive_types & _SENSITIVE_ID_TYPES)
    has_financial_fields = bool(sensitive_types & _FINANCIAL_FIELD_TYPES)
    has_lure_text = bool(features.korean_lure_keywords)
    has_public_agency_lure = bool(features.public_agency_keywords)

    if has_lure_text:
        _add_signal(result, ContentSignal.KOREAN_LURE_TEXT)

    if has_public_agency_lure:
        _add_signal(result, ContentSignal.PUBLIC_AGENCY_LURE)

    if has_pii_fields:
        _add_signal(
            result,
            ContentSignal.PII_COLLECTION_FORM,
            settings.score_weight_pii_collection_form,
        )

    if has_sensitive_id_fields:
        _add_signal(
            result,
            ContentSignal.SENSITIVE_ID_FIELD,
            settings.score_weight_sensitive_id_field,
        )

    if has_financial_fields:
        _add_signal(
            result,
            ContentSignal.FINANCIAL_FIELD,
            settings.score_weight_financial_field,
        )

    if features.download_links:
        _add_signal(
            result,
            ContentSignal.RISKY_DOWNLOAD_LINK,
            settings.score_weight_risky_download_link,
        )

    # 루어/기관명은 단독 문구만으로 점수를 만들면 정상 안내 페이지 오탐이 커진다.
    # 실제 입력 폼이나 위험 다운로드와 결합될 때만 추가 가중한다.
    if has_lure_text and (has_pii_fields or has_financial_fields or features.download_links):
        result.score += settings.score_weight_korean_lure

    if has_public_agency_lure and has_pii_fields:
        result.score += settings.score_weight_public_agency_lure

    alt_brands: set[str] = set()
    for alt in features.image_alts:
        alt_brands |= _brands_in_text(alt)
    if alt_brands and own_label not in alt_brands:
        result.logo_alt_impersonation = True
        result.signals.append(ContentSignal.LOGO_ALT_IMPERSONATION)
        result.score += settings.score_weight_logo_alt_impersonation

    if features.has_meta_refresh:
        result.signals.append(ContentSignal.META_REFRESH)
        result.score += settings.score_weight_meta_refresh
        if features.has_external_meta_refresh:
            result.signals.append(ContentSignal.EXTERNAL_META_REFRESH)
            result.score += settings.score_weight_external_meta_refresh

    if (
        features.external_link_ratio is not None
        and features.external_link_ratio >= settings.content_external_link_ratio_threshold
    ):
        result.signals.append(ContentSignal.EXTERNAL_LINK_OVERUSE)
        result.score += settings.score_weight_external_link_overuse

    result.score = min(result.score, settings.content_analysis_score_cap)
    return result
