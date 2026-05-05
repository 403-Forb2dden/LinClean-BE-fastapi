"""파이프라인 단계 단독 실행 엔드포인트.

운영 라우터에 등록되며 모든 호출은 X-Internal-Api-Key 헤더 인증을 거친다.
각 단계를 단독으로 실행해 응답을 그대로 돌려준다 — Spring 측에서 단계별 결과를
수집하거나 운영 디버깅 시 분기 동작을 확인할 때 쓴다.

| Path                              | Stage      | 호출 함수                       |
|-----------------------------------|------------|---------------------------------|
| POST /normalize                   | Stage 1    | normalize_url + unchain_url     |
| POST /threat-db                   | Stage 2    | check_threat_db                 |
| POST /domain-heuristic            | Stage 3    | check_domain_heuristic          |
| POST /content-analysis            | Stage 4    | analyze_content                 |
| POST /content/fetch-extract       | (보조)     | fetch_page + extract_features   |

전체 파이프라인 동기 실행은 `analyze.py` 의 `POST /analyze/sync`. 비동기 접수는 `POST /analyze`.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.api.deps import DBSession, InternalApiKey
from app.core.exceptions import NormalizationError
from app.schemas.content_analysis import (
    ContentAnalysisResult,
    ExtractedFeaturesView,
    FetchExtractResponse,
    FetchStatusView,
)
from app.schemas.domain_heuristic import DomainHeuristicResult
from app.schemas.normalize import NormalizeResult
from app.schemas.threat_db import ThreatDbResult
from app.schemas.unchain import UnchainResult
from app.services.content_analyzer import analyze_content
from app.services.content_analyzer.extract import extract_features_async
from app.services.content_analyzer.fetch import fetch_page
from app.services.domain_heuristic import check_domain_heuristic
from app.services.normalizer import normalize_url
from app.services.threat_db import check_threat_db
from app.services.unchainer import unchain_url

router = APIRouter()

# HTML 미리보기 상한 — 에디터/브라우저 렌더 부담 없이 원본을 훑기 좋은 크기.
# 슬라이싱은 codepoint 단위라 UTF-8 바이트 길이는 더 클 수 있다.
_HTML_PREVIEW_CHARS = 2048


def _normalize_or_400(raw_url: str) -> str:
    """단계 단독 호출용 — 스킴/IPv6/포트 검증을 normalize_url 로 위임.

    파이프라인은 1단계에서 이걸 거치지만 단독 단계 호출은 raw URL 을 직접 받기 때문에
    여기서 동일한 검증을 통과시켜 file:// 같은 비허용 스킴을 fetch 로 흘리지 않는다.
    SSRF 의 사설 IP 차단은 fetch.py 1선에서 한 번 더 막는다.
    """
    try:
        return normalize_url(raw_url).normalized_url
    except NormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid url: {exc.message}",
        ) from exc


class StageUrlRequest(BaseModel):
    url: str = Field(description="raw URL — 내부에서 normalize_url 을 통과시킨다.")


class StageNormalizeResponse(BaseModel):
    """1단계 응답 — normalize 결과와 unchain 결과를 함께 반환."""

    normalize: NormalizeResult
    unchain: UnchainResult


# ---------------------------------------------------------------------------
# 단계별 API — Stage 1 ~ Stage 4
# ---------------------------------------------------------------------------


@router.post(
    "/normalize",
    response_model=StageNormalizeResponse,
    summary="1단계 — URL 정규화 + 단축 URL 언체이닝",
    description=(
        "normalize_url 로 canonical form 을 만든 뒤 unchain_url 로 리다이렉트 체인을 끝까지 따라가 "
        "최종 URL 을 확정합니다. 2~4단계의 입력이 되는 final_url 을 별도로 확인할 때 사용합니다."
    ),
)
async def stage_normalize(
    body: StageUrlRequest, _: InternalApiKey
) -> StageNormalizeResponse:
    try:
        normalize_result = normalize_url(body.url)
    except NormalizationError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid url: {exc.message}",
        ) from exc
    unchain_result = await unchain_url(normalize_result.normalized_url)
    return StageNormalizeResponse(normalize=normalize_result, unchain=unchain_result)


@router.post(
    "/threat-db",
    response_model=ThreatDbResult,
    summary="2단계 — 외부 위협 DB 대조 (GSB + URLhaus)",
    description=(
        "check_threat_db 를 직접 호출합니다. 입력 URL 은 normalize_url 만 거친 상태로 전달되며 "
        "단축 URL 을 풀고 싶다면 먼저 /normalize 로 final_url 을 얻어 그 값을 넣어야 합니다."
    ),
)
async def stage_threat_db(
    body: StageUrlRequest, session: DBSession, _: InternalApiKey
) -> ThreatDbResult:
    target = _normalize_or_400(body.url)
    return await check_threat_db(session, target)


@router.post(
    "/domain-heuristic",
    response_model=DomainHeuristicResult,
    summary="3단계 — 도메인 휴리스틱 분석",
    description=(
        "check_domain_heuristic 를 직접 호출합니다. RDAP 캐시(24h) 가 적용되며 캐시 미스 시 "
        "최대 약 5초 대기할 수 있습니다. 단축 URL 을 풀고 싶다면 /normalize 를 먼저 호출하세요."
    ),
)
async def stage_domain_heuristic(
    body: StageUrlRequest, _: InternalApiKey
) -> DomainHeuristicResult:
    target = _normalize_or_400(body.url)
    return await check_domain_heuristic(target)


@router.post(
    "/content-analysis",
    response_model=ContentAnalysisResult,
    summary="4단계 — 페이지 콘텐츠 정적 분석 (fetch + extract + signals + AI)",
    description=(
        "analyze_content 를 직접 호출해 규칙 점수 · AI 추론이 합쳐진 ContentAnalysisResult 를 "
        "그대로 반환합니다. 파이프라인 skip 로직은 거치지 않으므로 선행 단계 점수와 무관하게 항상 "
        "실제 분석을 수행합니다. AI 프로바이더는 AI_PROVIDER 설정(기본 auto)을 따릅니다. "
        "이 엔드포인트는 unchainer 를 거치지 않으므로 단축 URL 을 직접 넣으면 "
        "unexpected_redirect 로 떨어집니다 — 단축 URL 은 /normalize 로 먼저 풀어야 합니다. "
        "선행 단계 신호 없이 호출되므로 AI 프롬프트는 페이지 피처만 보고 판정합니다."
    ),
)
async def stage_content_analysis(
    body: StageUrlRequest, _: InternalApiKey
) -> ContentAnalysisResult:
    return await analyze_content(_normalize_or_400(body.url))


# ---------------------------------------------------------------------------
# 보조 — 4단계 내부 fetch+extract 만 분리해서 확인
# ---------------------------------------------------------------------------


@router.post(
    "/content/fetch-extract",
    response_model=FetchExtractResponse,
    summary="(보조) 크롤링 + HTML 파싱 결과 확인",
    description=(
        "fetch_page() + extract_features() 만 수행해서 원본 HTML preview 와 추출된 "
        "피처(title, password 유무, meta refresh, 외부 링크 비율, 이미지 alt)를 반환합니다. "
        "규칙 점수 · AI 추론은 돌리지 않습니다. 4단계 디버깅용 보조 엔드포인트."
    ),
)
async def stage_content_fetch_extract(
    body: StageUrlRequest, _: InternalApiKey
) -> FetchExtractResponse:
    target = _normalize_or_400(body.url)
    fetch_result = await fetch_page(target)
    fetch_view = FetchStatusView(
        ok=fetch_result.ok,
        status_code=fetch_result.status_code,
        html_length=len(fetch_result.html),
        error=fetch_result.error,
    )

    if not fetch_result.ok:
        return FetchExtractResponse(url=target, fetch=fetch_view)

    features = await extract_features_async(fetch_result.html, base_url=target)
    return FetchExtractResponse(
        url=target,
        fetch=fetch_view,
        features=ExtractedFeaturesView(
            title=features.title,
            has_password_field=features.has_password_field,
            has_meta_refresh=features.has_meta_refresh,
            external_link_ratio=features.external_link_ratio,
            image_alts=features.image_alts,
            is_spa_shell=features.is_spa_shell,
        ),
        html_preview=fetch_result.html[:_HTML_PREVIEW_CHARS],
    )
