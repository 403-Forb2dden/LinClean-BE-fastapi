"""POST /api/v1/analyze 계열 — Spring 으로부터 URL 분석 위임을 받는 엔드포인트.

- POST /analyze      : 비동기 접수 (202). BackgroundTasks 로 파이프라인 실행 후
                       결과를 Spring 에 callback.
- POST /analyze/sync : 동기 실행 (200). 단건 호출 시 1~4단계 + verdict 를 즉시 반환.
                       디버그/QA 용.

두 엔드포인트 모두 X-Internal-Api-Key 헤더 인증을 거친다.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, BackgroundTasks, Request, status
from pydantic import BaseModel

from app.api.deps import DBSession, InternalApiKey
from app.db.session import SessionLocal
from app.schemas.analyze import AnalyzeAccepted, AnalyzeRequest
from app.schemas.db_independent_pipeline import (
    DbIndependentPipelineFailure,
    DbIndependentPipelineSuccess,
)
from app.schemas.pipeline import PipelineFailure, PipelineSuccess
from app.services.analysis_callback import post_analysis_callback
from app.services.db_independent_pipeline import run_db_independent_pipeline
from app.services.pipeline import run_pipeline

router = APIRouter()


async def _run_pipeline_task(analysis_id: str, original_url: str, request_id: str) -> None:
    """백그라운드 태스크 전용 래퍼. 세션을 독립적으로 열고 닫는다."""
    started = time.perf_counter()
    async with SessionLocal() as session:
        result = await run_pipeline(
            analysis_id=analysis_id,
            original_url=original_url,
            session=session,
        )
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    await post_analysis_callback(
        result,
        request_id=request_id,
        elapsed_ms=elapsed_ms,
        analyzed_at=datetime.now(tz=UTC),
    )


@router.post(
    "/analyze",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=AnalyzeAccepted,
    response_model_by_alias=True,
    summary="URL 분석 위임 접수",
)
async def analyze(
    body: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    _: InternalApiKey,
) -> AnalyzeAccepted:
    request_id = str(request.scope.get("request_id") or uuid.uuid4())
    background_tasks.add_task(
        _run_pipeline_task,
        analysis_id=body.analysis_id,
        original_url=body.url,
        request_id=request_id,
    )
    return AnalyzeAccepted(analysis_id=body.analysis_id)


class AnalyzeSyncRequest(BaseModel):
    url: str


@router.post(
    "/analyze/sync",
    response_model=PipelineSuccess | PipelineFailure,
    summary="전체 파이프라인 — 동기 결과 반환",
    description=(
        "run_pipeline 을 동기로 실행해 1~4단계 + verdict 를 즉시 반환합니다. "
        "단건 디버그/QA 용 — 본 호출은 RDAP·콘텐츠 페치·AI 추론을 모두 포함하므로 "
        "지연이 길 수 있습니다. 운영 트래픽은 비동기 /analyze 를 사용하세요."
    ),
)
async def analyze_sync(
    body: AnalyzeSyncRequest,
    session: DBSession,
    _: InternalApiKey,
) -> PipelineSuccess | PipelineFailure:
    analysis_id = str(uuid.uuid4())
    return await run_pipeline(
        analysis_id=analysis_id,
        original_url=body.url,
        session=session,
    )


@router.post(
    "/analyze/no-ai/sync",
    response_model=PipelineSuccess | PipelineFailure,
    summary="전체 파이프라인 — AI 비사용 동기 결과 반환",
    description=(
        "run_pipeline 을 AI 추론 없이 동기로 실행합니다. normalize, unchain, threat DB, "
        "도메인 휴리스틱, 콘텐츠 정적 분석은 수행하지만 OpenAI provider 를 호출하지 않고 "
        "AI verdict/score 가산 없이 규칙 기반 verdict 와 summary 를 반환합니다."
    ),
)
async def analyze_no_ai_sync(
    body: AnalyzeSyncRequest,
    session: DBSession,
    _: InternalApiKey,
) -> PipelineSuccess | PipelineFailure:
    analysis_id = str(uuid.uuid4())
    return await run_pipeline(
        analysis_id=analysis_id,
        original_url=body.url,
        session=session,
        use_ai=False,
    )


@router.post(
    "/analyze/db-independent/sync",
    response_model=DbIndependentPipelineSuccess | DbIndependentPipelineFailure,
    summary="DB 비의존 파이프라인 — 동기 결과 반환",
    description=(
        "GSB, URLhaus 등 외부 threat DB 조회 없이 URL 정규화, 리다이렉트 체인, "
        "도메인 휴리스틱, 콘텐츠 정적 분석 결과만으로 verdict/score 를 산출합니다. "
        "외부 DB 의존도를 제거한 실험·QA 용 경로입니다."
    ),
)
async def analyze_db_independent_sync(
    body: AnalyzeSyncRequest,
    _: InternalApiKey,
) -> DbIndependentPipelineSuccess | DbIndependentPipelineFailure:
    analysis_id = str(uuid.uuid4())
    return await run_db_independent_pipeline(
        analysis_id=analysis_id,
        original_url=body.url,
    )
