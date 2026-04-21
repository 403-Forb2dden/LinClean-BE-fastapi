"""POST /api/v1/analyze — Spring 으로부터 URL 분석 위임을 받는 엔드포인트."""

from __future__ import annotations

from fastapi import APIRouter, BackgroundTasks, status

from app.api.deps import InternalApiKey
from app.db.session import SessionLocal
from app.schemas.analyze import AnalyzeAccepted, AnalyzeRequest
from app.services.pipeline import run_pipeline

router = APIRouter()


async def _run_pipeline_task(analysis_id: str, original_url: str) -> None:
    """백그라운드 태스크 전용 래퍼. 세션을 독립적으로 열고 닫는다."""
    async with SessionLocal() as session:
        await run_pipeline(
            analysis_id=analysis_id,
            original_url=original_url,
            session=session,
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
    _: InternalApiKey,
) -> AnalyzeAccepted:
    background_tasks.add_task(
        _run_pipeline_task,
        analysis_id=body.analysis_id,
        original_url=body.url,
    )
    return AnalyzeAccepted(analysis_id=body.analysis_id)
