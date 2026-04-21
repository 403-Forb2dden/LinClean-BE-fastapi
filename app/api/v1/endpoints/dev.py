"""개발용 엔드포인트 — debug=true 환경에서만 등록됨."""

from __future__ import annotations

import uuid

from fastapi import APIRouter
from pydantic import BaseModel

from app.api.deps import DBSession
from app.schemas.pipeline import PipelineFailure, PipelineSuccess
from app.services.pipeline import run_pipeline

router = APIRouter()


class DevAnalyzeRequest(BaseModel):
    url: str


@router.post(
    "/analyze",
    response_model=PipelineSuccess | PipelineFailure,
    summary="[Dev] URL 분석 — 동기 결과 반환",
    description="파이프라인을 동기로 실행해 결과를 즉시 반환합니다. debug=true 환경 전용.",
)
async def dev_analyze(body: DevAnalyzeRequest, session: DBSession) -> PipelineSuccess | PipelineFailure:
    analysis_id = str(uuid.uuid4())
    return await run_pipeline(
        analysis_id=analysis_id,
        original_url=body.url,
        session=session,
    )
