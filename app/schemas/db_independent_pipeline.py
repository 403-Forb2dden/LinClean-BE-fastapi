from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.domain_heuristic import DomainHeuristicResult
from app.schemas.normalize import NormalizeResult
from app.schemas.pipeline import PipelineStage, PipelineTimings, Verdict
from app.schemas.unchain import UnchainResult


class DbIndependentPipelineStages(BaseModel):
    """외부 threat DB를 제외한 독립 파이프라인 단계 결과."""

    normalize: NormalizeResult
    unchain: UnchainResult
    domain_heuristic: DomainHeuristicResult
    content_analysis: ContentAnalysisResult


class DbIndependentPipelineSuccess(BaseModel):
    """DB 비의존 파이프라인 성공 응답."""

    status: Literal["success"] = "success"
    analysis_id: str
    original_url: str
    final_url: str
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    timings: PipelineTimings | None = None
    stages: DbIndependentPipelineStages


class DbIndependentPipelineFailure(BaseModel):
    status: Literal["failed"] = "failed"
    analysis_id: str
    original_url: str
    failed_at_stage: PipelineStage
    error: str
    timings: PipelineTimings | None = None


DbIndependentPipelineResult = DbIndependentPipelineSuccess | DbIndependentPipelineFailure
