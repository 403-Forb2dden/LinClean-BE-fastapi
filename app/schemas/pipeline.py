from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, Field

from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.domain_heuristic import DomainHeuristicResult
from app.schemas.normalize import NormalizeResult
from app.schemas.threat_db import ThreatDbResult
from app.schemas.unchain import UnchainResult


class PipelineStage(StrEnum):
    NORMALIZE = "normalize"
    UNCHAIN = "unchain"
    THREAT_DB = "threat_db"
    DOMAIN_HEURISTIC = "domain_heuristic"
    CONTENT_ANALYSIS = "content_analysis"


class Verdict(StrEnum):
    """종합 판정 — UI 의 색상/카피 분기 기준.

    score 만으로 매핑하되, 외부 위협 DB 매치(`threat_db.is_malicious=True`) 면
    점수와 무관하게 강제로 DANGER 가 된다. blacklist 매치 = 알려진 악성 URL 이라
    점수 합산이 임계 미달이어도 verdict 자체는 danger 가 맞다.
    """

    SAFE = "safe"
    CAUTION = "caution"
    DANGER = "danger"


class PipelineStages(BaseModel):
    """성공한 파이프라인의 각 단계 원시 결과. 모든 필드가 반드시 채워진다."""

    normalize: NormalizeResult
    unchain: UnchainResult
    threat_db: ThreatDbResult
    domain_heuristic: DomainHeuristicResult
    content_analysis: ContentAnalysisResult


class PipelineStageTimings(BaseModel):
    """단계별 소요 시간(초). 실행되지 않은 단계는 None 으로 남긴다."""

    normalize: float | None = Field(default=None, ge=0)
    unchain: float | None = Field(default=None, ge=0)
    threat_db: float | None = Field(default=None, ge=0)
    domain_heuristic: float | None = Field(default=None, ge=0)
    content_analysis: float | None = Field(default=None, ge=0)


class PipelineTimings(BaseModel):
    """파이프라인 전체 wall-clock 시간과 단계별 소요 시간(초)."""

    total_seconds: float = Field(ge=0)
    stages: PipelineStageTimings


class PipelineSuccess(BaseModel):
    """파이프라인 성공 응답. verdict/score 는 stages 합산의 결론이라 응답 상단에 노출 —
    클라이언트가 stages 트리를 파싱하지 않고도 곧장 사용자에게 보여줄 수 있게 한다."""

    status: Literal["success"] = "success"
    analysis_id: str
    original_url: str
    final_url: str
    verdict: Verdict
    score: int = Field(ge=0, le=100)
    timings: PipelineTimings | None = None
    stages: PipelineStages


class PipelineFailure(BaseModel):
    status: Literal["failed"] = "failed"
    analysis_id: str
    original_url: str
    final_url: str | None = None
    failed_at_stage: PipelineStage
    error: str
    error_code: str | None = None
    status_code: int | None = None
    timings: PipelineTimings | None = None


PipelineResult = PipelineSuccess | PipelineFailure
