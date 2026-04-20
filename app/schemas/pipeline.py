from enum import Enum
from typing import Literal

from pydantic import BaseModel

from app.schemas.normalize import NormalizeResult
from app.schemas.threat_db import ThreatDbResult
from app.schemas.unchain import UnchainResult


class PipelineStage(str, Enum):
    NORMALIZE = "normalize"
    UNCHAIN = "unchain"
    THREAT_DB = "threat_db"


class PipelineStages(BaseModel):
    """성공한 파이프라인의 각 단계 원시 결과. 모든 필드가 반드시 채워진다."""

    normalize: NormalizeResult
    unchain: UnchainResult
    threat_db: ThreatDbResult


class PipelineSuccess(BaseModel):
    status: Literal["success"] = "success"
    analysis_id: str
    original_url: str
    final_url: str
    stages: PipelineStages


class PipelineFailure(BaseModel):
    status: Literal["failed"] = "failed"
    analysis_id: str
    original_url: str
    failed_at_stage: PipelineStage
    error: str


PipelineResult = PipelineSuccess | PipelineFailure
