from typing import Literal

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    model_config = {"populate_by_name": True}

    analysis_id: str = Field(alias="analysisId")
    url: str


class AnalyzeAccepted(BaseModel):
    model_config = {"populate_by_name": True}

    analysis_id: str = Field(alias="analysisId")
    status: Literal["queued"] = "queued"
