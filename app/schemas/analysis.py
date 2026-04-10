from pydantic import BaseModel, Field


class NormalizeResult(BaseModel):
    """1단계 — URL 정규화(Canonicalization) 결과."""

    original_url: str = Field(description="입력 원본 URL (trim 후)")
    normalized_url: str = Field(description="정규화된 URL")
