from pydantic import BaseModel, Field


class NormalizeResult(BaseModel):
    """Stage 1 — URL canonicalization result."""

    original_url: str = Field(description="Original URL after trimming")
    normalized_url: str = Field(description="Canonicalized URL")
