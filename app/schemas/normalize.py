from pydantic import BaseModel, Field


class NormalizeResult(BaseModel):
    original_url: str = Field(description="Original URL after trimming")
    normalized_url: str = Field(description="Canonicalized URL")
