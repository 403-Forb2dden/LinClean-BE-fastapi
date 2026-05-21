from pydantic import BaseModel, Field


class NormalizeResult(BaseModel):
    original_url: str = Field(description="Original URL after trimming")
    normalized_url: str = Field(description="Canonicalized URL")
    scheme_was_added: bool = Field(
        default=False,
        description="True when the request URL had no explicit scheme and normalizer added one",
    )
