from pydantic import BaseModel, Field


class NormalizeResult(BaseModel):
    """Stage 1 — URL canonicalization result."""

    original_url: str = Field(description="Original URL after trimming")
    normalized_url: str = Field(description="Canonicalized URL")


class HopRecord(BaseModel):
    """리다이렉트 체인의 개별 hop."""

    url: str = Field(description="이 hop에서 요청한 URL")
    status_code: int = Field(description="HTTP 응답 상태 코드")
    location: str | None = Field(default=None, description="Location 헤더 값(있을 경우)")
    method: str = Field(default="HEAD", description="요청에 사용한 HTTP 메서드")


class UnchainResult(BaseModel):
    """Stage 2 — URL 언체이닝(리다이렉트 추적) 결과."""

    input_url: str = Field(description="언체이닝 시작 URL")
    final_url: str = Field(description="최종 도달 URL")
    hops: list[HopRecord] = Field(default_factory=list, description="리다이렉트 hop 기록")
    hop_count: int = Field(default=0, description="총 hop 수")
    timed_out: bool = Field(default=False, description="타임아웃 발생 여부")
    error: str | None = Field(default=None, description="체인 중단 사유(에러 발생 시)")
    signals: list[str] = Field(
        default_factory=list,
        description="탐지된 의심 신호 목록",
    )
