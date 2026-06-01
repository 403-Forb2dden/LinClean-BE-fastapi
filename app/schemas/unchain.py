from pydantic import BaseModel, Field


class HopRecord(BaseModel):
    url: str = Field(description="이 hop에서 요청한 URL")
    status_code: int = Field(description="HTTP 응답 상태 코드")
    raw_location: str | None = Field(default=None, description="Location 헤더 원본 값")
    location: str | None = Field(default=None, description="절대경로로 해석된 Location 값")
    method: str = Field(default="HEAD", description="요청에 사용한 HTTP 메서드")


class UnchainResult(BaseModel):
    input_url: str = Field(description="언체이닝 시작 URL")
    final_url: str = Field(description="최종 도달 URL")
    hops: list[HopRecord] = Field(default_factory=list)
    hop_count: int = Field(default=0)
    timed_out: bool = Field(default=False)
    error: str | None = Field(default=None)
    signals: list[str] = Field(default_factory=list)
