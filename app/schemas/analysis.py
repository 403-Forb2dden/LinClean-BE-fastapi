from typing import Literal

from pydantic import BaseModel, Field


class NormalizeResult(BaseModel):
    """Stage 1 — URL canonicalization result."""

    original_url: str = Field(description="Original URL after trimming")
    normalized_url: str = Field(description="Canonicalized URL")


class HopRecord(BaseModel):
    """리다이렉트 체인의 개별 hop."""

    url: str = Field(description="이 hop에서 요청한 URL")
    status_code: int = Field(description="HTTP 응답 상태 코드")
    raw_location: str | None = Field(default=None, description="Location 헤더 원본 값(상대경로 포함)")
    location: str | None = Field(default=None, description="절대경로로 해석된 Location 값")
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


class GSBMatch(BaseModel):
    """GSB Lookup 응답의 개별 위협 매치."""

    threat_type: str = Field(description="MALWARE / SOCIAL_ENGINEERING 등")
    platform_type: str | None = Field(default=None, description="ANY_PLATFORM 등")
    cache_duration: str | None = Field(default=None, description="예: '300s'")


class GSBResult(BaseModel):
    """GSB 조회 결과. 실패 시에도 raise 하지 않고 checked=False 로 반환."""

    checked: bool = Field(description="실제 API 호출이 성공적으로 완료됐는지")
    is_threat: bool = Field(default=False, description="하나 이상의 위협 매치 여부")
    matches: list[GSBMatch] = Field(default_factory=list)
    error: str | None = Field(default=None, description="실패 사유 코드")


class URLhausResult(BaseModel):
    """URLhaus 로컬 스냅샷 조회 결과."""

    checked: bool
    is_threat: bool = False
    match_type: Literal["url", "host", "host_path"] | None = None
    matched_key: str | None = None
    threat: str | None = None
    tags: list[str] = Field(default_factory=list)
    urlhaus_link: str | None = None
    error: str | None = None


class ThreatDbResult(BaseModel):
    """Stage 2 — GSB + URLhaus 대조 결과."""

    final_url: str
    is_malicious: bool
    sources_checked: int = Field(description="성공적으로 조회된 외부 소스 수 (0~2)")
    gsb: GSBResult
    urlhaus: URLhausResult
    threat_types: list[str] = Field(default_factory=list)
