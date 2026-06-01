from typing import Literal

from pydantic import BaseModel, Field


class GSBMatch(BaseModel):
    threat_type: str = Field(description="MALWARE / SOCIAL_ENGINEERING 등")
    platform_type: str | None = None
    cache_duration: str | None = None


class GSBResult(BaseModel):
    checked: bool = Field(description="API 호출 성공 여부")
    is_threat: bool = False
    matches: list[GSBMatch] = Field(default_factory=list)
    error: str | None = None


class URLhausResult(BaseModel):
    checked: bool
    is_threat: bool = False
    match_type: Literal["url", "host", "host_path"] | None = None
    matched_key: str | None = None
    threat: str | None = None
    tags: list[str] = Field(default_factory=list)
    urlhaus_link: str | None = None
    error: str | None = None


class ThreatDbResult(BaseModel):
    final_url: str
    is_malicious: bool
    sources_checked: int = Field(description="성공적으로 조회된 외부 소스 수 (0~2)")
    gsb: GSBResult
    urlhaus: URLhausResult
    threat_types: list[str] = Field(default_factory=list)
