from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable
from typing import TypeVar
from urllib.parse import urlparse

from app.core.config import settings
from app.core.tld import extract_url_parts
from app.schemas.content_analysis import ContentAnalysisResult, ContentSignal
from app.schemas.domain_heuristic import DomainHeuristicResult
from app.schemas.threat_db import GSBResult, ThreatDbResult, URLhausResult
from app.schemas.unchain import UnchainResult

T = TypeVar("T")


class PipelineStageTimeoutError(TimeoutError):
    def __init__(self, stage: str) -> None:
        super().__init__(f"{stage} timed out")
        self.stage = stage


class PipelineDeadline:
    def __init__(self, total_seconds: float | None = None) -> None:
        self._started = time.perf_counter()
        self._total_seconds = total_seconds or settings.pipeline_total_timeout_seconds

    def remaining(self) -> float:
        return max(0.0, self._total_seconds - (time.perf_counter() - self._started))

    def budget(self, stage_seconds: float) -> float:
        # 작은 양수로 wait_for까지 진입시켜 stage timeout 경로를 일관되게 탄다.
        return max(0.001, min(stage_seconds, self.remaining()))

    async def run(self, stage: str, coro: Awaitable[T], stage_seconds: float) -> T:
        try:
            return await asyncio.wait_for(coro, timeout=self.budget(stage_seconds))
        except TimeoutError as exc:
            raise PipelineStageTimeoutError(stage) from exc


def timed_out_unchain_result(url: str, *, error: str = "pipeline_timeout") -> UnchainResult:
    return UnchainResult(
        input_url=url,
        final_url=url,
        hops=[],
        hop_count=0,
        timed_out=True,
        error=error,
        signals=[error],
    )


def timed_out_threat_db_result(final_url: str) -> ThreatDbResult:
    return ThreatDbResult(
        final_url=final_url,
        is_malicious=False,
        sources_checked=0,
        gsb=GSBResult(checked=False, is_threat=False, error="pipeline_timeout"),
        urlhaus=URLhausResult(checked=False, is_threat=False, error="pipeline_timeout"),
        threat_types=[],
    )


def timed_out_domain_result(final_url: str) -> DomainHeuristicResult:
    ext = extract_url_parts(final_url)
    domain = ext.top_domain_under_public_suffix or (urlparse(final_url).hostname or "")
    return DomainHeuristicResult(
        domain=domain,
        score=0,
        signals=[],
        rdap=None,
        rdap_error="pipeline_timeout",
    )


def timed_out_content_result(final_url: str) -> ContentAnalysisResult:
    return ContentAnalysisResult(
        final_url=final_url,
        fetched=False,
        status_code=None,
        score=settings.score_weight_content_fetch_failed,
        signals=[ContentSignal.FETCH_FAILED],
        reason="콘텐츠 분석 시간이 초과되었습니다.",
        error="pipeline_timeout",
    )
