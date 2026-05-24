"""외부 threat DB 비의존 URL 분석 파이프라인."""

from __future__ import annotations

import time

import structlog

from app.core.config import settings
from app.core.exceptions import NormalizationError
from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.db_independent_pipeline import (
    DbIndependentPipelineFailure,
    DbIndependentPipelineStages,
    DbIndependentPipelineSuccess,
)
from app.schemas.domain_heuristic import DomainHeuristicResult
from app.schemas.pipeline import (
    PipelineStage,
    PipelineStageTimings,
    PipelineTimings,
    Verdict,
)
from app.schemas.unchain import UnchainResult
from app.services.content_analyzer import analyze_content, skipped_already_danger
from app.services.domain_heuristic import check_domain_heuristic
from app.services.normalizer import normalize_url
from app.services.unchainer import unchain_url

logger = structlog.get_logger(__name__)


def _elapsed_seconds(started: float) -> float:
    return round(time.perf_counter() - started, 6)


def _set_stage_timing(
    timings: PipelineStageTimings,
    stage: PipelineStage,
    started: float,
) -> None:
    setattr(timings, stage.value, _elapsed_seconds(started))


def _build_timings(started: float, stage_timings: PipelineStageTimings) -> PipelineTimings:
    return PipelineTimings(
        total_seconds=_elapsed_seconds(started),
        stages=stage_timings,
    )


def _decide_verdict(score: int) -> Verdict:
    if score >= settings.score_danger_threshold:
        return Verdict.DANGER
    if score >= settings.score_caution_threshold:
        return Verdict.CAUTION
    return Verdict.SAFE


def _total_score(
    heuristic: DomainHeuristicResult,
    content: ContentAnalysisResult,
) -> int:
    return min(heuristic.score + content.score, settings.score_total_cap)


def _redirect_signal_code(raw_signal: str) -> str | None:
    if raw_signal.startswith("cross_origin:"):
        return "REDIRECT_CROSS_ORIGIN"
    if raw_signal == "scheme_downgrade":
        return "REDIRECT_SCHEME_DOWNGRADE"
    if raw_signal == "redirect_loop":
        return "REDIRECT_LOOP"
    if raw_signal == "max_hops_reached":
        return "REDIRECT_MAX_HOPS_REACHED"
    if raw_signal.startswith("unsafe_scheme:"):
        return "REDIRECT_UNSAFE_SCHEME"
    if raw_signal == "ssrf_blocked":
        return "REDIRECT_SSRF_BLOCKED"
    return None


def _collect_db_independent_signals(
    heuristic: DomainHeuristicResult,
    unchain: UnchainResult,
) -> tuple[str, ...]:
    codes: list[str] = [signal.value for signal in heuristic.signals]
    for raw_signal in unchain.signals:
        code = _redirect_signal_code(raw_signal)
        if code is not None and code not in codes:
            codes.append(code)
    return tuple(codes)


async def run_db_independent_pipeline(
    analysis_id: str,
    original_url: str,
) -> DbIndependentPipelineSuccess | DbIndependentPipelineFailure:
    """GSB/URLhaus 조회 없이 URL·리다이렉트·도메인 신호로 판정한다."""
    log = logger.bind(analysis_id=analysis_id, pipeline="db_independent")
    log.info("db_independent_pipeline.start", url=original_url)
    total_started = time.perf_counter()
    stage_timings = PipelineStageTimings()

    stage_started = time.perf_counter()
    try:
        normalize = normalize_url(original_url)
    except NormalizationError as exc:
        _set_stage_timing(stage_timings, PipelineStage.NORMALIZE, stage_started)
        log.warning("db_independent_pipeline.failed", stage=PipelineStage.NORMALIZE, error=str(exc))
        return DbIndependentPipelineFailure(
            analysis_id=analysis_id,
            original_url=original_url,
            failed_at_stage=PipelineStage.NORMALIZE,
            error=str(exc),
            timings=_build_timings(total_started, stage_timings),
        )
    _set_stage_timing(stage_timings, PipelineStage.NORMALIZE, stage_started)

    stage_started = time.perf_counter()
    unchain = await unchain_url(
        normalize.normalized_url,
        prefer_https_when_schemeless=normalize.scheme_was_added,
    )
    _set_stage_timing(stage_timings, PipelineStage.UNCHAIN, stage_started)

    stage_started = time.perf_counter()
    heuristic = await check_domain_heuristic(unchain.final_url)
    _set_stage_timing(stage_timings, PipelineStage.DOMAIN_HEURISTIC, stage_started)

    if heuristic.score >= settings.score_danger_threshold:
        stage_started = time.perf_counter()
        content = skipped_already_danger(unchain.final_url)
        _set_stage_timing(stage_timings, PipelineStage.CONTENT_ANALYSIS, stage_started)
    else:
        upstream = _collect_db_independent_signals(heuristic, unchain)
        stage_started = time.perf_counter()
        content = await analyze_content(unchain.final_url, upstream_signals=upstream)
        _set_stage_timing(stage_timings, PipelineStage.CONTENT_ANALYSIS, stage_started)

    score = _total_score(heuristic, content)
    verdict = _decide_verdict(score)
    log.info(
        "db_independent_pipeline.done",
        final_url=unchain.final_url,
        verdict=verdict.value,
        score=score,
    )
    return DbIndependentPipelineSuccess(
        analysis_id=analysis_id,
        original_url=original_url,
        final_url=unchain.final_url,
        verdict=verdict,
        score=score,
        timings=_build_timings(total_started, stage_timings),
        stages=DbIndependentPipelineStages(
            normalize=normalize,
            unchain=unchain,
            domain_heuristic=heuristic,
            content_analysis=content,
        ),
    )
