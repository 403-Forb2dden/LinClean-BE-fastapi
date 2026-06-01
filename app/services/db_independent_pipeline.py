"""외부 threat DB 비의존 URL 분석 파이프라인."""

from __future__ import annotations

import time

import structlog

from app.core.config import settings
from app.core.exceptions import NormalizationError
from app.schemas.content_analysis import ContentAnalysisResult, ContentSignal
from app.schemas.db_independent_pipeline import (
    DbIndependentPipelineFailure,
    DbIndependentPipelineStages,
    DbIndependentPipelineSuccess,
)
from app.schemas.domain_heuristic import DomainHeuristicResult, DomainHeuristicSignal
from app.schemas.pipeline import (
    PipelineStage,
    PipelineStageTimings,
    PipelineTimings,
    Verdict,
)
from app.schemas.unchain import UnchainResult
from app.services.content_analyzer import analyze_content
from app.services.domain_heuristic import check_domain_heuristic
from app.services.normalizer import normalize_url
from app.services.page_unavailability import (
    PAGE_UNAVAILABLE_CODE,
    content_page_unavailable,
    unchain_page_unavailable,
)
from app.services.pipeline_deadline import (
    PipelineDeadline,
    PipelineStageTimeoutError,
    timed_out_content_result,
    timed_out_domain_result,
    timed_out_unchain_result,
)
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
        return DomainHeuristicSignal.REDIRECT_CROSS_ORIGIN.value
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


def _augment_heuristic_with_redirect_signals(
    heuristic: DomainHeuristicResult,
    unchain: UnchainResult,
) -> DomainHeuristicResult:
    signals = list(heuristic.signals)
    score = heuristic.score
    if (
        any(signal.startswith("cross_origin:") for signal in unchain.signals)
        and DomainHeuristicSignal.REDIRECT_CROSS_ORIGIN not in signals
    ):
        signals.append(DomainHeuristicSignal.REDIRECT_CROSS_ORIGIN)
        score = min(
            score + settings.score_weight_redirect_cross_origin,
            settings.domain_heuristic_score_cap,
        )
    if signals == heuristic.signals and score == heuristic.score:
        return heuristic
    return heuristic.model_copy(update={"signals": signals, "score": score})


def _page_unavailable_content(
    final_url: str,
    *,
    message: str,
    status_code: int | None,
) -> ContentAnalysisResult:
    return ContentAnalysisResult(
        final_url=final_url,
        fetched=False,
        status_code=status_code,
        score=0,
        signals=[ContentSignal.FETCH_FAILED],
        reason=message,
        error="page_unavailable",
    )


def _page_unavailable_failure(
    *,
    analysis_id: str,
    original_url: str,
    final_url: str,
    failed_at_stage: PipelineStage,
    error: str,
    status_code: int | None,
    started: float,
    stage_timings: PipelineStageTimings,
) -> DbIndependentPipelineFailure:
    return DbIndependentPipelineFailure(
        analysis_id=analysis_id,
        original_url=original_url,
        final_url=final_url,
        failed_at_stage=failed_at_stage,
        error=error,
        error_code=PAGE_UNAVAILABLE_CODE,
        status_code=status_code,
        timings=_build_timings(started, stage_timings),
    )


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
    deadline = PipelineDeadline()
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
    try:
        unchain = await deadline.run(
            PipelineStage.UNCHAIN.value,
            unchain_url(
                normalize.normalized_url,
                prefer_https_when_schemeless=normalize.scheme_was_added,
            ),
            settings.pipeline_unchain_timeout_seconds,
        )
    except PipelineStageTimeoutError:
        log.warning("db_independent_pipeline.stage_timeout", stage=PipelineStage.UNCHAIN)
        unchain = timed_out_unchain_result(normalize.normalized_url)
    except Exception as exc:
        log.warning(
            "db_independent_pipeline.stage_error",
            stage=PipelineStage.UNCHAIN,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        unchain = timed_out_unchain_result(normalize.normalized_url, error="stage_error")
    _set_stage_timing(stage_timings, PipelineStage.UNCHAIN, stage_started)

    if unavailable := unchain_page_unavailable(unchain):
        message, status_code = unavailable
        log.info(
            "db_independent_pipeline.page_unavailable",
            stage=PipelineStage.UNCHAIN,
            final_url=unchain.final_url,
            status_code=status_code,
            error=unchain.error,
        )
        stage_started = time.perf_counter()
        try:
            heuristic = await deadline.run(
                PipelineStage.DOMAIN_HEURISTIC.value,
                check_domain_heuristic(unchain.final_url),
                settings.pipeline_domain_timeout_seconds,
            )
        except PipelineStageTimeoutError:
            log.warning(
                "db_independent_pipeline.stage_timeout",
                stage=PipelineStage.DOMAIN_HEURISTIC,
            )
            heuristic = timed_out_domain_result(unchain.final_url)
        except Exception as exc:
            log.warning(
                "db_independent_pipeline.stage_error",
                stage=PipelineStage.DOMAIN_HEURISTIC,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            heuristic = timed_out_domain_result(unchain.final_url)
        _set_stage_timing(stage_timings, PipelineStage.DOMAIN_HEURISTIC, stage_started)
        heuristic = _augment_heuristic_with_redirect_signals(heuristic, unchain)
        content = _page_unavailable_content(
            unchain.final_url,
            message=message,
            status_code=status_code,
        )
        score = _total_score(heuristic, content)
        if score >= settings.score_caution_threshold:
            verdict = _decide_verdict(score)
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
        return _page_unavailable_failure(
            analysis_id=analysis_id,
            original_url=original_url,
            final_url=unchain.final_url,
            failed_at_stage=PipelineStage.UNCHAIN,
            error=message,
            status_code=status_code,
            started=total_started,
            stage_timings=stage_timings,
        )

    stage_started = time.perf_counter()
    try:
        heuristic = await deadline.run(
            PipelineStage.DOMAIN_HEURISTIC.value,
            check_domain_heuristic(unchain.final_url),
            settings.pipeline_domain_timeout_seconds,
        )
    except PipelineStageTimeoutError:
        log.warning(
            "db_independent_pipeline.stage_timeout",
            stage=PipelineStage.DOMAIN_HEURISTIC,
        )
        heuristic = timed_out_domain_result(unchain.final_url)
    except Exception as exc:
        log.warning(
            "db_independent_pipeline.stage_error",
            stage=PipelineStage.DOMAIN_HEURISTIC,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        heuristic = timed_out_domain_result(unchain.final_url)
    _set_stage_timing(stage_timings, PipelineStage.DOMAIN_HEURISTIC, stage_started)
    heuristic = _augment_heuristic_with_redirect_signals(heuristic, unchain)

    upstream = _collect_db_independent_signals(heuristic, unchain)
    stage_started = time.perf_counter()
    try:
        content = await deadline.run(
            PipelineStage.CONTENT_ANALYSIS.value,
            analyze_content(unchain.final_url, upstream_signals=upstream),
            settings.pipeline_content_timeout_seconds,
        )
    except PipelineStageTimeoutError:
        log.warning(
            "db_independent_pipeline.stage_timeout",
            stage=PipelineStage.CONTENT_ANALYSIS,
        )
        content = timed_out_content_result(unchain.final_url)
    except Exception as exc:
        log.warning(
            "db_independent_pipeline.stage_error",
            stage=PipelineStage.CONTENT_ANALYSIS,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        content = timed_out_content_result(unchain.final_url)
    _set_stage_timing(stage_timings, PipelineStage.CONTENT_ANALYSIS, stage_started)

    if unavailable := content_page_unavailable(content):
        message, status_code = unavailable
        log.info(
            "db_independent_pipeline.page_unavailable",
            stage=PipelineStage.CONTENT_ANALYSIS,
            final_url=unchain.final_url,
            status_code=status_code,
            error=content.error,
        )
        score = _total_score(heuristic, content)
        if score >= settings.score_caution_threshold:
            verdict = _decide_verdict(score)
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
        return _page_unavailable_failure(
            analysis_id=analysis_id,
            original_url=original_url,
            final_url=unchain.final_url,
            failed_at_stage=PipelineStage.CONTENT_ANALYSIS,
            error=message,
            status_code=status_code,
            started=total_started,
            stage_timings=stage_timings,
        )

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
