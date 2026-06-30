"""URL 분석 파이프라인 오케스트레이터."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable
from contextlib import suppress
from typing import TYPE_CHECKING, TypeVar
from urllib.parse import urlparse

import structlog

from app.core.config import settings
from app.core.exceptions import NormalizationError
from app.core.tld import extract_url_parts
from app.schemas.content_analysis import ContentAnalysisResult, ContentSignal
from app.schemas.domain_heuristic import (
    DomainHeuristicResult,
    DomainHeuristicSignal,
    DomainHeuristicSkippedReason,
)
from app.schemas.normalize import NormalizeResult
from app.schemas.pipeline import (
    PipelineFailure,
    PipelineStage,
    PipelineStages,
    PipelineStageTimings,
    PipelineSuccess,
    PipelineTimings,
    Verdict,
)
from app.schemas.threat_db import ThreatDbResult
from app.schemas.unchain import UnchainResult
from app.services.analysis_summary import build_analysis_summary
from app.services.content_analyzer import analyze_content, skipped_already_danger
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
    timed_out_threat_db_result,
    timed_out_unchain_result,
)
from app.services.threat_db import check_threat_db
from app.services.unchainer import unchain_url

logger = structlog.get_logger(__name__)

T = TypeVar("T")

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


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


async def _timed_async_stage(
    timings: PipelineStageTimings,
    stage: PipelineStage,
    coro: Awaitable[T],
) -> T:
    started = time.perf_counter()
    try:
        return await coro
    finally:
        _set_stage_timing(timings, stage, started)


def _stage_normalize(log: structlog.stdlib.BoundLogger, original_url: str) -> NormalizeResult:
    result = normalize_url(original_url)
    log.info("pipeline.normalize.done", normalized_url=result.normalized_url)
    return result


async def _stage_unchain(log: structlog.stdlib.BoundLogger, normalized_url: str) -> UnchainResult:
    result = await unchain_url(normalized_url)
    log.info(
        "pipeline.unchain.done",
        final_url=result.final_url,
        hops=result.hop_count,
        signals=result.signals,
    )
    return result


async def _stage_threat_db(
    log: structlog.stdlib.BoundLogger,
    final_url: str,
    session: AsyncSession,
    original_url: str | None = None,
) -> ThreatDbResult:
    if original_url and original_url != final_url:
        result = await check_threat_db(session, final_url, original_url=original_url)
    else:
        result = await check_threat_db(session, final_url)
    log.info(
        "pipeline.threat_db.done",
        is_malicious=result.is_malicious,
        sources_checked=result.sources_checked,
    )
    return result


async def _stage_domain_heuristic(
    log: structlog.stdlib.BoundLogger, final_url: str
) -> DomainHeuristicResult:
    result = await check_domain_heuristic(final_url)
    log.info(
        "pipeline.domain_heuristic.done",
        score=result.score,
        signals=[s.value for s in result.signals],
    )
    return result


def _collect_upstream_signals(
    threat: ThreatDbResult, heuristic: DomainHeuristicResult
) -> tuple[str, ...]:
    """선행 단계 시그널을 한 줄 코드 배열로 평탄화. AI 프롬프트의 사전 정보로 쓰인다.

    threat_db 측은 enum 시그널이 없어 매치 여부를 명시 코드(GSB_THREAT/URLHAUS_THREAT)로
    합성해 넣는다. 이 단계에 도달했다는 건 short-circuit 미발동 = is_malicious=False 라는
    뜻이라 두 코드 모두 평소엔 비어있지만, 미래에 약한 매치가 합산만 막혔을 케이스도
    누락 없이 전달하기 위해 명시적으로 합산한다.
    """
    codes: list[str] = [s.value for s in heuristic.signals]
    if threat.gsb.is_threat:
        codes.append("GSB_THREAT")
    if threat.urlhaus.is_threat:
        codes.append("URLHAUS_THREAT")
    return tuple(codes)


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


async def _stage_content_analysis(
    log: structlog.stdlib.BoundLogger,
    final_url: str,
    upstream_signals: tuple[str, ...],
    *,
    use_ai: bool,
) -> ContentAnalysisResult:
    result = await analyze_content(final_url, upstream_signals=upstream_signals, use_ai=use_ai)
    log.info(
        "pipeline.content_analysis.done",
        fetched=result.fetched,
        score=result.score,
        signals=[s.value for s in result.signals],
        ai_verdict=result.ai_verdict.value if result.ai_verdict else None,
        use_ai=use_ai,
        upstream_signals=list(upstream_signals),
    )
    return result


def _preceding_score(threat: ThreatDbResult, heuristic: DomainHeuristicResult) -> int:
    """2~3단계 누적 점수. 4단계 건너뛸지 판단하는 기준."""
    score = heuristic.score
    if threat.gsb.is_threat:
        score += settings.score_weight_gsb
    if threat.urlhaus.is_threat:
        score += settings.score_weight_urlhaus
    return score


def _total_score(
    threat: ThreatDbResult,
    heuristic: DomainHeuristicResult,
    content: ContentAnalysisResult,
) -> int:
    """전 단계 합산 후 100 으로 캡. content.score 는 4단계가 실제로 돌았을 때만 비-0."""
    if threat.is_malicious:
        return settings.score_total_cap
    return min(
        _preceding_score(threat, heuristic) + content.score,
        settings.score_total_cap,
    )


def _decide_verdict(score: int, threat: ThreatDbResult) -> Verdict:
    """Known malicious 매치는 danger. 나머지는 점수 구간으로 매핑."""
    if threat.is_malicious:
        return Verdict.DANGER
    if score >= settings.score_danger_threshold:
        return Verdict.DANGER
    if score >= settings.score_caution_threshold:
        return Verdict.CAUTION
    return Verdict.SAFE


def _skipped_heuristic(final_url: str) -> DomainHeuristicResult:
    """threat match 로 조기 종료된 경우 heuristic 자리에 들어갈 placeholder.

    score=0 이라 합산에 영향 없고, skipped_reason 으로 "우리가 건너뛴 것" 을 식별 가능하게
    남긴다. 응답 스키마의 heuristic 필드가 필수라서 빈 객체라도 채워야 하는 제약 때문.

    domain 값은 정상 경로(check_domain_heuristic)와 동일하게 등록 가능 도메인을 쓴다.
    full host 를 쓰면 같은 필드에 의미가 두 가지로 갈리고, 다운스트림에서
    `signin.evil.example.com` 와 `example.com` 이 다른 버킷으로 잡힌다.
    """
    ext = extract_url_parts(final_url)
    domain = ext.top_domain_under_public_suffix or (urlparse(final_url).hostname or "")
    return DomainHeuristicResult(
        domain=domain,
        score=0,
        signals=[],
        rdap=None,
        rdap_error=None,
        skipped_reason=DomainHeuristicSkippedReason.THREAT_MATCHED,
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
) -> PipelineFailure:
    return PipelineFailure(
        analysis_id=analysis_id,
        original_url=original_url,
        final_url=final_url,
        failed_at_stage=failed_at_stage,
        error=error,
        error_code=PAGE_UNAVAILABLE_CODE,
        status_code=status_code,
        timings=_build_timings(started, stage_timings),
    )


def _pipeline_success(
    *,
    analysis_id: str,
    original_url: str,
    final_url: str,
    verdict: Verdict,
    score: int,
    started: float,
    stage_timings: PipelineStageTimings,
    normalize: NormalizeResult,
    unchain: UnchainResult,
    threat: ThreatDbResult,
    heuristic: DomainHeuristicResult,
    content: ContentAnalysisResult,
) -> PipelineSuccess:
    return PipelineSuccess(
        analysis_id=analysis_id,
        original_url=original_url,
        final_url=final_url,
        verdict=verdict,
        score=score,
        summary=build_analysis_summary(
            verdict=verdict,
            threat=threat,
            heuristic=heuristic,
            content=content,
        ),
        timings=_build_timings(started, stage_timings),
        stages=PipelineStages(
            normalize=normalize,
            unchain=unchain,
            threat_db=threat,
            domain_heuristic=heuristic,
            content_analysis=content,
        ),
    )


async def _run_stage_2_and_3(
    log: structlog.stdlib.BoundLogger,
    final_url: str,
    original_url: str,
    session: AsyncSession,
    timings: PipelineStageTimings,
) -> tuple[ThreatDbResult, DomainHeuristicResult, bool]:
    """2·3단계를 병렬 실행한다. threat_db 가 먼저 malicious 로 끝나면 heuristic 을
    즉시 cancel 하고 조기 종료 플래그를 세워 반환한다.

    반환: (threat, heuristic, short_circuited).
    short_circuited=True 면 heuristic 은 placeholder 이고 4단계는 skip 대상.
    `CancelledError` 와 stage 내부 예외는 남은 task 를 정리한 뒤 그대로 re-raise.
    """
    threat_task = asyncio.create_task(
        _timed_async_stage(
            timings,
            PipelineStage.THREAT_DB,
            _stage_threat_db(log, final_url, session, original_url),
        )
    )
    heur_task = asyncio.create_task(
        _timed_async_stage(
            timings,
            PipelineStage.DOMAIN_HEURISTIC,
            _stage_domain_heuristic(log, final_url),
        )
    )

    try:
        done, _ = await asyncio.wait(
            {threat_task, heur_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        # short-circuit 시 두 분기 모두 _skipped_heuristic 으로 통일한다 — task 종료 순서에
        # 따라 응답 score 가 placeholder(0) ↔ 실제 점수(15~80) 로 갈리는 비결정성을 제거.
        # verdict 는 어차피 DANGER 강제라 사용자 영향은 없지만, 옵저버빌리티/회귀 재현성을
        # 위해 동일 입력에 동일 score 가 나오도록 박는다.
        if threat_task in done:
            threat: ThreatDbResult = threat_task.result()
            if threat.is_malicious:
                # RDAP 대기로 5s 가까이 떠 있을 수 있는 heuristic 을 cancel 로 회수.
                heur_task.cancel()
                with suppress(asyncio.CancelledError):
                    await heur_task
                return threat, _skipped_heuristic(final_url), True
            heuristic: DomainHeuristicResult = await heur_task
            return threat, heuristic, False

        # heuristic 이 먼저 끝난 경로. threat 는 이미 거의 끝났을 가능성이 높으므로 대기한다.
        heuristic = heur_task.result()
        threat = await threat_task
        if threat.is_malicious:
            # 양쪽 다 완료된 뒤 malicious 로 드러난 경우 — heuristic 은 실제 점수가 있지만
            # 위 분기와 응답 일관성을 맞추기 위해 placeholder 로 갈아치운다.
            return threat, _skipped_heuristic(final_url), True
        return threat, heuristic, False
    except BaseException:
        # 상위 cancel 또는 stage 내부 예외 — 남은 task 가 고아로 떠돌지 않게 정리하고 전파.
        for task in (threat_task, heur_task):
            if not task.done():
                task.cancel()
        raise


async def run_pipeline(
    analysis_id: str,
    original_url: str,
    session: AsyncSession,
    *,
    use_ai: bool = True,
) -> PipelineSuccess | PipelineFailure:
    log = logger.bind(analysis_id=analysis_id)
    log.info("pipeline.start", url=original_url)
    total_started = time.perf_counter()
    deadline = PipelineDeadline()
    stage_timings = PipelineStageTimings()

    stage_started = time.perf_counter()
    try:
        norm = _stage_normalize(log, original_url)
    except NormalizationError as exc:
        _set_stage_timing(stage_timings, PipelineStage.NORMALIZE, stage_started)
        log.warning("pipeline.failed", stage=PipelineStage.NORMALIZE, error=str(exc))
        return PipelineFailure(
            analysis_id=analysis_id,
            original_url=original_url,
            failed_at_stage=PipelineStage.NORMALIZE,
            error=str(exc),
            timings=_build_timings(total_started, stage_timings),
        )
    _set_stage_timing(stage_timings, PipelineStage.NORMALIZE, stage_started)

    stage_started = time.perf_counter()
    try:
        unchain: UnchainResult = await deadline.run(
            PipelineStage.UNCHAIN.value,
            _timed_async_stage(
                stage_timings,
                PipelineStage.UNCHAIN,
                unchain_url(
                    norm.normalized_url,
                    prefer_https_when_schemeless=norm.scheme_was_added,
                ),
            ),
            settings.pipeline_unchain_timeout_seconds,
        )
    except PipelineStageTimeoutError:
        log.warning("pipeline.stage_timeout", stage=PipelineStage.UNCHAIN)
        unchain = timed_out_unchain_result(norm.normalized_url)
        if stage_timings.unchain is None:
            _set_stage_timing(stage_timings, PipelineStage.UNCHAIN, stage_started)
    except Exception as exc:
        log.warning(
            "pipeline.stage_error",
            stage=PipelineStage.UNCHAIN,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        unchain = timed_out_unchain_result(norm.normalized_url, error="stage_error")
        if stage_timings.unchain is None:
            _set_stage_timing(stage_timings, PipelineStage.UNCHAIN, stage_started)

    if unavailable := unchain_page_unavailable(unchain):
        message, status_code = unavailable
        log.info(
            "pipeline.page_unavailable",
            stage=PipelineStage.UNCHAIN,
            final_url=unchain.final_url,
            status_code=status_code,
            error=unchain.error,
        )
        try:
            threat, heuristic, _ = await deadline.run(
                "reputation",
                _run_stage_2_and_3(
                    log,
                    unchain.final_url,
                    norm.normalized_url,
                    session,
                    stage_timings,
                ),
                settings.pipeline_reputation_timeout_seconds,
            )
        except PipelineStageTimeoutError:
            log.warning("pipeline.stage_timeout", stage="reputation")
            threat = timed_out_threat_db_result(unchain.final_url)
            heuristic = timed_out_domain_result(unchain.final_url)
        except Exception as exc:
            log.warning(
                "pipeline.stage_error",
                stage="reputation",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            threat = timed_out_threat_db_result(unchain.final_url)
            heuristic = timed_out_domain_result(unchain.final_url)

        heuristic = _augment_heuristic_with_redirect_signals(heuristic, unchain)
        content = _page_unavailable_content(
            unchain.final_url,
            message=message,
            status_code=status_code,
        )
        score = _total_score(threat, heuristic, content)
        if threat.is_malicious or score >= settings.score_caution_threshold:
            verdict = _decide_verdict(score, threat)
            return _pipeline_success(
                analysis_id=analysis_id,
                original_url=original_url,
                final_url=unchain.final_url,
                verdict=verdict,
                score=score,
                started=total_started,
                stage_timings=stage_timings,
                normalize=norm,
                unchain=unchain,
                threat=threat,
                heuristic=heuristic,
                content=content,
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

    # 2·3단계는 둘 다 unchain.final_url 만 필요하고 서로 독립이라 병렬로 돈다.
    # threat_db 가 먼저 malicious 로 끝나면 verdict 가 이미 danger 로 확정이므로
    # heuristic 을 cancel 하고 4단계까지 skip — 여기서 조기 종료가 일어난다.
    try:
        threat, heuristic, short_circuited = await deadline.run(
            "reputation",
            _run_stage_2_and_3(
                log,
                unchain.final_url,
                norm.normalized_url,
                session,
                stage_timings,
            ),
            settings.pipeline_reputation_timeout_seconds,
        )
    except PipelineStageTimeoutError:
        log.warning("pipeline.stage_timeout", stage="reputation")
        threat = timed_out_threat_db_result(unchain.final_url)
        heuristic = timed_out_domain_result(unchain.final_url)
        short_circuited = False

    except Exception as exc:
        log.warning(
            "pipeline.stage_error",
            stage="reputation",
            error=str(exc),
            error_type=type(exc).__name__,
        )
        threat = timed_out_threat_db_result(unchain.final_url)
        heuristic = timed_out_domain_result(unchain.final_url)
        short_circuited = False

    heuristic = _augment_heuristic_with_redirect_signals(heuristic, unchain)

    if short_circuited:
        log.info(
            "pipeline.short_circuit",
            reason="threat_db_match",
            gsb_threat=threat.gsb.is_threat,
            urlhaus_threat=threat.urlhaus.is_threat,
        )
        stage_started = time.perf_counter()
        content = skipped_already_danger(unchain.final_url)
        _set_stage_timing(stage_timings, PipelineStage.CONTENT_ANALYSIS, stage_started)
    else:
        # known malicious 는 verdict 가 이미 외부 DB 로 확정됐으므로 페이지를 받아보지 않는다.
        # 휴리스틱 danger 는 페이지가 존재하지 않을 수 있으므로 content fetch 로 가용성을 확인한다.
        preceding = _preceding_score(threat, heuristic)
        if threat.is_malicious:
            log.info(
                "pipeline.content_analysis.skipped",
                reason="threat_db_match",
                preceding_score=preceding,
            )
            stage_started = time.perf_counter()
            content = skipped_already_danger(unchain.final_url)
            _set_stage_timing(stage_timings, PipelineStage.CONTENT_ANALYSIS, stage_started)
        else:
            upstream = _collect_upstream_signals(threat, heuristic)
            try:
                content = await deadline.run(
                    PipelineStage.CONTENT_ANALYSIS.value,
                    _timed_async_stage(
                        stage_timings,
                        PipelineStage.CONTENT_ANALYSIS,
                        _stage_content_analysis(
                            log,
                            unchain.final_url,
                            upstream,
                            use_ai=use_ai,
                        ),
                    ),
                    settings.pipeline_content_timeout_seconds,
                )
            except PipelineStageTimeoutError:
                log.warning("pipeline.stage_timeout", stage=PipelineStage.CONTENT_ANALYSIS)
                content = timed_out_content_result(unchain.final_url)
            except Exception as exc:
                log.warning(
                    "pipeline.stage_error",
                    stage=PipelineStage.CONTENT_ANALYSIS,
                    error=str(exc),
                    error_type=type(exc).__name__,
                )
                content = timed_out_content_result(unchain.final_url)

    if unavailable := content_page_unavailable(content):
        message, status_code = unavailable
        log.info(
            "pipeline.page_unavailable",
            stage=PipelineStage.CONTENT_ANALYSIS,
            final_url=unchain.final_url,
            status_code=status_code,
            error=content.error,
        )
        score = _total_score(threat, heuristic, content)
        if threat.is_malicious or score >= settings.score_caution_threshold:
            verdict = _decide_verdict(score, threat)
            return _pipeline_success(
                analysis_id=analysis_id,
                original_url=original_url,
                final_url=unchain.final_url,
                verdict=verdict,
                score=score,
                started=total_started,
                stage_timings=stage_timings,
                normalize=norm,
                unchain=unchain,
                threat=threat,
                heuristic=heuristic,
                content=content,
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

    score = _total_score(threat, heuristic, content)
    verdict = _decide_verdict(score, threat)
    log.info(
        "pipeline.done",
        final_url=unchain.final_url,
        verdict=verdict.value,
        score=score,
    )
    return _pipeline_success(
        analysis_id=analysis_id,
        original_url=original_url,
        final_url=unchain.final_url,
        verdict=verdict,
        score=score,
        started=total_started,
        stage_timings=stage_timings,
        normalize=norm,
        unchain=unchain,
        threat=threat,
        heuristic=heuristic,
        content=content,
    )
