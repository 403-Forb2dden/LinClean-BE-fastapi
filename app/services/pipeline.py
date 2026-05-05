"""URL 분석 파이프라인 오케스트레이터."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from urllib.parse import urlparse

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.exceptions import NormalizationError
from app.core.tld import extract_url_parts
from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.domain_heuristic import DomainHeuristicResult
from app.schemas.normalize import NormalizeResult
from app.schemas.pipeline import (
    PipelineFailure,
    PipelineStage,
    PipelineStages,
    PipelineSuccess,
    Verdict,
)
from app.schemas.threat_db import ThreatDbResult
from app.schemas.unchain import UnchainResult
from app.services.content_analyzer import analyze_content, skipped_already_danger
from app.services.domain_heuristic import check_domain_heuristic
from app.services.normalizer import normalize_url
from app.services.threat_db import check_threat_db
from app.services.unchainer import unchain_url

logger = structlog.get_logger(__name__)


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
    log: structlog.stdlib.BoundLogger, final_url: str, session: AsyncSession
) -> ThreatDbResult:
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


async def _stage_content_analysis(
    log: structlog.stdlib.BoundLogger,
    final_url: str,
    upstream_signals: tuple[str, ...],
) -> ContentAnalysisResult:
    result = await analyze_content(final_url, upstream_signals=upstream_signals)
    log.info(
        "pipeline.content_analysis.done",
        fetched=result.fetched,
        score=result.score,
        signals=[s.value for s in result.signals],
        ai_verdict=result.ai_verdict.value if result.ai_verdict else None,
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
    return min(
        _preceding_score(threat, heuristic) + content.score,
        settings.score_total_cap,
    )


def _decide_verdict(score: int, threat: ThreatDbResult) -> Verdict:
    """blacklist 매치는 점수와 무관하게 danger. 나머지는 점수 구간으로 매핑."""
    if threat.is_malicious:
        return Verdict.DANGER
    if score >= settings.score_danger_threshold:
        return Verdict.DANGER
    if score >= settings.score_caution_threshold:
        return Verdict.CAUTION
    return Verdict.SAFE


def _skipped_heuristic(final_url: str) -> DomainHeuristicResult:
    """threat match 로 조기 종료된 경우 heuristic 자리에 들어갈 placeholder.

    score=0 이라 합산에 영향 없고, rdap_error 코드로 "우리가 건너뛴 것" 을 식별 가능하게 남긴다.
    응답 스키마의 heuristic 필드가 필수라서 빈 객체라도 채워야 하는 제약 때문.

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
        rdap_error="skipped_threat_matched",
    )


async def _run_stage_2_and_3(
    log: structlog.stdlib.BoundLogger,
    final_url: str,
    session: AsyncSession,
) -> tuple[ThreatDbResult, DomainHeuristicResult, bool]:
    """2·3단계를 병렬 실행한다. threat_db 가 먼저 malicious 로 끝나면 heuristic 을
    즉시 cancel 하고 조기 종료 플래그를 세워 반환한다.

    반환: (threat, heuristic, short_circuited).
    short_circuited=True 면 heuristic 은 placeholder 이고 4단계는 skip 대상.
    `CancelledError` 와 stage 내부 예외는 남은 task 를 정리한 뒤 그대로 re-raise.
    """
    threat_task = asyncio.create_task(_stage_threat_db(log, final_url, session))
    heur_task = asyncio.create_task(_stage_domain_heuristic(log, final_url))

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
            threat = threat_task.result()
            if threat.is_malicious:
                # RDAP 대기로 5s 가까이 떠 있을 수 있는 heuristic 을 cancel 로 회수.
                heur_task.cancel()
                with suppress(asyncio.CancelledError):
                    await heur_task
                return threat, _skipped_heuristic(final_url), True
            heuristic = await heur_task
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
) -> PipelineSuccess | PipelineFailure:
    log = logger.bind(analysis_id=analysis_id)
    log.info("pipeline.start", url=original_url)

    try:
        norm = _stage_normalize(log, original_url)
    except NormalizationError as exc:
        log.warning("pipeline.failed", stage=PipelineStage.NORMALIZE, error=str(exc))
        return PipelineFailure(
            analysis_id=analysis_id,
            original_url=original_url,
            failed_at_stage=PipelineStage.NORMALIZE,
            error=str(exc),
        )

    unchain = await _stage_unchain(log, norm.normalized_url)
    # 2·3단계는 둘 다 unchain.final_url 만 필요하고 서로 독립이라 병렬로 돈다.
    # threat_db 가 먼저 malicious 로 끝나면 verdict 가 이미 danger 로 확정이므로
    # heuristic 을 cancel 하고 4단계까지 skip — 여기서 조기 종료가 일어난다.
    threat, heuristic, short_circuited = await _run_stage_2_and_3(
        log, unchain.final_url, session
    )

    if short_circuited:
        log.info(
            "pipeline.short_circuit",
            reason="threat_db_match",
            gsb_threat=threat.gsb.is_threat,
            urlhaus_threat=threat.urlhaus.is_threat,
        )
        content = skipped_already_danger(unchain.final_url)
    else:
        # 이미 danger 확정된 URL은 페이지를 받아보지 않는다 — 네트워크·AI 비용 절감.
        # 판정이 바뀌지 않을 단계에 초 단위 지연과 건당 원화를 쓸 이유가 없다.
        preceding = _preceding_score(threat, heuristic)
        if threat.is_malicious or preceding >= settings.score_danger_threshold:
            log.info(
                "pipeline.content_analysis.skipped",
                reason=("threat_db_match" if threat.is_malicious else "already_danger"),
                preceding_score=preceding,
            )
            content = skipped_already_danger(unchain.final_url)
        else:
            upstream = _collect_upstream_signals(threat, heuristic)
            content = await _stage_content_analysis(log, unchain.final_url, upstream)

    score = _total_score(threat, heuristic, content)
    verdict = _decide_verdict(score, threat)
    log.info(
        "pipeline.done",
        final_url=unchain.final_url,
        verdict=verdict.value,
        score=score,
    )
    return PipelineSuccess(
        analysis_id=analysis_id,
        original_url=original_url,
        final_url=unchain.final_url,
        verdict=verdict,
        score=score,
        stages=PipelineStages(
            normalize=norm,
            unchain=unchain,
            threat_db=threat,
            domain_heuristic=heuristic,
            content_analysis=content,
        ),
    )
