"""URL 분석 파이프라인 오케스트레이터."""

from __future__ import annotations

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import NormalizationError
from app.schemas.normalize import NormalizeResult
from app.schemas.pipeline import (
    PipelineFailure,
    PipelineStage,
    PipelineStages,
    PipelineSuccess,
)
from app.schemas.threat_db import ThreatDbResult
from app.schemas.unchain import UnchainResult
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
    log.info("pipeline.unchain.done", final_url=result.final_url, hops=result.hop_count, signals=result.signals)
    return result


async def _stage_threat_db(log: structlog.stdlib.BoundLogger, final_url: str, session: AsyncSession) -> ThreatDbResult:
    result = await check_threat_db(session, final_url)
    log.info("pipeline.threat_db.done", is_malicious=result.is_malicious, sources_checked=result.sources_checked)
    return result


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
    threat = await _stage_threat_db(log, unchain.final_url, session)

    log.info("pipeline.done", final_url=unchain.final_url)
    return PipelineSuccess(
        analysis_id=analysis_id,
        original_url=original_url,
        final_url=unchain.final_url,
        stages=PipelineStages(normalize=norm, unchain=unchain, threat_db=threat),
    )
