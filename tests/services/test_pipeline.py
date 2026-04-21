"""run_pipeline 통합 회귀 — stage 추가 시 응답 스키마/순서 검증."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from app.schemas.domain_heuristic import DomainHeuristicResult, DomainHeuristicSignal
from app.schemas.normalize import NormalizeResult
from app.schemas.pipeline import PipelineFailure, PipelineStage, PipelineSuccess
from app.schemas.threat_db import GSBResult, ThreatDbResult, URLhausResult
from app.schemas.unchain import UnchainResult
from app.services.pipeline import run_pipeline
from sqlalchemy.ext.asyncio import AsyncSession


def _make_unchain(final_url: str) -> UnchainResult:
    return UnchainResult(input_url=final_url, final_url=final_url, hops=[], hop_count=0, signals=[])


def _make_threat(final_url: str) -> ThreatDbResult:
    return ThreatDbResult(
        final_url=final_url,
        is_malicious=False,
        sources_checked=2,
        gsb=GSBResult(checked=True),
        urlhaus=URLhausResult(checked=True),
    )


def _make_heuristic(domain: str) -> DomainHeuristicResult:
    return DomainHeuristicResult(
        domain=domain,
        score=15,
        signals=[DomainHeuristicSignal.HOSTING_PLATFORM],
        rdap=None,
        rdap_error="not_found",
    )


@pytest.mark.asyncio
async def test_run_pipeline_includes_domain_heuristic_stage(async_session: AsyncSession) -> None:
    """domain_heuristic stage 추가가 응답 스키마에 정상 반영되는지 검증."""
    final_url = "https://example.com/"

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.unchain_url", new_callable=AsyncMock) as mock_unchain,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat,
        patch(
            "app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock
        ) as mock_heuristic,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_threat.return_value = _make_threat(final_url)
        mock_heuristic.return_value = _make_heuristic("example.com")

        result = await run_pipeline("aid-1", final_url, async_session)

    assert isinstance(result, PipelineSuccess)
    assert result.analysis_id == "aid-1"
    assert result.final_url == final_url
    assert result.stages.domain_heuristic.domain == "example.com"
    assert result.stages.domain_heuristic.signals == [DomainHeuristicSignal.HOSTING_PLATFORM]
    # threat_db → domain_heuristic 순서 — heuristic 인자는 unchain.final_url
    mock_heuristic.assert_awaited_once_with(final_url)


@pytest.mark.asyncio
async def test_run_pipeline_normalize_failure_skips_heuristic(
    async_session: AsyncSession,
) -> None:
    """normalize 단계 실패 시 후속 단계가 호출되지 않아야 한다."""
    from app.core.exceptions import NormalizationError

    with (
        patch("app.services.pipeline.normalize_url") as mock_norm,
        patch("app.services.pipeline.check_domain_heuristic", new_callable=AsyncMock) as mock_h,
    ):
        mock_norm.side_effect = NormalizationError("invalid")

        result = await run_pipeline("aid-2", "not a url", async_session)

    assert isinstance(result, PipelineFailure)
    assert result.failed_at_stage == PipelineStage.NORMALIZE
    mock_h.assert_not_awaited()
