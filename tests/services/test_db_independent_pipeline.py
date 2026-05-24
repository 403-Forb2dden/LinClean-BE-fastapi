"""외부 threat DB 비의존 파이프라인 회귀 테스트."""

from __future__ import annotations

import asyncio
import inspect
from unittest.mock import AsyncMock, patch

import pytest
from app.core.config import settings
from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.db_independent_pipeline import (
    DbIndependentPipelineFailure,
    DbIndependentPipelineSuccess,
)
from app.schemas.domain_heuristic import DomainHeuristicResult, DomainHeuristicSignal
from app.schemas.normalize import NormalizeResult
from app.schemas.pipeline import PipelineStage, Verdict
from app.schemas.unchain import UnchainResult
from app.services.db_independent_pipeline import run_db_independent_pipeline


def _make_unchain(final_url: str, *, signals: list[str] | None = None) -> UnchainResult:
    return UnchainResult(
        input_url=final_url,
        final_url=final_url,
        hops=[],
        hop_count=0,
        signals=signals or [],
    )


def _make_heuristic(score: int) -> DomainHeuristicResult:
    return DomainHeuristicResult(
        domain="example.com",
        score=score,
        signals=[DomainHeuristicSignal.HOSTING_PLATFORM] if score else [],
        rdap=None,
        rdap_error=None,
    )


def _make_content(final_url: str, *, score: int = 0) -> ContentAnalysisResult:
    return ContentAnalysisResult(final_url=final_url, fetched=True, score=score, signals=[])


@pytest.mark.asyncio
async def test_db_independent_pipeline_never_calls_threat_db() -> None:
    final_url = "https://example.com/login"

    with (
        patch("app.services.db_independent_pipeline.normalize_url") as mock_norm,
        patch(
            "app.services.db_independent_pipeline.unchain_url", new_callable=AsyncMock
        ) as mock_unchain,
        patch(
            "app.services.db_independent_pipeline.check_domain_heuristic",
            new_callable=AsyncMock,
        ) as mock_heuristic,
        patch(
            "app.services.db_independent_pipeline.analyze_content", new_callable=AsyncMock
        ) as mock_content,
        patch("app.services.pipeline.check_threat_db", new_callable=AsyncMock) as mock_threat_db,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_heuristic.return_value = _make_heuristic(15)
        mock_content.return_value = _make_content(final_url, score=20)

        result = await run_db_independent_pipeline("aid-db-free", final_url)

    assert isinstance(result, DbIndependentPipelineSuccess)
    assert result.analysis_id == "aid-db-free"
    assert result.final_url == final_url
    assert result.score == 35
    assert result.verdict == Verdict.CAUTION
    assert result.stages.domain_heuristic.score == 15
    assert result.stages.content_analysis.score == 20
    assert result.timings is not None
    assert result.timings.stages.threat_db is None
    mock_threat_db.assert_not_awaited()


@pytest.mark.asyncio
async def test_db_independent_pipeline_passes_url_and_redirect_signals_to_content() -> None:
    final_url = "https://redirected.example.com/login"

    with (
        patch("app.services.db_independent_pipeline.normalize_url") as mock_norm,
        patch(
            "app.services.db_independent_pipeline.unchain_url", new_callable=AsyncMock
        ) as mock_unchain,
        patch(
            "app.services.db_independent_pipeline.check_domain_heuristic",
            new_callable=AsyncMock,
        ) as mock_heuristic,
        patch(
            "app.services.db_independent_pipeline.analyze_content", new_callable=AsyncMock
        ) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(
            original_url="https://short.test/a",
            normalized_url="https://short.test/a",
        )
        mock_unchain.return_value = _make_unchain(
            final_url,
            signals=["cross_origin:short.test->redirected.example.com"],
        )
        mock_heuristic.return_value = _make_heuristic(15)
        mock_content.return_value = _make_content(final_url)

        await run_db_independent_pipeline("aid-sig", "https://short.test/a")

    mock_content.assert_awaited_once()
    args, kwargs = mock_content.await_args
    assert args == (final_url,)
    upstream = kwargs["upstream_signals"]
    if inspect.isawaitable(upstream):
        upstream = await upstream
    assert upstream == (
        "HOSTING_PLATFORM",
        "REDIRECT_CROSS_ORIGIN",
    )
    assert "provider" not in kwargs


@pytest.mark.asyncio
async def test_db_independent_pipeline_skips_content_when_heuristic_is_danger() -> None:
    final_url = "https://danger.example.com/login"
    content_started = asyncio.Event()

    async def _slow_heuristic(_: str) -> DomainHeuristicResult:
        await asyncio.sleep(0.01)
        return _make_heuristic(65)

    async def _slow_content(_: str, **__: object) -> ContentAnalysisResult:
        content_started.set()
        return _make_content(final_url, score=20)

    with (
        patch("app.services.db_independent_pipeline.normalize_url") as mock_norm,
        patch(
            "app.services.db_independent_pipeline.unchain_url", new_callable=AsyncMock
        ) as mock_unchain,
        patch(
            "app.services.db_independent_pipeline.check_domain_heuristic",
            new=AsyncMock(side_effect=_slow_heuristic),
        ),
        patch(
            "app.services.db_independent_pipeline.analyze_content",
            new=AsyncMock(side_effect=_slow_content),
        ) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)

        result = await run_db_independent_pipeline("aid-parallel", final_url)

    assert isinstance(result, DbIndependentPipelineSuccess)
    assert result.score == 65
    assert result.stages.content_analysis.error == "skipped_already_danger"
    assert content_started.is_set() is False
    mock_content.assert_not_awaited()


@pytest.mark.asyncio
async def test_db_independent_pipeline_degrades_when_heuristic_fails() -> None:
    final_url = "https://error.example.com/login"

    async def _failing_heuristic(_: str) -> DomainHeuristicResult:
        await asyncio.sleep(0.01)
        raise RuntimeError("heuristic failed")

    with (
        patch("app.services.db_independent_pipeline.normalize_url") as mock_norm,
        patch(
            "app.services.db_independent_pipeline.unchain_url", new_callable=AsyncMock
        ) as mock_unchain,
        patch(
            "app.services.db_independent_pipeline.check_domain_heuristic",
            new=AsyncMock(side_effect=_failing_heuristic),
        ),
        patch(
            "app.services.db_independent_pipeline.analyze_content",
            new_callable=AsyncMock,
        ) as mock_content,
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_content.return_value = _make_content(final_url)

        result = await run_db_independent_pipeline("aid-error-cleanup", final_url)

    assert isinstance(result, DbIndependentPipelineSuccess)
    assert result.stages.domain_heuristic.rdap_error == "pipeline_timeout"
    mock_content.assert_awaited_once()


@pytest.mark.asyncio
async def test_db_independent_pipeline_caps_content_stage_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    final_url = "https://slow-content.example.com/login"
    monkeypatch.setattr(settings, "pipeline_content_timeout_seconds", 0.001)

    async def _slow_content(_: str, **__: object) -> ContentAnalysisResult:
        await asyncio.sleep(1)
        return _make_content(final_url, score=90)

    with (
        patch("app.services.db_independent_pipeline.normalize_url") as mock_norm,
        patch(
            "app.services.db_independent_pipeline.unchain_url", new_callable=AsyncMock
        ) as mock_unchain,
        patch(
            "app.services.db_independent_pipeline.check_domain_heuristic",
            new_callable=AsyncMock,
        ) as mock_heuristic,
        patch(
            "app.services.db_independent_pipeline.analyze_content",
            new=AsyncMock(side_effect=_slow_content),
        ),
    ):
        mock_norm.return_value = NormalizeResult(original_url=final_url, normalized_url=final_url)
        mock_unchain.return_value = _make_unchain(final_url)
        mock_heuristic.return_value = _make_heuristic(0)

        result = await run_db_independent_pipeline("aid-content-timeout", final_url)

    assert isinstance(result, DbIndependentPipelineSuccess)
    assert result.stages.content_analysis.error == "pipeline_timeout"
    assert result.timings is not None
    assert result.timings.total_seconds < 0.5


@pytest.mark.asyncio
async def test_db_independent_pipeline_returns_failure_on_normalize_error() -> None:
    from app.core.exceptions import NormalizationError

    with (
        patch("app.services.db_independent_pipeline.normalize_url") as mock_norm,
        patch(
            "app.services.db_independent_pipeline.unchain_url", new_callable=AsyncMock
        ) as mock_unchain,
    ):
        mock_norm.side_effect = NormalizationError("invalid")

        result = await run_db_independent_pipeline("aid-bad", "not a url")

    assert isinstance(result, DbIndependentPipelineFailure)
    assert result.failed_at_stage == PipelineStage.NORMALIZE
    assert result.timings is not None
    assert result.timings.stages.normalize is not None
    mock_unchain.assert_not_awaited()
