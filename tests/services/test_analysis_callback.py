from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from app.core.config import settings
from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.domain_heuristic import DomainHeuristicResult
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
from app.schemas.threat_db import GSBResult, ThreatDbResult, URLhausResult
from app.schemas.unchain import UnchainResult
from app.services.analysis_callback import post_analysis_callback


def _success_result() -> PipelineSuccess:
    final_url = "https://example.test/"
    return PipelineSuccess(
        analysis_id="aid-1",
        original_url="https://bit.ly/a",
        final_url=final_url,
        verdict=Verdict.SAFE,
        score=0,
        timings=PipelineTimings(
            total_seconds=0.123,
            stages=PipelineStageTimings(
                normalize=0.001,
                unchain=0.002,
                threat_db=0.003,
                domain_heuristic=0.004,
                content_analysis=0.005,
            ),
        ),
        stages=PipelineStages(
            normalize=NormalizeResult(
                original_url="https://bit.ly/a",
                normalized_url="https://bit.ly/a",
            ),
            unchain=UnchainResult(
                input_url="https://bit.ly/a",
                final_url=final_url,
                hops=[],
                hop_count=0,
            ),
            threat_db=ThreatDbResult(
                final_url=final_url,
                is_malicious=False,
                sources_checked=2,
                gsb=GSBResult(checked=True),
                urlhaus=URLhausResult(checked=True),
            ),
            domain_heuristic=DomainHeuristicResult(
                domain="example.test",
                score=0,
                signals=[],
            ),
            content_analysis=ContentAnalysisResult(
                final_url=final_url,
                fetched=True,
                score=0,
                signals=[],
            ),
        ),
    )


@pytest.mark.asyncio
async def test_posts_success_callback_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "spring_internal_url", "http://spring.internal")
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = httpx.Response(200, json={"received": True})

    with patch("app.services.analysis_callback.httpx.AsyncClient", return_value=mock_client):
        delivered = await post_analysis_callback(
            _success_result(),
            request_id="rid-1",
            elapsed_ms=123,
            analyzed_at=datetime(2026, 4, 7, 5, 42, 11, tzinfo=UTC),
        )

    assert delivered is True
    mock_client.post.assert_awaited_once()
    url = mock_client.post.await_args.args[0]
    kwargs = mock_client.post.await_args.kwargs
    assert url == "http://spring.internal/internal/analysis-result"
    assert kwargs["headers"] == {
        "Content-Type": "application/json",
        "X-Internal-Api-Key": settings.internal_api_key,
        "X-Request-ID": "rid-1",
    }
    payload = kwargs["json"]
    assert payload["analysisId"] == "aid-1"
    assert payload["requestId"] == "rid-1"
    assert payload["status"] == "succeeded"
    assert payload["originalUrl"] == "https://bit.ly/a"
    assert payload["finalUrl"] == "https://example.test/"
    assert payload["verdict"] == "safe"
    assert payload["score"] == 0
    assert payload["engineVersion"] == settings.app_version
    assert payload["analyzedAt"] == "2026-04-07T05:42:11Z"
    assert payload["elapsedMs"] == 123
    assert payload["timings"] == {
        "total_seconds": 0.123,
        "stages": {
            "normalize": 0.001,
            "unchain": 0.002,
            "threat_db": 0.003,
            "domain_heuristic": 0.004,
            "content_analysis": 0.005,
        },
    }
    assert payload["stages"]["threat_db"]["is_malicious"] is False


@pytest.mark.asyncio
async def test_retries_callback_on_non_2xx(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "spring_internal_url", "http://spring.internal/")
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.side_effect = [
        httpx.Response(500),
        httpx.Response(502),
        httpx.Response(200),
    ]

    with (
        patch("app.services.analysis_callback.httpx.AsyncClient", return_value=mock_client),
        patch("app.services.analysis_callback.asyncio.sleep", new_callable=AsyncMock),
    ):
        delivered = await post_analysis_callback(
            _success_result(),
            request_id="rid-1",
            elapsed_ms=1,
            analyzed_at=datetime(2026, 4, 7, 5, 42, 11, tzinfo=UTC),
        )

    assert delivered is True
    assert mock_client.post.await_count == 3


@pytest.mark.asyncio
async def test_posts_failure_callback_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "spring_internal_url", "http://spring.internal")
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = httpx.Response(200)
    result = PipelineFailure(
        analysis_id="aid-fail",
        original_url="not a url",
        failed_at_stage=PipelineStage.NORMALIZE,
        error="invalid url",
        timings=PipelineTimings(
            total_seconds=0.001,
            stages=PipelineStageTimings(normalize=0.001),
        ),
    )

    with patch("app.services.analysis_callback.httpx.AsyncClient", return_value=mock_client):
        delivered = await post_analysis_callback(
            result,
            request_id="rid-fail",
            elapsed_ms=7,
            analyzed_at=datetime(2026, 4, 7, 5, 42, 41, tzinfo=UTC),
        )

    assert delivered is True
    payload = mock_client.post.await_args.kwargs["json"]
    assert payload["analysisId"] == "aid-fail"
    assert payload["requestId"] == "rid-fail"
    assert payload["status"] == "failed"
    assert payload["originalUrl"] == "not a url"
    assert payload["error"] == {
        "code": "NORMALIZE_FAILED",
        "stage": "normalize",
        "message": "invalid url",
    }
    assert payload["timings"]["total_seconds"] == 0.001
    assert payload["timings"]["stages"]["normalize"] == 0.001
    assert "stages" not in payload
