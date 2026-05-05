from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from app.api.v1.endpoints import analyze as analyze_endpoint
from app.schemas.pipeline import PipelineFailure, PipelineStage


class _FakeSessionContext:
    async def __aenter__(self) -> object:
        return object()

    async def __aexit__(self, *args: object) -> None:
        return None


@pytest.mark.asyncio
async def test_background_task_posts_pipeline_result_callback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = PipelineFailure(
        analysis_id="aid-1",
        original_url="not a url",
        failed_at_stage=PipelineStage.NORMALIZE,
        error="invalid",
    )
    mock_run_pipeline = AsyncMock(return_value=result)
    mock_callback = AsyncMock(return_value=True)
    monkeypatch.setattr(analyze_endpoint, "SessionLocal", lambda: _FakeSessionContext())
    monkeypatch.setattr(analyze_endpoint, "run_pipeline", mock_run_pipeline)
    monkeypatch.setattr(analyze_endpoint, "post_analysis_callback", mock_callback)

    await analyze_endpoint._run_pipeline_task(
        analysis_id="aid-1",
        original_url="not a url",
        request_id="rid-1",
    )

    mock_run_pipeline.assert_awaited_once()
    mock_callback.assert_awaited_once()
    kwargs = mock_callback.await_args.kwargs
    assert mock_callback.await_args.args == (result,)
    assert kwargs["request_id"] == "rid-1"
    assert kwargs["elapsed_ms"] >= 0
    assert kwargs["analyzed_at"].tzinfo is not None
