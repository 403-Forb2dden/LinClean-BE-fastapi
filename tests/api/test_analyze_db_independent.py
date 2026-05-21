"""DB 비의존 분석 엔드포인트 테스트."""

from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import AsyncMock

import httpx
import pytest_asyncio
from app.api.v1.endpoints import analyze as analyze_endpoint
from app.core.config import settings
from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.db_independent_pipeline import (
    DbIndependentPipelineStages,
    DbIndependentPipelineSuccess,
)
from app.schemas.domain_heuristic import DomainHeuristicResult
from app.schemas.normalize import NormalizeResult
from app.schemas.pipeline import PipelineStageTimings, PipelineTimings, Verdict
from app.schemas.unchain import UnchainResult
from fastapi import FastAPI
from httpx import ASGITransport


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    app = FastAPI()
    app.include_router(analyze_endpoint.router, prefix=settings.api_v1_prefix)
    transport = ASGITransport(app=app)
    headers = {"X-Internal-Api-Key": settings.internal_api_key}
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers=headers,
    ) as c:
        yield c


def _success_result() -> DbIndependentPipelineSuccess:
    final_url = "https://example.com/login"
    return DbIndependentPipelineSuccess(
        analysis_id="aid-api",
        original_url=final_url,
        final_url=final_url,
        verdict=Verdict.SAFE,
        score=0,
        timings=PipelineTimings(
            total_seconds=0.001,
            stages=PipelineStageTimings(
                normalize=0.001,
                unchain=0.001,
                domain_heuristic=0.001,
                content_analysis=0.001,
            ),
        ),
        stages=DbIndependentPipelineStages(
            normalize=NormalizeResult(original_url=final_url, normalized_url=final_url),
            unchain=UnchainResult(input_url=final_url, final_url=final_url),
            domain_heuristic=DomainHeuristicResult(
                domain="example.com",
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


async def test_analyze_db_independent_sync_returns_result(
    client: httpx.AsyncClient,
    monkeypatch,
) -> None:
    mock_run = AsyncMock(return_value=_success_result())
    monkeypatch.setattr(analyze_endpoint, "run_db_independent_pipeline", mock_run)

    resp = await client.post(
        f"{settings.api_v1_prefix}/analyze/db-independent/sync",
        json={"url": "https://example.com/login"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "success"
    assert body["verdict"] == "safe"
    assert "threat_db" not in body["stages"]
    mock_run.assert_awaited_once()
    assert mock_run.await_args.kwargs["original_url"] == "https://example.com/login"


async def test_analyze_db_independent_sync_requires_internal_key() -> None:
    app = FastAPI()
    app.include_router(analyze_endpoint.router, prefix=settings.api_v1_prefix)
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post(
            f"{settings.api_v1_prefix}/analyze/db-independent/sync",
            json={"url": "https://example.com/login"},
        )

    assert resp.status_code == 401
