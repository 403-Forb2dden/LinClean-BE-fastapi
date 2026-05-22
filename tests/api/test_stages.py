"""/api/v1/* 단계별 운영 엔드포인트 테스트.

X-Internal-Api-Key 인증 + 단계 단독 호출 동작을 검증한다.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from unittest.mock import AsyncMock, patch

import httpx
import pytest_asyncio
from app.api.v1.endpoints import stages as stages_endpoint
from app.core.config import settings
from app.schemas.content_analysis import AIVerdict, ContentAnalysisResult, ContentSignal
from app.services.content_analyzer.fetch import FetchResult
from fastapi import FastAPI
from httpx import ASGITransport


@pytest_asyncio.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """stages 라우터만 마운트한 얇은 FastAPI 앱 — lifespan / DB / 스케줄러를 건드리지 않는다."""
    app = FastAPI()
    app.include_router(stages_endpoint.router, prefix=settings.api_v1_prefix)
    transport = ASGITransport(app=app)
    headers = {"X-Internal-Api-Key": settings.internal_api_key}
    async with httpx.AsyncClient(
        transport=transport, base_url="http://test", headers=headers
    ) as c:
        yield c


_ENDPOINT_FETCH = f"{settings.api_v1_prefix}/content/fetch-extract"
_ENDPOINT_ANALYSIS = f"{settings.api_v1_prefix}/content-analysis"


class TestFetchExtractEndpoint:
    async def test_returns_fetch_and_features_on_success(self, client: httpx.AsyncClient) -> None:
        html = (
            "<html><head><title>NAVER</title></head>"
            '<body><form><input type="password"></form>'
            '<img alt="NAVER logo"></body></html>'
        )
        fetch = FetchResult(
            ok=True,
            url="https://evil-naver.test/",
            status_code=200,
            html=html,
        )
        with patch(
            "app.api.v1.endpoints.stages.fetch_page",
            AsyncMock(return_value=fetch),
        ):
            resp = await client.post(_ENDPOINT_FETCH, json={"url": "https://evil-naver.test/"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["url"] == "https://evil-naver.test/"
        assert body["fetch"]["ok"] is True
        assert body["fetch"]["status_code"] == 200
        assert body["fetch"]["html_length"] == len(html)
        assert body["features"]["title"] == "NAVER"
        assert body["features"]["has_password_field"] is True
        assert body["features"]["image_alts"] == ["NAVER logo"]
        assert body["features"]["form_field_summaries"]
        assert body["html_preview"] is not None
        assert "<title>NAVER</title>" in body["html_preview"]

    async def test_fetch_failure_omits_features(self, client: httpx.AsyncClient) -> None:
        fetch = FetchResult(ok=False, url="https://down.test/", error="connect_error")
        with patch(
            "app.api.v1.endpoints.stages.fetch_page",
            AsyncMock(return_value=fetch),
        ):
            resp = await client.post(_ENDPOINT_FETCH, json={"url": "https://down.test/"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["fetch"]["ok"] is False
        assert body["fetch"]["error"] == "connect_error"
        assert body["features"] is None
        assert body["html_preview"] is None

    async def test_html_preview_caps_bytes(self, client: httpx.AsyncClient) -> None:
        big = "<html><body>" + ("x" * 10000) + "</body></html>"
        fetch = FetchResult(ok=True, url="https://big.test/", status_code=200, html=big)
        with patch(
            "app.api.v1.endpoints.stages.fetch_page",
            AsyncMock(return_value=fetch),
        ):
            resp = await client.post(_ENDPOINT_FETCH, json={"url": "https://big.test/"})

        preview = resp.json()["html_preview"]
        assert preview is not None
        # 2048 bytes 상한 — 그 이하로 잘려야 한다
        assert len(preview) <= 2048

    async def test_missing_url_returns_422(self, client: httpx.AsyncClient) -> None:
        resp = await client.post(_ENDPOINT_FETCH, json={})
        assert resp.status_code == 422

    async def test_invalid_scheme_rejected(self, client: httpx.AsyncClient) -> None:
        """file:// 같은 비허용 스킴은 normalize_url 에서 400 으로 떨어진다."""
        resp = await client.post(_ENDPOINT_FETCH, json={"url": "file:///etc/passwd"})
        assert resp.status_code == 400
        assert "invalid url" in resp.json()["detail"]


class TestContentAnalysisEndpoint:
    async def test_returns_full_content_analysis(self, client: httpx.AsyncClient) -> None:
        expected = ContentAnalysisResult(
            final_url="https://x.test/",
            fetched=True,
            score=80,
            signals=[ContentSignal.BRAND_IMPERSONATION_FORM],
            title="NAVER",
            has_password_field=True,
            brand_impersonation=True,
            ai_verdict=AIVerdict.PHISHING,
            ai_reason="브랜드 위장",
        )
        with patch(
            "app.api.v1.endpoints.stages.analyze_content",
            AsyncMock(return_value=expected),
        ):
            resp = await client.post(_ENDPOINT_ANALYSIS, json={"url": "https://x.test/"})

        assert resp.status_code == 200
        body = resp.json()
        assert body["final_url"] == "https://x.test/"
        assert body["score"] == 80
        assert body["signals"] == ["BRAND_IMPERSONATION_FORM"]
        assert body["ai_verdict"] == "phishing"
        assert body["ai_reason"] == "브랜드 위장"

    async def test_does_not_skip_based_on_preceding_score(
        self, client: httpx.AsyncClient
    ) -> None:
        """파이프라인과 달리 단계 단독 엔드포인트는 항상 실제 분석을 수행한다."""
        expected = ContentAnalysisResult(
            final_url="https://x.test/",
            fetched=False,
            score=0,
            signals=[],
            error="connect_error",
        )
        with patch(
            "app.api.v1.endpoints.stages.analyze_content",
            AsyncMock(return_value=expected),
        ) as mock_analyze:
            await client.post(_ENDPOINT_ANALYSIS, json={"url": "https://x.test/"})

        mock_analyze.assert_awaited_once_with("https://x.test/")


class TestAuthRequired:
    """모든 stages 엔드포인트는 X-Internal-Api-Key 헤더 인증이 필수다."""

    async def test_missing_header_rejected_401(self) -> None:
        app = FastAPI()
        app.include_router(stages_endpoint.router, prefix=settings.api_v1_prefix)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.post(_ENDPOINT_ANALYSIS, json={"url": "https://x.test/"})
        assert resp.status_code == 401

    async def test_wrong_key_rejected_401(self) -> None:
        app = FastAPI()
        app.include_router(stages_endpoint.router, prefix=settings.api_v1_prefix)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
            headers={"X-Internal-Api-Key": "wrong-key"},
        ) as c:
            resp = await c.post(_ENDPOINT_ANALYSIS, json={"url": "https://x.test/"})
        assert resp.status_code == 401
