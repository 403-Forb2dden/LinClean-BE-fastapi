from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from app.core.config import settings
from app.schemas.content_analysis import ContentAnalysisResult, ContentSignal
from app.schemas.domain_heuristic import DomainHeuristicResult, DomainHeuristicSignal, RdapInfo
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
from app.schemas.threat_db import GSBMatch, GSBResult, ThreatDbResult, URLhausResult
from app.schemas.unchain import HopRecord, UnchainResult
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
                hops=[
                    HopRecord(
                        url="https://bit.ly/a",
                        status_code=302,
                        location=final_url,
                    ),
                    HopRecord(url=final_url, status_code=200),
                ],
                hop_count=2,
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
                score=25,
                signals=[DomainHeuristicSignal.NEW_DOMAIN],
                rdap=RdapInfo(
                    domain="example.test",
                    registrar="Example Registrar",
                    created_date=datetime(2026, 4, 1, tzinfo=UTC),
                    expiry_date=None,
                    domain_age_days=6,
                    is_new_domain=True,
                ),
            ),
            content_analysis=ContentAnalysisResult(
                final_url=final_url,
                fetched=True,
                score=45,
                signals=[ContentSignal.BRAND_IMPERSONATION_FORM],
                has_password_field=True,
                ai_verdict="phishing",
                ai_reason="브랜드 사칭 로그인 폼이 확인되었습니다.",
            ),
        ),
    )


def _malicious_result() -> PipelineSuccess:
    result = _success_result()
    result.stages.threat_db.is_malicious = True
    result.stages.threat_db.gsb = GSBResult(
        checked=True,
        is_threat=True,
        matches=[GSBMatch(threat_type="SOCIAL_ENGINEERING")],
    )
    result.stages.threat_db.urlhaus = URLhausResult(
        checked=True,
        is_threat=True,
        matched_key="example.test",
    )
    return result


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
    assert payload["summary"] == "브랜드 사칭 로그인 폼이 확인되었습니다."
    assert payload["reasons"] == [
        {
            "code": "NEW_DOMAIN",
            "stage": 3,
            "weight": settings.score_weight_new_domain,
            "message": "최근 등록된 도메인입니다.",
        },
        {
            "code": "BRAND_IMPERSONATION_FORM",
            "stage": 4,
            "weight": settings.score_weight_brand_impersonation,
            "message": "브랜드를 사칭하는 로그인 폼이 확인되었습니다.",
        },
        {
            "code": "AI_PHISHING",
            "stage": 4,
            "weight": settings.score_weight_ai_phishing,
            "message": "브랜드 사칭 로그인 폼이 확인되었습니다.",
        },
    ]
    assert payload["stages"] == {
        "externalDb": {
            "gsb": {"isThreat": False, "matchedTypes": []},
            "urlhaus": {"isThreat": False, "host": "example.test"},
        },
        "unchain": {
            "hops": 2,
            "chain": ["https://bit.ly/a", "https://example.test/"],
        },
        "domainHeuristic": {
            "rdap": {
                "domain": "example.test",
                "registrar": "Example Registrar",
                "createdDate": "2026-04-01T00:00:00Z",
                "domainAgeDays": 6,
                "isNewDomain": True,
            },
            "signals": ["NEW_DOMAIN"],
        },
        "contentAnalysis": {
            "fetched": True,
            "hasPasswordField": True,
            "aiVerdict": "phishing",
            "aiReason": "브랜드 사칭 로그인 폼이 확인되었습니다.",
        },
    }


@pytest.mark.asyncio
async def test_posts_known_malicious_callback_with_fixed_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "spring_internal_url", "http://spring.internal")
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.post.return_value = httpx.Response(200, json={"received": True})

    with patch("app.services.analysis_callback.httpx.AsyncClient", return_value=mock_client):
        delivered = await post_analysis_callback(
            _malicious_result(),
            request_id="rid-1",
            elapsed_ms=123,
            analyzed_at=datetime(2026, 4, 7, 5, 42, 11, tzinfo=UTC),
        )

    assert delivered is True
    payload = mock_client.post.await_args.kwargs["json"]
    assert payload["summary"] == "악성으로 알려진 페이지 입니다."
    assert payload["reasons"][:2] == [
        {
            "code": "GSB_MATCH",
            "stage": 2,
            "weight": settings.score_weight_gsb,
            "message": "Google Safe Browsing에 악성 URL로 등록되어 있습니다.",
        },
        {
            "code": "URLHAUS_MATCH",
            "stage": 2,
            "weight": settings.score_weight_urlhaus,
            "message": "URLhaus에 악성 URL로 등록되어 있습니다.",
        },
    ]
    assert payload["stages"]["externalDb"] == {
        "gsb": {"isThreat": True, "matchedTypes": ["SOCIAL_ENGINEERING"]},
        "urlhaus": {"isThreat": True, "host": "example.test"},
    }


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
        "stage": 1,
        "message": "invalid url",
    }
    assert "timings" not in payload
    assert "stages" not in payload
