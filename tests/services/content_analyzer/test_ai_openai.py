"""OpenAIProvider — Chat Completions 기반 피싱 추론 어댑터."""

from __future__ import annotations

import asyncio
import json
import sys
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.core.config import settings
from app.schemas.content_analysis import AIVerdict
from app.services.content_analyzer.ai import AIPromptContext
from app.services.content_analyzer.ai_openai import OpenAIProvider


@pytest.fixture(autouse=True)
def _set_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_api_key", "test-key")


def _ctx() -> AIPromptContext:
    return AIPromptContext(
        final_url="https://evil-naver.test/signin",
        title="NAVER 로그인",
        has_password_field=True,
        has_meta_refresh=False,
        image_alts=("NAVER",),
        external_link_ratio=0.9,
    )


def _mock_http_response(
    content: str,
    *,
    usage: dict[str, int] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        raise_for_status=lambda: None,
        json=lambda: {
            "choices": [{"message": {"content": content}}],
            "usage": usage,
        },
    )


def _mock_http_client(
    content: str,
    *,
    usage: dict[str, int] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        post=AsyncMock(return_value=_mock_http_response(content, usage=usage)),
        aclose=AsyncMock(),
    )


def _usage(prompt: int, completion: int) -> dict[str, int]:
    return {
        "prompt_tokens": prompt,
        "completion_tokens": completion,
        "total_tokens": prompt + completion,
    }


async def test_openai_returns_verdict_on_success() -> None:
    payload = json.dumps({"verdict": "phishing", "reason": "브랜드 불일치"})
    client = _mock_http_client(payload, usage=_usage(120, 18))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        result = await OpenAIProvider().infer(_ctx())

    assert result is not None
    assert result.verdict == AIVerdict.PHISHING
    assert result.reason == "브랜드 불일치"
    assert result.model == settings.openai_model
    assert result.token_usage is not None
    assert result.token_usage.prompt_tokens == 120
    assert result.token_usage.completion_tokens == 18
    assert result.token_usage.total_tokens == 138


async def test_openai_missing_usage_returns_none_token_usage() -> None:
    """usage 가 비어 있으면 token_usage=None 으로 떨어뜨린다 (추론 자체는 성공)."""
    client = _mock_http_client(json.dumps({"verdict": "benign", "reason": "ok"}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        result = await OpenAIProvider().infer(_ctx())

    assert result is not None
    assert result.token_usage is None


async def test_openai_custom_model_overrides_settings() -> None:
    """생성자에 model 을 넘기면 settings.openai_model 보다 우선한다 — 모델 비교용."""
    client = _mock_http_client(json.dumps({"verdict": "benign", "reason": "ok"}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        result = await OpenAIProvider(model="gpt-4o").infer(_ctx())

    request_json = client.post.await_args.kwargs["json"]
    assert request_json["model"] == "gpt-4o"
    assert result is not None
    assert result.model == "gpt-4o"


async def test_openai_returns_none_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_api_key", None)
    provider = OpenAIProvider()
    assert await provider.infer(_ctx()) is None


async def test_openai_uses_configured_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_model", "gpt-4o-mini")

    client = _mock_http_client(json.dumps({"verdict": "benign", "reason": "ok"}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        await OpenAIProvider().infer(_ctx())

    request_json = client.post.await_args.kwargs["json"]
    assert request_json["model"] == "gpt-4o-mini"
    assert request_json["response_format"]["type"] == "json_schema"
    assert request_json["response_format"]["json_schema"]["strict"] is True
    assert request_json["max_tokens"] == settings.openai_max_output_tokens


async def test_openai_prompt_requests_short_expert_plain_korean_reason() -> None:
    client = _mock_http_client(json.dumps({"verdict": "benign", "reason": "ok"}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        await OpenAIProvider().infer(_ctx())

    system_msg = client.post.await_args.kwargs["json"]["messages"][0]["content"]
    assert "100자" in system_msg
    assert "보안 전문가" in system_msg
    assert "쉬운 한국어" in system_msg


async def test_openai_truncates_reason_to_100_chars() -> None:
    long_reason = "가" * 150
    client = _mock_http_client(json.dumps({"verdict": "suspicious", "reason": long_reason}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        result = await OpenAIProvider().infer(_ctx())

    assert result is not None
    assert len(result.reason) == 100


async def test_openai_uses_http_client_without_sdk_resource_import() -> None:
    client = _mock_http_client(json.dumps({"verdict": "benign", "reason": "ok"}))
    httpx_client_cls = MagicMock(return_value=client)
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", httpx_client_cls):
        await OpenAIProvider(timeout_seconds=3.0).infer(_ctx())

    assert httpx_client_cls.call_args.kwargs["base_url"] == "https://api.openai.com/v1"
    assert httpx_client_cls.call_args.kwargs["timeout"] == 3.0
    assert httpx_client_cls.call_args.kwargs["trust_env"] is False
    assert client.post.await_args.args == ("/chat/completions",)


async def test_openai_request_has_hard_timeout() -> None:
    async def never_returns(*_: object, **__: object) -> object:
        await asyncio.sleep(10)
        return _mock_http_response(json.dumps({"verdict": "benign", "reason": "late"}))

    client = SimpleNamespace(post=never_returns, aclose=AsyncMock())
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        started = time.perf_counter()
        result = await OpenAIProvider(timeout_seconds=0.01).infer(_ctx())

    assert result is None
    assert time.perf_counter() - started < 0.5


async def test_openai_provider_does_not_import_openai_sdk() -> None:
    sys.modules.pop("openai", None)
    client = _mock_http_client(json.dumps({"verdict": "benign", "reason": "ok"}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        await OpenAIProvider().infer(_ctx())

    assert "openai" not in sys.modules


async def test_openai_user_prompt_includes_upstream_signals() -> None:
    """ctx.upstream_signals 가 user payload 의 upstream_signals 배열로 직렬화돼야 한다."""
    client = _mock_http_client(
        json.dumps({"verdict": "phishing", "reason": "타이포 + 비밀번호 폼"})
    )
    ctx = AIPromptContext(
        final_url="https://evil-naverr.test/signin",
        title="NAVER 로그인",
        has_password_field=True,
        has_meta_refresh=False,
        image_alts=("NAVER",),
        external_link_ratio=0.9,
        upstream_signals=("TYPO_DOMAIN", "NEW_DOMAIN"),
    )
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        await OpenAIProvider().infer(ctx)

    user_msg = client.post.await_args.kwargs["json"]["messages"][1]["content"]
    body = json.loads(user_msg)
    assert body["upstream_signals"] == ["TYPO_DOMAIN", "NEW_DOMAIN"]


async def test_openai_user_prompt_includes_high_signal_structured_context() -> None:
    client = _mock_http_client(
        json.dumps({"verdict": "suspicious", "reason": "민감정보 입력 유도"})
    )
    ctx = AIPromptContext(
        final_url="https://nhis-support.test/",
        title="고유가 피해지원금 대상 조회",
        has_password_field=False,
        has_meta_refresh=False,
        image_alts=(),
        external_link_ratio=None,
        body_text_snippets=("국민건강보험 고유가 피해지원금 지급대상 여부 조회",),
        form_field_summaries=(
            "label=주민등록번호 name=resident_registration_number placeholder=주민등록번호",
        ),
        cta_texts=("지원금 대상 조회하기",),
        download_links=(),
        sensitive_field_types=("resident_registration_number",),
        korean_lure_keywords=("지원금",),
        public_agency_keywords=("국민건강보험",),
    )
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        await OpenAIProvider().infer(ctx)

    user_msg = client.post.await_args.kwargs["json"]["messages"][1]["content"]
    body = json.loads(user_msg)
    assert body["body_text"] == ["국민건강보험 고유가 피해지원금 지급대상 여부 조회"]
    assert body["form_fields"] == [
        "label=주민등록번호 name=resident_registration_number placeholder=주민등록번호"
    ]
    assert body["cta_texts"] == ["지원금 대상 조회하기"]
    assert body["sensitive_field_types"] == ["resident_registration_number"]
    assert body["korean_lure_keywords"] == ["지원금"]
    assert body["public_agency_keywords"] == ["국민건강보험"]


async def test_openai_user_prompt_omits_empty_upstream_signals() -> None:
    """기본값(빈 튜플)이면 빈 배열로 직렬화돼 단독 페이지 분석 모드와 동일하게 동작."""
    client = _mock_http_client(json.dumps({"verdict": "benign", "reason": "ok"}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        await OpenAIProvider().infer(_ctx())

    body = json.loads(client.post.await_args.kwargs["json"]["messages"][1]["content"])
    assert body["upstream_signals"] == []


async def test_openai_parse_error_returns_none() -> None:
    client = _mock_http_client("not-json")
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        result = await OpenAIProvider().infer(_ctx())
    assert result is None


async def test_openai_unknown_verdict_returns_none() -> None:
    """응답 JSON 의 verdict 값이 enum 범위를 벗어나면 None 으로 떨어뜨린다."""
    client = _mock_http_client(json.dumps({"verdict": "unknown_value", "reason": "x"}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        assert await OpenAIProvider().infer(_ctx()) is None


async def test_openai_api_exception_returns_none() -> None:
    client = SimpleNamespace(post=AsyncMock(side_effect=RuntimeError("5xx")), aclose=AsyncMock())
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        result = await OpenAIProvider().infer(_ctx())
    assert result is None


async def test_openai_cancelled_propagates() -> None:
    client = SimpleNamespace(
        post=AsyncMock(side_effect=asyncio.CancelledError()),
        aclose=AsyncMock(),
    )
    with (
        patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client),
        pytest.raises(asyncio.CancelledError),
    ):
        await OpenAIProvider().infer(_ctx())


async def test_openai_provider_closes_http_client_with_aclose() -> None:
    client = _mock_http_client(json.dumps({"verdict": "benign", "reason": "ok"}))
    with patch("app.services.content_analyzer.ai_openai.httpx.AsyncClient", return_value=client):
        provider = OpenAIProvider()
        await provider.infer(_ctx())
        await provider.aclose()

    client.aclose.assert_awaited_once()
