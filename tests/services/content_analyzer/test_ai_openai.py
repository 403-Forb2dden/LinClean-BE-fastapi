"""OpenAIProvider — gpt-4o-mini 기반 피싱 추론 어댑터."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

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


def _mock_completion(
    content: str,
    *,
    usage: SimpleNamespace | None = None,
) -> SimpleNamespace:
    """chat.completions.create 가 돌려주는 객체 모양을 흉내낸 간단 스텁."""
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
        usage=usage,
    )


def _usage(prompt: int, completion: int) -> SimpleNamespace:
    return SimpleNamespace(
        prompt_tokens=prompt,
        completion_tokens=completion,
        total_tokens=prompt + completion,
    )


async def test_openai_returns_verdict_on_success() -> None:
    payload = json.dumps({"verdict": "phishing", "reason": "브랜드 불일치"})
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=AsyncMock(
                    return_value=_mock_completion(payload, usage=_usage(120, 18))
                )
            )
        )
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        provider = OpenAIProvider()
        result = await provider.infer(_ctx())

    assert result is not None
    assert result.verdict == AIVerdict.PHISHING
    assert result.reason == "브랜드 불일치"
    # 모델 id 와 토큰 사용량이 추론 결과에 실려 나와야 한다
    assert result.model == settings.openai_model
    assert result.token_usage is not None
    assert result.token_usage.prompt_tokens == 120
    assert result.token_usage.completion_tokens == 18
    assert result.token_usage.total_tokens == 138


async def test_openai_missing_usage_returns_none_token_usage() -> None:
    """usage 가 비어 있으면 token_usage=None 으로 떨어뜨린다 (추론 자체는 성공)."""
    payload = json.dumps({"verdict": "benign", "reason": "ok"})
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=AsyncMock(return_value=_mock_completion(payload, usage=None))
            )
        )
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        result = await OpenAIProvider().infer(_ctx())

    assert result is not None
    assert result.token_usage is None


async def test_openai_custom_model_overrides_settings() -> None:
    """생성자에 model 을 넘기면 settings.openai_model 보다 우선한다 — 모델 비교용."""
    payload = json.dumps({"verdict": "benign", "reason": "ok"})
    create = AsyncMock(return_value=_mock_completion(payload, usage=_usage(10, 5)))
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        result = await OpenAIProvider(model="gpt-4o").infer(_ctx())

    assert create.call_args.kwargs["model"] == "gpt-4o"
    assert result is not None
    assert result.model == "gpt-4o"


async def test_openai_returns_none_without_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_api_key", None)
    provider = OpenAIProvider()
    assert await provider.infer(_ctx()) is None


async def test_openai_uses_configured_model(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "openai_model", "gpt-4o-mini")

    create = AsyncMock(
        return_value=_mock_completion(json.dumps({"verdict": "benign", "reason": "ok"}))
    )
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        await OpenAIProvider().infer(_ctx())

    kwargs = create.call_args.kwargs
    assert kwargs["model"] == "gpt-4o-mini"
    # structured output 스키마 사용
    assert kwargs["response_format"]["type"] == "json_schema"
    assert kwargs["response_format"]["json_schema"]["strict"] is True
    # timeout 전달
    assert kwargs["timeout"] == settings.openai_timeout_seconds


async def test_openai_user_prompt_includes_upstream_signals() -> None:
    """ctx.upstream_signals 가 user payload 의 upstream_signals 배열로 직렬화돼야 한다."""
    payload = json.dumps({"verdict": "phishing", "reason": "타이포 + 비밀번호 폼"})
    create = AsyncMock(return_value=_mock_completion(payload, usage=_usage(50, 10)))
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
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
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        await OpenAIProvider().infer(ctx)

    user_msg = create.call_args.kwargs["messages"][1]["content"]
    body = json.loads(user_msg)
    assert body["upstream_signals"] == ["TYPO_DOMAIN", "NEW_DOMAIN"]


async def test_openai_user_prompt_omits_empty_upstream_signals() -> None:
    """기본값(빈 튜플)이면 빈 배열로 직렬화돼 단독 페이지 분석 모드와 동일하게 동작."""
    payload = json.dumps({"verdict": "benign", "reason": "ok"})
    create = AsyncMock(return_value=_mock_completion(payload))
    client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=create))
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        await OpenAIProvider().infer(_ctx())

    body = json.loads(create.call_args.kwargs["messages"][1]["content"])
    assert body["upstream_signals"] == []


async def test_openai_parse_error_returns_none() -> None:
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=AsyncMock(return_value=_mock_completion("not-json"))
            )
        )
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        result = await OpenAIProvider().infer(_ctx())
    assert result is None


async def test_openai_unknown_verdict_returns_none() -> None:
    """응답 JSON 의 verdict 값이 enum 범위를 벗어나면 None 으로 떨어뜨린다."""
    payload = json.dumps({"verdict": "unknown_value", "reason": "x"})
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=AsyncMock(return_value=_mock_completion(payload)))
        )
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        assert await OpenAIProvider().infer(_ctx()) is None


async def test_openai_api_exception_returns_none() -> None:
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(create=AsyncMock(side_effect=RuntimeError("5xx")))
        )
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ):
        result = await OpenAIProvider().infer(_ctx())
    assert result is None


async def test_openai_cancelled_propagates() -> None:
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=AsyncMock(side_effect=asyncio.CancelledError())
            )
        )
    )
    with patch(
        "app.services.content_analyzer.ai_openai.AsyncOpenAI",
        return_value=client,
    ), pytest.raises(asyncio.CancelledError):
        await OpenAIProvider().infer(_ctx())
