"""ai.py — 프로바이더 Protocol + Null 기본 어댑터."""

from __future__ import annotations

import pytest
from app.schemas.content_analysis import AIVerdict
from app.services.content_analyzer.ai import (
    AIInference,
    AIPromptContext,
    NullAIProvider,
    get_ai_provider,
    set_ai_provider,
)


@pytest.fixture(autouse=True)
def _reset_provider() -> None:
    """각 테스트 종료 시 기본 NullAIProvider 로 복구."""
    yield
    set_ai_provider(NullAIProvider())


async def test_null_provider_returns_none() -> None:
    ctx = AIPromptContext(
        final_url="https://x.test/",
        title="hi",
        has_password_field=False,
        has_meta_refresh=False,
        image_alts=(),
        external_link_ratio=None,
    )
    result = await NullAIProvider().infer(ctx)
    assert result is None


async def test_default_provider_is_null() -> None:
    assert isinstance(get_ai_provider(), NullAIProvider)


async def test_set_custom_provider() -> None:
    class FakeProvider:
        async def infer(self, ctx: AIPromptContext) -> AIInference | None:
            return AIInference(verdict=AIVerdict.PHISHING, reason="mock")

    set_ai_provider(FakeProvider())
    provider = get_ai_provider()
    ctx = AIPromptContext(
        final_url="https://x.test/",
        title=None,
        has_password_field=False,
        has_meta_refresh=False,
        image_alts=(),
        external_link_ratio=None,
    )
    inference = await provider.infer(ctx)
    assert inference is not None
    assert inference.verdict == AIVerdict.PHISHING
    assert inference.reason == "mock"
