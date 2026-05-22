"""analyze_content — fetch · extract · signals · AI 통합."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
from app.core.config import settings
from app.schemas.content_analysis import AIVerdict, ContentSignal, TokenUsage
from app.services.content_analyzer.ai import AIInference, AIPromptContext, NullAIProvider
from app.services.content_analyzer.analyze import analyze_content, skipped_already_danger
from app.services.content_analyzer.fetch import FetchResult


def _mock_fetch(ok: bool, html: str = "", error: str | None = None, status: int = 200):
    return patch(
        "app.services.content_analyzer.analyze.fetch_page",
        AsyncMock(
            return_value=FetchResult(
                ok=ok,
                url="https://x.test/",
                status_code=status,
                html=html,
                error=error,
            )
        ),
    )


class TestHappyPath:
    async def test_clean_page_returns_zero_score(self) -> None:
        html = "<html><head><title>Hello</title></head><body><p>ok</p></body></html>"
        with _mock_fetch(ok=True, html=html):
            result = await analyze_content("https://benign.test/")

        assert result.fetched is True
        assert result.final_url == "https://benign.test/"
        assert result.score == 0
        assert result.signals == []
        assert result.title == "Hello"
        assert result.has_password_field is False
        assert result.error is None


class TestFetchFailure:
    async def test_fetch_failure_degraded_result(self) -> None:
        with _mock_fetch(ok=False, error="timeout"):
            result = await analyze_content("https://down.test/")

        assert result.fetched is False
        assert result.error == "timeout"
        assert ContentSignal.FETCH_FAILED in result.signals
        assert result.score == settings.score_weight_content_fetch_failed
        assert result.ai_verdict is None

    async def test_http_404_fetch_failure_has_human_readable_reason(self) -> None:
        with _mock_fetch(ok=False, error="http_error_404", status=404):
            result = await analyze_content("https://missing.test/")

        assert result.fetched is False
        assert result.error == "http_error_404"
        assert result.reason == "페이지를 찾을 수 없습니다."
        assert result.status_code == 404
        assert result.ai_verdict is None

    async def test_success_exposes_final_url_status_code(self) -> None:
        with _mock_fetch(ok=True, html="<html></html>", status=204):
            result = await analyze_content("https://ok.test/")

        assert result.fetched is True
        assert result.status_code == 204

    @pytest.mark.parametrize("error", ["not_html", "too_large", "unexpected_redirect"])
    async def test_benign_fetch_errors_score_zero(self, error: str) -> None:
        """정상 컨텐츠(PDF/이미지/대형 정적)·파이프라인 이슈는 시그널만 남기고 가산은 0."""
        with _mock_fetch(ok=False, error=error):
            result = await analyze_content("https://x.test/")

        assert result.score == 0
        assert ContentSignal.FETCH_FAILED in result.signals
        assert result.error == error

    async def test_fetch_failure_skips_extract_and_ai(self) -> None:
        with (
            _mock_fetch(ok=False, error="connect_error"),
            patch("app.services.content_analyzer.analyze.extract_features_async") as ext_mock,
            patch("app.services.content_analyzer.analyze.score_content") as sig_mock,
            patch("app.services.content_analyzer.analyze.get_ai_provider") as ai_mock,
        ):
            await analyze_content("https://x.test/")

        ext_mock.assert_not_called()
        sig_mock.assert_not_called()
        ai_mock.assert_not_called()

    def test_skipped_already_danger_has_fixed_user_reason(self) -> None:
        result = skipped_already_danger("https://danger.test/")

        assert result.fetched is False
        assert result.ai_reason is None
        assert result.reason == "위험성이 확인된 URL입니다. 페이지를 열지 않는 것이 좋습니다."
        assert result.error == "skipped_already_danger"


class TestBrandImpersonationEndToEnd:
    async def test_brand_impersonation_form_scored(self) -> None:
        html = """
        <html>
          <head><title>NAVER 로그인</title></head>
          <body>
            <form><input type="password" name="pw"></form>
            <img src="logo.png" alt="NAVER">
          </body>
        </html>
        """
        with _mock_fetch(ok=True, html=html):
            result = await analyze_content("https://evil-naver.test/signin")

        assert result.fetched is True
        assert result.brand_impersonation is True
        assert result.logo_alt_impersonation is True
        assert ContentSignal.BRAND_IMPERSONATION_FORM in result.signals
        assert ContentSignal.LOGO_ALT_IMPERSONATION in result.signals
        assert result.title == "NAVER 로그인"
        assert result.has_password_field is True


class TestHighSignalContextEndToEnd:
    async def test_high_signal_features_surface_and_ai_sees_structured_summary(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[AIPromptContext] = []

        class CaptureAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                seen.append(ctx)
                return AIInference(verdict=AIVerdict.BENIGN, reason="local signals enough")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: CaptureAI(),
        )
        html = """
        <html>
          <head><title>고유가 피해지원금 대상 조회</title></head>
          <body>
            <h1>국민건강보험 고유가 피해지원금 지급대상 여부 조회</h1>
            <form>
              <label for="rrn">주민등록번호</label>
              <input id="rrn" name="resident_registration_number" placeholder="주민등록번호">
              <button type="button">지원금 대상 조회하기</button>
            </form>
          </body>
        </html>
        """
        with _mock_fetch(ok=True, html=html):
            result = await analyze_content("https://nhis-support.test/")

        assert result.body_text_snippets
        assert "지원금 대상 조회하기" in result.cta_texts
        assert "resident_registration_number" in result.sensitive_field_types
        assert ContentSignal.PII_COLLECTION_FORM in result.signals
        assert len(seen) == 1
        assert "지원금 대상 조회하기" in seen[0].cta_texts
        assert "resident_registration_number" in seen[0].sensitive_field_types
        assert "국민건강보험" in seen[0].public_agency_keywords

    async def test_ai_provider_still_called_once_with_extended_context(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = 0

        class CountingAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                nonlocal calls
                calls += 1
                return AIInference(verdict=AIVerdict.SUSPICIOUS, reason="structured context")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: CountingAI(),
        )
        html = (
            '<html><body><a href="/downloads/kakaotalk.apk">'
            "카카오톡 최신버전 다운로드</a></body></html>"
        )
        with _mock_fetch(ok=True, html=html):
            await analyze_content("https://obituary.test/")

        assert calls == 1


class TestAI:
    async def test_ai_phishing_verdict_adds_score(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class StubAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                return AIInference(verdict=AIVerdict.PHISHING, reason="brand mismatch")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: StubAI(),
        )

        html = "<html><head><title>hi</title></head></html>"
        with _mock_fetch(ok=True, html=html):
            result = await analyze_content("https://x.test/")

        assert result.ai_verdict == AIVerdict.PHISHING
        assert result.ai_reason == "brand mismatch"
        assert result.score >= settings.score_weight_ai_phishing

    async def test_ai_suspicious_verdict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class StubAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                return AIInference(verdict=AIVerdict.SUSPICIOUS, reason="mild")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: StubAI(),
        )
        with _mock_fetch(ok=True, html="<html></html>"):
            result = await analyze_content("https://x.test/")

        assert result.ai_verdict == AIVerdict.SUSPICIOUS
        assert result.score == settings.score_weight_ai_suspicious

    async def test_ai_benign_verdict_no_score(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class StubAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                return AIInference(verdict=AIVerdict.BENIGN, reason="ok")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: StubAI(),
        )
        with _mock_fetch(ok=True, html="<html></html>"):
            result = await analyze_content("https://x.test/")

        assert result.ai_verdict == AIVerdict.BENIGN
        assert result.score == 0

    async def test_ai_none_keeps_nulls(self) -> None:
        # 기본 provider 는 NullAIProvider → None 반환
        with _mock_fetch(ok=True, html="<html></html>"):
            result = await analyze_content("https://x.test/")

        assert result.ai_verdict is None
        assert result.ai_reason is None
        assert result.ai_error is None
        assert result.ai_model is None
        assert result.ai_token_usage is None

    async def test_ai_token_usage_and_model_surface(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """프로바이더가 채워 준 model/token_usage 가 결과에 그대로 실려 나와야 한다."""

        class TokenAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                return AIInference(
                    verdict=AIVerdict.BENIGN,
                    reason="ok",
                    model="gpt-4o-mini",
                    token_usage=TokenUsage(
                        prompt_tokens=100,
                        completion_tokens=20,
                        total_tokens=120,
                    ),
                )

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: TokenAI(),
        )
        with _mock_fetch(ok=True, html="<html></html>"):
            result = await analyze_content("https://x.test/")

        assert result.ai_model == "gpt-4o-mini"
        assert result.ai_token_usage is not None
        assert result.ai_token_usage.total_tokens == 120

    async def test_ai_exception_is_absorbed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class BoomAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                raise RuntimeError("model exploded")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: BoomAI(),
        )
        with _mock_fetch(ok=True, html="<html></html>"):
            result = await analyze_content("https://x.test/")

        assert result.ai_verdict is None
        assert result.ai_error is not None
        # 규칙 기반 결과는 여전히 유효
        assert result.fetched is True


class TestSpaShellEndToEnd:
    async def test_spa_shell_flag_surfaces_and_ai_sees_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """SPA 셸 HTML 에 대해 ContentAnalysisResult.is_spa_shell=True 로 나오고,
        AI 프로바이더의 프롬프트 컨텍스트에도 is_spa_shell=True 가 실려 전달된다."""
        seen: list[AIPromptContext] = []

        class CaptureAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                seen.append(ctx)
                return AIInference(verdict=AIVerdict.BENIGN, reason="spa shell, no evidence")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: CaptureAI(),
        )
        html = (
            '<!doctype html><html><head><title>x</title>'
            '<script type="module" src="./app.js"></script></head>'
            '<body><div id="root"></div></body></html>'
        )
        with _mock_fetch(ok=True, html=html):
            result = await analyze_content("https://spa.test/")

        assert result.is_spa_shell is True
        assert result.has_password_field is False
        assert ContentSignal.SPA_SHELL in result.signals
        # SPA 셸은 규칙 점수 가산 없음 — AI benign 이므로 최종 점수 0
        assert result.score == 0
        assert len(seen) == 1
        assert seen[0].is_spa_shell is True


class TestCancelledError:
    async def test_fetch_cancelled_propagates(self) -> None:
        """shutdown/timeout 신호는 degraded 결과로 흡수하지 않고 re-raise."""
        with patch(
            "app.services.content_analyzer.analyze.fetch_page",
            AsyncMock(side_effect=asyncio.CancelledError()),
        ), pytest.raises(asyncio.CancelledError):
            await analyze_content("https://x.test/")

    async def test_ai_cancelled_propagates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class CancelAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                raise asyncio.CancelledError()

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: CancelAI(),
        )
        with _mock_fetch(ok=True, html="<html></html>"), pytest.raises(asyncio.CancelledError):
            await analyze_content("https://x.test/")


async def test_null_provider_used_by_default() -> None:
    """설정 없이 호출 시 NullAIProvider 가 쓰이고 AI 필드는 None."""
    from app.services.content_analyzer import ai as ai_module

    assert isinstance(ai_module.get_ai_provider(), NullAIProvider)


class TestUpstreamSignals:
    """analyze_content 가 받은 upstream_signals 를 AI 프롬프트 컨텍스트로 그대로 전달해야 한다."""

    async def test_upstream_signals_forwarded_to_provider(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seen: list[AIPromptContext] = []

        class CaptureAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                seen.append(ctx)
                return AIInference(verdict=AIVerdict.SUSPICIOUS, reason="ok")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: CaptureAI(),
        )
        with _mock_fetch(ok=True, html="<html><head><title>x</title></head></html>"):
            await analyze_content(
                "https://x.test/",
                upstream_signals=["TYPO_DOMAIN", "NEW_DOMAIN"],
            )

        assert len(seen) == 1
        assert seen[0].upstream_signals == ("TYPO_DOMAIN", "NEW_DOMAIN")

    async def test_upstream_signals_default_empty(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """파라미터를 생략하면 빈 튜플 — 디버그 엔드포인트처럼 선행 단계 없이 호출되는 경로 보호."""
        seen: list[AIPromptContext] = []

        class CaptureAI:
            async def infer(self, ctx: AIPromptContext) -> AIInference:
                seen.append(ctx)
                return AIInference(verdict=AIVerdict.BENIGN, reason="ok")

        monkeypatch.setattr(
            "app.services.content_analyzer.analyze.get_ai_provider",
            lambda: CaptureAI(),
        )
        with _mock_fetch(ok=True, html="<html></html>"):
            await analyze_content("https://x.test/")

        assert seen[0].upstream_signals == ()
