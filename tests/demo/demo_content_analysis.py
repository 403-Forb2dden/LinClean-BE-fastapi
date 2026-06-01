"""페이지 콘텐츠 정적 분석 데모.

사용법:
    python -m tests.demo.demo_content_analysis

실제 네트워크로 HTML 을 취득해 BS4 로 파싱하고 규칙 기반 점수를 계산한다.
AI 어댑터는 기본값 `NullAIProvider` — `OPENAI_API_KEY` 환경변수가 있으면
이 스크립트가 `OpenAIProvider` 로 교체해서 gpt-4o-mini 추론도 같이 보여준다.

외부 사이트가 응답하지 않으면 해당 케이스는 `fetched=False`, `error=...` 로
degraded 반환되고 파이프라인은 계속 돈다 (의도된 동작).
"""

from __future__ import annotations

import asyncio

from app.core.config import settings
from app.schemas.content_analysis import ContentAnalysisResult
from app.services.content_analyzer import analyze_content
from app.services.content_analyzer.ai import set_ai_provider
from app.services.content_analyzer.ai_openai import OpenAIProvider

DIVIDER = "-" * 72


CASES: list[tuple[str, str]] = [
    # --- 정상 페이지 ---
    ("정상 페이지 (example.com)", "https://example.com/"),
    ("자기 브랜드 도메인 (naver.com)", "https://www.naver.com/"),
    # --- 페치/파싱 경로 점검 ---
    ("HTML 샘플 (httpbin)", "https://httpbin.org/html"),
    ("비-HTML content-type (favicon)", "https://www.google.com/favicon.ico"),
    # --- degraded 경로 ---
    (
        "존재하지 않는 호스트 (connect_error 기대)",
        "https://this-host-definitely-does-not-exist-xyzabc-123.test/",
    ),
    # --- 리다이렉트 방지 동작 확인 ---
    (
        "3xx 응답 (unexpected_redirect — unchainer 가 먼저 해소했어야 하는 케이스)",
        "http://google.com/",
    ),
]


def _fmt_ratio(r: float | None) -> str:
    return "-" if r is None else f"{r:.2f}"


def _print_result(label: str, url: str, result: ContentAnalysisResult) -> None:
    print(f"       input         : {url}")
    print(f"       fetched       : {result.fetched}")
    if not result.fetched:
        print(f"       error         : {result.error}")
    else:
        print(f"       title         : {result.title!r}")
        print(f"       password_form : {result.has_password_field}")
        print(f"       meta_refresh  : {result.has_meta_refresh}")
        print(f"       ext_link_ratio: {_fmt_ratio(result.external_link_ratio)}")
        print(f"       brand_imperson: {result.brand_impersonation}")
        print(f"       alt_imperson  : {result.logo_alt_impersonation}")
    print(f"       score         : {result.score}")
    print(f"       signals       : {[s.value for s in result.signals]}")
    verdict = result.ai_verdict.value if result.ai_verdict else None
    print(f"       ai_verdict    : {verdict} (reason={result.ai_reason!r})")
    if result.ai_error:
        print(f"       ai_error      : {result.ai_error}")


async def main() -> None:
    print()
    print("=" * 72)
    print("  LinClean -- Content Analysis Demo")
    print("=" * 72)
    print()

    provider: OpenAIProvider | None = None
    if settings.openai_api_key:
        provider = OpenAIProvider()
        set_ai_provider(provider)
        print(f"  AI: OpenAIProvider ({settings.openai_model})")
    else:
        print("  AI: NullAIProvider (OPENAI_API_KEY 미설정 — ai_verdict 는 None)")
    print(f"  danger threshold (skip 기준): {settings.score_danger_threshold}")
    print()

    try:
        for i, (desc, url) in enumerate(CASES, 1):
            print(f"  [{i:02d}] {desc}")
            try:
                result = await analyze_content(url)
            except Exception as exc:  # 데모에서만 — 운영 코드는 파이프라인이 degraded 처리
                print(f"       !! 예외: {type(exc).__name__}: {exc}")
                print(DIVIDER)
                continue
            _print_result(desc, url, result)
            print(DIVIDER)
    finally:
        if provider is not None:
            await provider.aclose()

    print()


if __name__ == "__main__":
    asyncio.run(main())
