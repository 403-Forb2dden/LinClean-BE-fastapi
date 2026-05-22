"""선택적 Playwright 기반 렌더링 분석.

정적 HTML 만으로 판정하기 어려운 SPA/동적 페이지에 한해 호출된다.
Playwright 가 설치되지 않았거나 브라우저 실행에 실패하면 degraded 결과를 반환하고,
기존 정적 분석 경로는 그대로 유지한다.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from app.core.config import settings
from app.core.logging import get_logger
from app.services.content_analyzer.fetch import (
    _is_blocked_host,
    _is_ip_literal,
    _pick_user_agent,
    _resolved_addrs_blocked,
)

logger = get_logger(__name__)
_BLOCKED_RESOURCE_TYPES: frozenset[str] = frozenset({"image", "media", "font"})


@dataclass(frozen=True)
class RenderResult:
    ok: bool
    url: str
    html: str = ""
    error: str | None = None


_render_semaphore: asyncio.Semaphore | None = None


def _get_render_semaphore() -> asyncio.Semaphore:
    global _render_semaphore
    if _render_semaphore is None:
        _render_semaphore = asyncio.Semaphore(settings.content_render_concurrency)
    return _render_semaphore


async def _target_blocked(url: str) -> bool:
    parsed = urlparse(url)
    if _is_blocked_host(parsed.hostname):
        return True
    if parsed.hostname and not _is_ip_literal(parsed.hostname.strip("[]")):
        try:
            return await _resolved_addrs_blocked(parsed.hostname)
        except OSError:
            return False
    return False


async def render_page(url: str) -> RenderResult:
    """브라우저 렌더링 후 DOM HTML 을 반환한다.

    내부망 SSRF 방어는 fetch 와 같은 1·2선 검사 함수를 재사용한다. DNS rebind 잔여 위험은
    fetch 와 동일하게 배포 단 egress 정책으로 닫아야 한다.
    """
    if not settings.content_precision_enabled:
        return RenderResult(ok=False, url=url, error="precision_disabled")

    if await _target_blocked(url):
        logger.info("content_render.blocked_host", url=url)
        return RenderResult(ok=False, url=url, error="blocked_host")

    try:
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError
        from playwright.async_api import async_playwright
    except ImportError:
        return RenderResult(ok=False, url=url, error="playwright_unavailable")

    timeout_ms = int(settings.content_render_timeout_seconds * 1000)
    sem = _get_render_semaphore()
    async with sem:
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                try:
                    page = await browser.new_page(
                        user_agent=_pick_user_agent(),
                        locale="ko-KR",
                    )

                    async def _route_handler(route: Any) -> None:
                        request = route.request
                        if request.resource_type in _BLOCKED_RESOURCE_TYPES:
                            await route.abort()
                        else:
                            await route.continue_()

                    await page.route("**/*", _route_handler)
                    await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                    await page.wait_for_timeout(settings.content_render_settle_ms)
                    html = await page.content()
                    return RenderResult(ok=True, url=url, html=html)
                finally:
                    await browser.close()
        except PlaywrightTimeoutError:
            return RenderResult(ok=False, url=url, error="timeout")
        except Exception as exc:
            logger.warning(
                "content_render.failed",
                url=url,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return RenderResult(ok=False, url=url, error="render_failed")
