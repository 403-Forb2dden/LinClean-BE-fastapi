"""사용자 표시용 페이지 스냅샷 생성."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.page_snapshot import PageSnapshotResult, PageSnapshotStatus
from app.services.content_analyzer.fetch import _pick_user_agent
from app.services.content_analyzer.render import _target_blocked

logger = get_logger(__name__)

_SAFE_KEY = re.compile(r"[^A-Za-z0-9_.-]+")


def _elapsed_seconds(started: float) -> float:
    return round(time.perf_counter() - started, 6)


def skipped_page_snapshot(final_url: str, reason: str) -> PageSnapshotResult:
    return PageSnapshotResult(
        status=PageSnapshotStatus.SKIPPED,
        final_url=final_url,
        error=reason,
    )


def timed_out_page_snapshot(final_url: str, started: float | None = None) -> PageSnapshotResult:
    return PageSnapshotResult(
        status=PageSnapshotStatus.TIMEOUT,
        final_url=final_url,
        elapsed_seconds=_elapsed_seconds(started) if started is not None else None,
        error="timeout",
    )


def failed_page_snapshot(
    final_url: str,
    *,
    error: str,
    started: float | None = None,
) -> PageSnapshotResult:
    return PageSnapshotResult(
        status=PageSnapshotStatus.FAILED,
        final_url=final_url,
        elapsed_seconds=_elapsed_seconds(started) if started is not None else None,
        error=error,
    )


def _storage_path(analysis_id: str) -> tuple[Path, str]:
    safe_id = _SAFE_KEY.sub("-", analysis_id).strip("-") or "snapshot"
    storage_dir = Path(settings.page_snapshot_storage_dir)
    filename = f"{safe_id}.png"
    return storage_dir / filename, filename


def _load_playwright() -> tuple[type[BaseException], Callable[[], Any]]:
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright

    return PlaywrightTimeoutError, async_playwright


async def capture_page_snapshot(analysis_id: str, final_url: str) -> PageSnapshotResult:
    """Playwright 로 최종 URL 첫 화면 PNG 를 저장한다.

    보안 차단은 콘텐츠 렌더링과 같은 대상 host 검사를 재사용한다. Playwright 가 없거나
    브라우저 실행이 실패하면 파이프라인을 깨지 않고 failed 상태를 반환한다.
    """
    started = time.perf_counter()

    if not settings.page_snapshot_enabled:
        return skipped_page_snapshot(final_url, "snapshot_disabled")

    if await _target_blocked(final_url):
        logger.info("page_snapshot.blocked_host", url=final_url)
        return failed_page_snapshot(final_url, error="blocked_host", started=started)

    try:
        playwright_timeout_error, async_playwright = _load_playwright()
    except ImportError:
        return failed_page_snapshot(final_url, error="playwright_unavailable", started=started)

    path, storage_key = _storage_path(analysis_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    timeout_ms = int(settings.page_snapshot_timeout_seconds * 1000)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                page = await browser.new_page(
                    user_agent=_pick_user_agent(),
                    locale="ko-KR",
                    viewport={
                        "width": settings.page_snapshot_viewport_width,
                        "height": settings.page_snapshot_viewport_height,
                    },
                )
                await page.goto(final_url, wait_until="domcontentloaded", timeout=timeout_ms)
                await page.screenshot(path=str(path), full_page=settings.page_snapshot_full_page)
            finally:
                await browser.close()
    except playwright_timeout_error:
        return timed_out_page_snapshot(final_url, started)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.warning(
            "page_snapshot.failed",
            url=final_url,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return failed_page_snapshot(final_url, error="snapshot_failed", started=started)

    return PageSnapshotResult(
        status=PageSnapshotStatus.AVAILABLE,
        final_url=final_url,
        storage_key=storage_key,
        elapsed_seconds=_elapsed_seconds(started),
    )
