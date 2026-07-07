from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from app.core.config import settings
from app.schemas.page_snapshot import PageSnapshotStatus
from app.services.page_snapshot import capture_page_snapshot, skipped_page_snapshot


def test_skipped_page_snapshot_marks_reason() -> None:
    result = skipped_page_snapshot("https://example.com/", "skipped_already_danger")

    assert result.status == PageSnapshotStatus.SKIPPED
    assert result.final_url == "https://example.com/"
    assert result.error == "skipped_already_danger"
    assert result.storage_key is None


@pytest.mark.asyncio
async def test_capture_page_snapshot_returns_failed_when_target_is_blocked() -> None:
    with patch("app.services.page_snapshot._target_blocked", new_callable=AsyncMock) as blocked:
        blocked.return_value = True

        result = await capture_page_snapshot("aid-blocked", "http://127.0.0.1/")

    assert result.status == PageSnapshotStatus.FAILED
    assert result.error == "blocked_host"
    assert result.elapsed_seconds is not None


@pytest.mark.asyncio
async def test_capture_page_snapshot_sanitizes_storage_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "page_snapshot_storage_dir", str(tmp_path))

    with (
        patch("app.services.page_snapshot._target_blocked", new_callable=AsyncMock) as blocked,
        patch("app.services.page_snapshot._load_playwright") as load_playwright,
    ):
        blocked.return_value = False
        page = AsyncMock()
        browser = AsyncMock()
        browser.new_page.return_value = page
        chromium = AsyncMock()
        chromium.launch.return_value = browser
        playwright_context = MagicMock()
        playwright_context.__aenter__ = AsyncMock(
            return_value=MagicMock(chromium=chromium)
        )
        playwright_context.__aexit__ = AsyncMock(return_value=None)
        async_playwright = MagicMock(return_value=playwright_context)
        load_playwright.return_value = (TimeoutError, async_playwright)

        result = await capture_page_snapshot("aid/#45 snapshot", "https://example.com/")

    assert result.status == PageSnapshotStatus.AVAILABLE
    assert result.storage_key == "aid-45-snapshot.png"
    page.screenshot.assert_awaited_once_with(
        path=str(tmp_path / "aid-45-snapshot.png"),
        full_page=settings.page_snapshot_full_page,
    )
