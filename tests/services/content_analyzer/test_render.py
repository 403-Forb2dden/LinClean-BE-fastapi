from __future__ import annotations

import pytest
from app.services.content_analyzer import render


@pytest.mark.asyncio
async def test_render_semaphore_is_recreated_per_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = render._get_render_semaphore()
    monkeypatch.setattr(render, "_render_semaphore_loop_ref", lambda: object())
    second = render._get_render_semaphore()

    assert first is not second
