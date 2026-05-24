from __future__ import annotations

import asyncio

from app.services.content_analyzer import render


def test_render_semaphore_is_recreated_per_event_loop() -> None:
    async def get_sem() -> asyncio.Semaphore:
        return render._get_render_semaphore()

    first = asyncio.run(get_sem())
    second = asyncio.run(get_sem())

    assert first is not second
