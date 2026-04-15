"""APScheduler 싱글톤 — URLhaus 일일 동기화 스케줄링."""

from __future__ import annotations

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler(timezone="UTC")
    return _scheduler


def start_scheduler() -> None:
    """URLhaus 동기화 job 을 등록하고 스케줄러 기동.

    `scheduler_enabled=False` 면 no-op (테스트 환경 용).
    """
    if not settings.scheduler_enabled:
        logger.info("scheduler.disabled")
        return

    # import 시점에 순환 참조 방지차 지연 로드.
    from app.services.threat_db.urlhaus_sync import sync_urlhaus

    scheduler = get_scheduler()
    if scheduler.running:
        return

    scheduler.add_job(
        sync_urlhaus,
        trigger=CronTrigger(hour=settings.urlhaus_sync_cron_hour, minute=0),
        id="urlhaus_sync",
        coalesce=True,
        max_instances=1,
        misfire_grace_time=3600,
        replace_existing=True,
    )
    scheduler.start()
    logger.info("scheduler.started", cron_hour=settings.urlhaus_sync_cron_hour)


def shutdown_scheduler(wait: bool = False) -> None:
    global _scheduler
    if _scheduler is None or not _scheduler.running:
        return
    _scheduler.shutdown(wait=wait)
    logger.info("scheduler.stopped")
