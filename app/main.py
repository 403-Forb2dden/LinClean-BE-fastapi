import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.error_handlers import register_error_handlers
from app.api.v1.router import api_router as api_v1_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.core.scheduler import shutdown_scheduler, start_scheduler
from app.db.session import engine
from app.middleware.request_context import RequestContextMiddleware

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    logger.info(
        "app.startup",
        environment=settings.environment,
        version=settings.app_version,
    )
    start_scheduler()
    startup_task: asyncio.Task | None = None
    if settings.scheduler_enabled and settings.urlhaus_sync_on_startup:
        # 최초 부트 시 즉시 1회 동기화 (백그라운드, 앱 기동은 블로킹하지 않음).
        from app.services.threat_db.urlhaus_sync import sync_urlhaus

        startup_task = asyncio.create_task(sync_urlhaus())

    try:
        yield
    finally:
        logger.info("app.shutdown")
        if startup_task is not None and not startup_task.done():
            startup_task.cancel()
        shutdown_scheduler(wait=False)
        await engine.dispose()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        openapi_url=f"{settings.api_v1_prefix}/openapi.json",
        docs_url=f"{settings.api_v1_prefix}/docs",
        redoc_url=f"{settings.api_v1_prefix}/redoc",
        lifespan=lifespan,
    )

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_error_handlers(app)

    app.include_router(api_v1_router, prefix=settings.api_v1_prefix)

    return app


app = create_app()
