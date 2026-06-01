import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.error_handlers import register_error_handlers
from app.api.v1.router import api_router as api_v1_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.core.scheduler import shutdown_scheduler, start_scheduler
from app.db.session import engine
from app.middleware.request_context import RequestContextMiddleware
from app.services.content_analyzer.ai import AIProvider, set_ai_provider
from app.services.content_analyzer.fetch import aclose_client as aclose_fetch_client
from app.services.domain_heuristic.rdap import aclose_client as aclose_rdap_client
from app.services.unchainer.unchain import aclose_client as aclose_unchain_client

logger = get_logger(__name__)


def _select_ai_provider() -> AIProvider:
    """OpenAIProvider 를 고정 사용한다. SDK import 는 provider 내부에서 infer 시점까지 지연한다."""
    from app.services.content_analyzer.ai_openai import OpenAIProvider

    return OpenAIProvider()


async def _aclose_provider(provider: AIProvider) -> None:
    # AIProvider Protocol 에는 aclose 가 없다 — 구현체에만 있으면 호출.
    aclose = getattr(provider, "aclose", None)
    if aclose is not None:
        await aclose()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    configure_logging()
    logger.info(
        "app.startup",
        environment=settings.environment,
        version=settings.app_version,
    )
    start_scheduler()

    # AI 프로바이더 부트스트랩 — 키가 없으면 NullAIProvider (4단계 AI 추론 비활성).
    # 로컬/CI 에서도 이 분기로 안전하게 동작하므로 별도 조건이 필요 없다.
    ai_provider = _select_ai_provider()
    set_ai_provider(ai_provider)
    logger.info(
        "app.ai_provider",
        provider=type(ai_provider).__name__,
        choice=settings.ai_provider,
    )
    startup_task: asyncio.Task[dict[str, int]] | None = None
    if settings.scheduler_enabled and settings.urlhaus_sync_on_startup:
        # 최초 부트 시 즉시 1회 동기화 (백그라운드, 앱 기동은 블로킹하지 않음).
        from app.services.threat_db.urlhaus_sync import sync_urlhaus

        startup_task = asyncio.create_task(sync_urlhaus())

        def _log_startup_sync_result(t: asyncio.Task[dict[str, int]]) -> None:
            # 백그라운드 task 의 예외가 사일런트하게 사라지지 않도록 로깅.
            if t.cancelled():
                return
            exc = t.exception()
            if exc is not None:
                logger.warning(
                    "urlhaus_sync.startup_failed",
                    error=str(exc),
                    error_type=type(exc).__name__,
                )

        startup_task.add_done_callback(_log_startup_sync_result)

    try:
        yield
    finally:
        logger.info("app.shutdown")
        if startup_task is not None and not startup_task.done():
            startup_task.cancel()
            # cancel 후 짧게 대기해 "Task was destroyed but it is pending" 경고 방지.
            with suppress(TimeoutError, asyncio.CancelledError):
                await asyncio.wait_for(
                    asyncio.shield(asyncio.gather(startup_task, return_exceptions=True)),
                    timeout=2.0,
                )
        shutdown_scheduler(wait=False)
        await aclose_rdap_client()
        await aclose_fetch_client()
        await aclose_unchain_client()
        await _aclose_provider(ai_provider)
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
