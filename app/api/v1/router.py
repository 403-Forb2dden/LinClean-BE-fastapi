from fastapi import APIRouter

from app.api.v1.endpoints import analyze, health
from app.core.config import settings

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(analyze.router, tags=["analyze"])

if settings.debug:
    from app.api.v1.endpoints import dev

    api_router.include_router(dev.router, prefix="/dev", tags=["dev"])
