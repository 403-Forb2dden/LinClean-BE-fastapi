from fastapi import APIRouter, status
from sqlalchemy import text

from app.api.deps import DBSession
from app.core.config import settings
from app.schemas.common import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def health() -> HealthResponse:
    """Liveness probe — does not touch dependencies."""
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        environment=settings.environment,
    )


@router.get("/health/ready", response_model=HealthResponse, status_code=status.HTTP_200_OK)
async def readiness(db: DBSession) -> HealthResponse:
    """Readiness probe — verifies database connectivity."""
    await db.execute(text("SELECT 1"))
    return HealthResponse(
        status="ready",
        version=settings.app_version,
        environment=settings.environment,
    )
