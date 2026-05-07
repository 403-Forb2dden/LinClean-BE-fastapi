from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.pipeline import PipelineFailure, PipelineSuccess

logger = get_logger(__name__)

_CALLBACK_PATH = "/internal/analysis-result"
_MAX_ATTEMPTS = 3


def _iso_z(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _callback_url() -> str:
    return f"{settings.spring_internal_url.rstrip('/')}{_CALLBACK_PATH}"


def _success_payload(
    result: PipelineSuccess,
    *,
    request_id: str,
    elapsed_ms: int,
    analyzed_at: datetime,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "analysisId": result.analysis_id,
        "requestId": request_id,
        "status": "succeeded",
        "originalUrl": result.original_url,
        "finalUrl": result.final_url,
        "verdict": result.verdict.value,
        "score": result.score,
        "stages": result.stages.model_dump(mode="json"),
        "engineVersion": settings.app_version,
        "analyzedAt": _iso_z(analyzed_at),
        "elapsedMs": elapsed_ms,
    }
    if result.timings is not None:
        payload["timings"] = result.timings.model_dump(mode="json")
    return payload


def _failure_payload(
    result: PipelineFailure,
    *,
    request_id: str,
    elapsed_ms: int,
    analyzed_at: datetime,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "analysisId": result.analysis_id,
        "requestId": request_id,
        "status": "failed",
        "originalUrl": result.original_url,
        "error": {
            "code": f"{result.failed_at_stage.value.upper()}_FAILED",
            "stage": result.failed_at_stage.value,
            "message": result.error,
        },
        "engineVersion": settings.app_version,
        "analyzedAt": _iso_z(analyzed_at),
        "elapsedMs": elapsed_ms,
    }
    if result.timings is not None:
        payload["timings"] = result.timings.model_dump(mode="json")
    return payload


def build_analysis_callback_payload(
    result: PipelineSuccess | PipelineFailure,
    *,
    request_id: str,
    elapsed_ms: int,
    analyzed_at: datetime,
) -> dict[str, Any]:
    if isinstance(result, PipelineSuccess):
        return _success_payload(
            result,
            request_id=request_id,
            elapsed_ms=elapsed_ms,
            analyzed_at=analyzed_at,
        )
    return _failure_payload(
        result,
        request_id=request_id,
        elapsed_ms=elapsed_ms,
        analyzed_at=analyzed_at,
    )


async def post_analysis_callback(
    result: PipelineSuccess | PipelineFailure,
    *,
    request_id: str,
    elapsed_ms: int,
    analyzed_at: datetime,
) -> bool:
    payload = build_analysis_callback_payload(
        result,
        request_id=request_id,
        elapsed_ms=elapsed_ms,
        analyzed_at=analyzed_at,
    )
    headers = {
        "Content-Type": "application/json",
        "X-Internal-Api-Key": settings.internal_api_key,
        "X-Request-ID": request_id,
    }
    url = _callback_url()

    async with httpx.AsyncClient(timeout=10.0) as client:
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                resp = await client.post(url, json=payload, headers=headers)
            except httpx.HTTPError as exc:
                logger.warning(
                    "analysis_callback.request_failed",
                    analysis_id=result.analysis_id,
                    attempt=attempt,
                    error=str(exc),
                )
            else:
                if 200 <= resp.status_code < 300:
                    logger.info(
                        "analysis_callback.delivered",
                        analysis_id=result.analysis_id,
                        attempt=attempt,
                    )
                    return True
                logger.warning(
                    "analysis_callback.bad_status",
                    analysis_id=result.analysis_id,
                    attempt=attempt,
                    status_code=resp.status_code,
                )

            if attempt < _MAX_ATTEMPTS:
                await asyncio.sleep(0.5 * (2 ** (attempt - 1)))

    logger.error(
        "analysis_callback.dead_letter",
        analysis_id=result.analysis_id,
        callback_url=url,
        attempts=_MAX_ATTEMPTS,
        payload=payload,
    )
    return False
