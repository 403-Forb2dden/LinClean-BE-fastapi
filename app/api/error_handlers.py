from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.exceptions import AppError
from app.core.logging import get_logger
from app.middleware.request_context import REQUEST_ID_HEADER
from app.schemas.common import ErrorResponse

logger = get_logger(__name__)


def _request_id(request: Request) -> str | None:
    return request.headers.get(REQUEST_ID_HEADER)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        logger.warning("app.error", code=exc.code, message=exc.message, details=exc.details)
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                code=exc.code,
                message=exc.message,
                details=exc.details or None,
                request_id=_request_id(request),
            ).model_dump(exclude_none=True),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorResponse(
                code="http_error",
                message=str(exc.detail),
                request_id=_request_id(request),
            ).model_dump(exclude_none=True),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=ErrorResponse(
                code="validation_error",
                message="Request validation failed.",
                details={"errors": exc.errors()},
                request_id=_request_id(request),
            ).model_dump(exclude_none=True),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled.exception", error=str(exc))
        return JSONResponse(
            status_code=500,
            content=ErrorResponse(
                code="internal_error",
                message="An unexpected error occurred.",
                request_id=_request_id(request),
            ).model_dump(exclude_none=True),
        )
