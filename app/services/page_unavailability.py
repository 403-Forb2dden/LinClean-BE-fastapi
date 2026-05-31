from __future__ import annotations

from app.schemas.content_analysis import ContentAnalysisResult
from app.schemas.unchain import UnchainResult

PAGE_UNAVAILABLE_CODE = "PAGE_UNAVAILABLE"

_UNAVAILABLE_ERRORS: tuple[str, ...] = (
    "dns_failure",
    "timeout",
    "connect_error",
    "blocked_host",
    "invalid_host",
)


def _message_for_status(status_code: int) -> str:
    if status_code == 404:
        return "페이지를 찾을 수 없습니다."
    if 400 <= status_code < 500:
        return "페이지 요청이 거부되었거나 찾을 수 없습니다."
    return "대상 서버 오류로 페이지를 확인할 수 없습니다."


def _message_for_error(error: str) -> str:
    if error == "dns_failure":
        return "도메인 주소를 확인할 수 없습니다."
    if error == "timeout":
        return "페이지 응답 시간이 초과되었습니다."
    if error in {"connect_error"} or error.startswith("connection_refused"):
        return "페이지에 연결할 수 없습니다."
    if error in {"blocked_host", "invalid_host"}:
        return "내부망 또는 차단된 호스트라 분석하지 않았습니다."
    if error.startswith("server_error_"):
        return "대상 서버 오류로 페이지를 확인할 수 없습니다."
    if error.startswith("http_error_"):
        return "페이지를 가져오지 못했습니다."
    return "페이지를 확인할 수 없습니다."


def _status_from_error(error: str) -> int | None:
    for prefix in ("server_error_", "http_error_"):
        if error.startswith(prefix):
            raw = error.removeprefix(prefix)
            if raw.isdigit():
                return int(raw)
    return None


def unchain_page_unavailable(unchain: UnchainResult) -> tuple[str, int | None] | None:
    """Return user message/status when unchain already proved the page is unavailable."""
    for hop in reversed(unchain.hops):
        if hop.status_code >= 400:
            return _message_for_status(hop.status_code), hop.status_code

    error = unchain.error
    if error is None:
        return None
    if error in _UNAVAILABLE_ERRORS or error.startswith(
        ("connection_refused", "server_error_", "http_error_")
    ):
        status_code = _status_from_error(error)
        message = _message_for_status(status_code) if status_code else _message_for_error(error)
        return message, status_code
    return None


def content_page_unavailable(content: ContentAnalysisResult) -> tuple[str, int | None] | None:
    """Return user message/status when content fetch could not reach an analyzable page."""
    if content.fetched:
        return None
    error = content.error
    if error is None:
        return None
    if error in _UNAVAILABLE_ERRORS or error.startswith("http_error_"):
        status_code = content.status_code or _status_from_error(error)
        message = content.reason or (
            _message_for_status(status_code) if status_code else _message_for_error(error)
        )
        return message, status_code
    return None
