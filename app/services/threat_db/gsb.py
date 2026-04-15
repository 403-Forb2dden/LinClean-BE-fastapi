"""Google Safe Browsing Lookup API 클라이언트.

실패(타임아웃/인증/레이트리밋/서버 에러)는 모두 raise 하지 않고
`GSBResult(checked=False, error=...)` 로 반환해 상위 파이프라인을 보호한다.
"""

from __future__ import annotations

import httpx

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.analysis import GSBMatch, GSBResult

logger = get_logger(__name__)

_LOGGED_MISSING_KEY = False


def _log_missing_key_once() -> None:
    # API 키 미설정은 정상 경로이므로 로그 스팸 방지차 1회만 경고.
    global _LOGGED_MISSING_KEY
    if not _LOGGED_MISSING_KEY:
        logger.warning("gsb.api_key_not_configured")
        _LOGGED_MISSING_KEY = True


def _build_request_body(url: str) -> dict:
    return {
        "client": {
            "clientId": settings.gsb_client_id,
            "clientVersion": settings.gsb_client_version,
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }


async def check_gsb(url: str) -> GSBResult:
    """GSB Lookup API 호출 결과를 GSBResult 로 반환."""
    if not settings.gsb_api_key:
        _log_missing_key_once()
        return GSBResult(checked=False, is_threat=False, error="not_configured")

    params = {"key": settings.gsb_api_key}
    body = _build_request_body(url)

    try:
        async with httpx.AsyncClient(timeout=settings.gsb_timeout_seconds) as client:
            resp = await client.post(settings.gsb_api_url, params=params, json=body)
    except httpx.TimeoutException:
        return GSBResult(checked=False, is_threat=False, error="timeout")
    except httpx.HTTPError:
        return GSBResult(checked=False, is_threat=False, error="http_error")

    status = resp.status_code
    if status in (400, 401, 403):
        return GSBResult(checked=False, is_threat=False, error="auth_error")
    if status == 429:
        return GSBResult(checked=False, is_threat=False, error="rate_limited")
    if 500 <= status < 600:
        return GSBResult(checked=False, is_threat=False, error=f"server_error_{status}")
    if status != 200:
        return GSBResult(checked=False, is_threat=False, error=f"http_error_{status}")

    try:
        data = resp.json()
    except ValueError:
        return GSBResult(checked=False, is_threat=False, error="invalid_response")

    raw_matches = data.get("matches") or []
    matches = [
        GSBMatch(
            threat_type=m.get("threatType", "UNKNOWN"),
            platform_type=m.get("platformType"),
            cache_duration=m.get("cacheDuration"),
        )
        for m in raw_matches
    ]
    return GSBResult(
        checked=True,
        is_threat=bool(matches),
        matches=matches,
        error=None,
    )
