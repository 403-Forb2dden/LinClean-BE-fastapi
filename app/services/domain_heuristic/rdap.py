from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import httpx
import tldextract

from app.core.config import settings
from app.core.logging import get_logger
from app.schemas.domain_heuristic import RdapInfo

logger = get_logger(__name__)

# domain → (RdapInfo | None, expire_at: monotonic timestamp)
_cache: dict[str, tuple[RdapInfo | None, float]] = {}

# 동시 요청 합치기용 — 같은 도메인 요청이 겹치면 하나의 Future만 실제로 fetch
_inflight: dict[str, asyncio.Future[tuple[RdapInfo | None, str | None]]] = {}

# 커넥션/TLS 재사용을 위해 모듈 레벨에서 싱글턴 사용
_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        # RFC 7480 SHOULD: authoritative RDAP 서버로 redirect될 때 일부 구현은
        # Accept 없으면 406 또는 HTML을 반환 → 기본 헤더로 명시
        _client = httpx.AsyncClient(
            timeout=settings.rdap_timeout_seconds,
            headers={"Accept": "application/rdap+json"},
        )
    return _client


async def aclose_client() -> None:
    """앱 셧다운 훅에서 호출. 테스트에서 client 상태 초기화에도 사용."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _extract_registrar(data: dict) -> str | None:  # type: ignore[type-arg]
    for entity in data.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            if isinstance(vcard, list) and len(vcard) > 1:
                for entry in vcard[1]:
                    if isinstance(entry, list) and entry and entry[0] == "fn":
                        return str(entry[3])
    return None


def _parse_datetime(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        # Python 3.11+의 fromisoformat은 Z suffix를 직접 파싱
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt
    except ValueError:
        return None


def _parse_rdap_response(domain: str, data: dict) -> RdapInfo:  # type: ignore[type-arg]
    events = {e["eventAction"]: e.get("eventDate") for e in data.get("events", [])}
    created_date = _parse_datetime(events.get("registration"))
    expiry_date = _parse_datetime(events.get("expiration"))

    now = datetime.now(tz=UTC)
    domain_age_days: int | None = None
    is_new_domain = False
    if created_date:
        domain_age_days = (now - created_date).days
        is_new_domain = domain_age_days < settings.rdap_new_domain_threshold_days

    return RdapInfo(
        domain=domain,
        registrar=_extract_registrar(data),
        created_date=created_date,
        expiry_date=expiry_date,
        domain_age_days=domain_age_days,
        is_new_domain=is_new_domain,
    )


def _encode_for_url(domain: str) -> str | None:
    """IDN 도메인을 punycode로 변환. ASCII 도메인은 그대로 통과."""
    try:
        return domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None


async def _fetch_rdap(domain: str) -> tuple[RdapInfo | None, str | None]:
    encoded = _encode_for_url(domain)
    if encoded is None:
        return None, "invalid_domain"

    rdap_url = f"{settings.rdap_bootstrap_url}{encoded}"
    try:
        client = _get_client()
        resp = await client.get(rdap_url, follow_redirects=True)
        resp.raise_for_status()
        data = resp.json()
    except httpx.TimeoutException:
        return None, "timeout"
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return None, "not_found"
        return None, "http_error"
    except Exception as exc:
        logger.warning(
            "rdap.unexpected_error",
            domain=domain,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return None, "unexpected"

    try:
        result = _parse_rdap_response(domain, data)
    except Exception as exc:
        logger.warning(
            "rdap.parse_error",
            domain=domain,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return None, "parse_error"

    _cache[domain] = (result, time.monotonic() + settings.rdap_cache_ttl_seconds)
    return result, None


async def lookup_rdap(url: str) -> tuple[RdapInfo | None, str | None]:
    """(RdapInfo | None, error_code | None) 반환. 에러 시 파이프라인 중단하지 않음."""
    ext = tldextract.extract(url)
    domain = ext.top_domain_under_public_suffix
    if not domain:
        return None, "no_domain"

    now = time.monotonic()
    cached = _cache.get(domain)
    if cached is not None:
        info, expire_at = cached
        if now < expire_at:
            return info, None
        # 만료 엔트리는 즉시 제거 — 무작위 도메인 트래픽으로 dict 무한 성장 방지
        _cache.pop(domain, None)

    # 같은 도메인 in-flight 요청이 있으면 결과 공유 — RDAP 서버 부하 방지
    existing = _inflight.get(domain)
    if existing is not None:
        return await existing

    loop = asyncio.get_running_loop()
    fut: asyncio.Future[tuple[RdapInfo | None, str | None]] = loop.create_future()
    _inflight[domain] = fut
    try:
        result = await _fetch_rdap(domain)
        fut.set_result(result)
        return result
    except BaseException as exc:
        fut.set_exception(exc)
        raise
    finally:
        _inflight.pop(domain, None)
