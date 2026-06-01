from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

import httpx
from cachetools import TTLCache

from app.core.config import settings
from app.core.logging import get_logger
from app.core.tld import extract_url_parts
from app.schemas.domain_heuristic import RdapInfo

logger = get_logger(__name__)

# domain → RdapInfo | None. TTL 만료 + LRU eviction 모두 cachetools 가 관리.
# 24h TTL 동안 무작위 도메인 트래픽으로 dict 가 무한 성장하던 종전 동작을 maxsize 로 천장 박음.
# TTLCache 는 thread-safe 가 아니지만 단일 이벤트 루프에서 동기 접근만 하므로 안전.
_cache: TTLCache[str, RdapInfo | None] = TTLCache(
    maxsize=settings.rdap_cache_max_entries,
    ttl=settings.rdap_cache_ttl_seconds,
)

# 동시 요청 합치기용 — 같은 도메인 요청이 겹치면 하나의 Future만 실제로 fetch
_inflight: dict[str, asyncio.Future[tuple[RdapInfo | None, str | None]]] = {}

# 커넥션/TLS 재사용을 위해 모듈 레벨에서 싱글턴 사용
_client: httpx.AsyncClient | None = None
_rate_limit_until: float | None = None
_DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS = 30.0
_MAX_RATE_LIMIT_COOLDOWN_SECONDS = 120.0


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


def _retry_after_seconds(value: str | None) -> float:
    if not value:
        return _DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS

    try:
        seconds = float(value)
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return _DEFAULT_RATE_LIMIT_COOLDOWN_SECONDS
        if retry_at.tzinfo is None:
            retry_at = retry_at.replace(tzinfo=UTC)
        seconds = (retry_at.astimezone(UTC) - datetime.now(tz=UTC)).total_seconds()

    return min(max(seconds, 0.0), _MAX_RATE_LIMIT_COOLDOWN_SECONDS)


def _remember_rate_limit(domain: str, retry_after: str | None) -> None:
    global _rate_limit_until
    cooldown_seconds = _retry_after_seconds(retry_after)
    _rate_limit_until = time.monotonic() + cooldown_seconds
    logger.warning(
        "rdap.rate_limited",
        domain=domain,
        retry_after=retry_after,
        cooldown_seconds=cooldown_seconds,
    )


def _rate_limited_now() -> bool:
    return _rate_limit_until is not None and time.monotonic() < _rate_limit_until


def _rate_limit_remaining_seconds() -> float:
    if _rate_limit_until is None:
        return 0.0
    return round(max(_rate_limit_until - time.monotonic(), 0.0), 3)


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
        if exc.response.status_code == 429:
            _remember_rate_limit(domain, exc.response.headers.get("retry-after"))
            return None, "rate_limited"
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

    _cache[domain] = result
    return result, None


async def lookup_rdap(url: str) -> tuple[RdapInfo | None, str | None]:
    """(RdapInfo | None, error_code | None) 반환. 에러 시 파이프라인 중단하지 않음."""
    ext = extract_url_parts(url)
    domain = ext.top_domain_under_public_suffix
    if not domain:
        return None, "no_domain"

    if _rate_limited_now():
        logger.info(
            "rdap.rate_limit_cooldown_active",
            domain=domain,
            remaining_seconds=_rate_limit_remaining_seconds(),
        )
        return None, "rate_limited"

    # TTLCache 가 만료된 엔트리는 자동으로 KeyError 처리 — 명시적 만료 체크 불필요.
    try:
        return _cache[domain], None
    except KeyError:
        pass

    # 같은 도메인 in-flight 요청이 있으면 결과 공유 — RDAP 서버 부하 방지
    existing = _inflight.get(domain)
    if existing is not None:
        return await existing

    loop = asyncio.get_running_loop()
    fut: asyncio.Future[tuple[RdapInfo | None, str | None]] = loop.create_future()
    _inflight[domain] = fut
    try:
        result = await _fetch_rdap(domain)
        if not fut.done():
            fut.set_result(result)
        return result
    except BaseException as exc:
        if not fut.done():
            fut.set_exception(exc)
            # If the owner task is cancelled before another waiter consumes this future,
            # retrieve the exception to avoid noisy "Future exception was never retrieved".
            fut.add_done_callback(lambda done: done.exception())
        raise
    finally:
        _inflight.pop(domain, None)
