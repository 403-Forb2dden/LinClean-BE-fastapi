"""최종 URL의 HTML 본문을 취득한다.

정적 분석 파이프라인 특성상 리다이렉트는 이미 2단계에서 해소됐다고 가정하고
follow_redirects=False 로 굳힌다. 3xx 를 되받으면 unchainer 가 놓친 케이스이므로
에러로 처리해 후속 단계에서 파이프라인 정합성을 따질 수 있게 한다.

httpx.AsyncClient 는 모듈 레벨 싱글턴으로 재사용한다 — 매 요청마다 TCP/TLS 핸드셰이크를
새로 여는 비용을 피하기 위함. lifespan 에서 aclose_client() 로 명시 종료한다.

SSRF 방어 — 호스트가 IP 리터럴이면 사설/loopback/link-local 등이 아닌지 검사하고,
잘 알려진 내부 호스트네임(localhost, 클라우드 메타데이터 서비스)은 차단한다.
호스트네임은 추가로 실제 DNS 해석한 결과 IP 들도 동일 룰로 검증한다 — `evil.com → 127.0.0.1`
처럼 lexical 검사를 통과하는 케이스 차단. 단, getaddrinfo 시점과 connect 시점 사이의
재해석(완전한 DNS rebind)은 본 1선에서 막지 못하므로 운영 환경에서는 egress 방화벽
또는 분석 전용 프록시로 잔여 위험을 차단해야 한다.
"""

from __future__ import annotations

import ipaddress
import random
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx

from app.core.config import settings
from app.core.dns_cache import resolve_host_addrs
from app.core.logging import get_logger

logger = get_logger(__name__)

# 분석 대상이 HTML이 아닌 바이너리(PNG, PDF, ZIP 등)면 정적 분석 자체가 의미 없으므로 조기 컷.
# application/xhtml+xml 은 의도적으로 제외 — BS4+lxml HTML 파서를 그대로 쓰지만, XHTML/XML
# 경로는 외부 DTD/엔티티 해석 가능성이 (lxml 버전·옵션에 따라) 회색지대라 입력에서 잘라낸다.
# 정상 트래픽 영향은 거의 없다 — 대부분의 사이트는 text/html 로 응답하고, XHTML 만 응답하는
# 사이트는 분석 누락으로 두는 트레이드오프.
_HTML_CT_KEYWORDS: tuple[str, ...] = ("text/html",)

# SSRF 방어 — 사용자가 정상 도메인을 위장해 보내도 호스트네임 자체가 내부 자원을 가리키면 차단.
# 클라우드 메타데이터 엔드포인트는 IP 가 169.254.169.254 라 IP 검사로도 대부분 잡히지만,
# DNS alias 만 노출된 케이스 대비 호스트네임도 함께 거부한다 (GCE/AWS/Alibaba 모두 커버).
_BLOCKED_HOSTNAMES: frozenset[str] = frozenset(
    {
        "localhost",
        "ip6-localhost",
        "ip6-loopback",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "instance-data.ec2.internal",
    }
)


@dataclass
class FetchResult:
    ok: bool
    url: str
    status_code: int | None = None
    html: str = ""
    error: str | None = None


# 모듈 레벨 싱글턴 — RDAP client 와 동일 패턴. 첫 요청 때 lazy init, lifespan 에서 aclose.
_client: httpx.AsyncClient | None = None


def _build_client() -> httpx.AsyncClient:
    timeout = httpx.Timeout(
        settings.content_fetch_timeout_seconds,
        connect=settings.content_fetch_connect_timeout_seconds,
    )
    if settings.content_fetch_proxy_url:
        return httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            verify=True,
            cookies=None,
            trust_env=False,
            proxy=settings.content_fetch_proxy_url,
        )
    return httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        verify=True,
        cookies=None,
        trust_env=False,
    )


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = _build_client()
    return _client


async def aclose_client() -> None:
    """앱 셧다운 훅에서 호출. 테스트에서도 client 상태 초기화에 쓴다."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


def _pick_user_agent() -> str:
    pool = settings.content_user_agents
    # 풀이 비면 misconfiguration 이라 침묵 폴백 대신 raise — 매번 같은 UA 노출되는
    # 봇 탐지 회피 의도를 운영자가 알지 못한 채 흘려보내지 않게 한다.
    if not pool:
        raise RuntimeError("content_user_agents pool is empty — set CONTENT_USER_AGENTS")
    # UA 로테이션은 보안 속성이 아니라 봇 탐지 회피 — random 으로 충분하다.
    return random.choice(pool)  # noqa: S311


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _is_blocked_ip_literal(host: str) -> bool:
    """호스트가 IP 리터럴이고 사설/loopback/link-local 등이면 True. IP 아니면 False."""
    try:
        ip_obj = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def _is_blocked_host(host: str | None) -> bool:
    if not host:
        return True
    # urlparse().hostname 은 이미 IPv6 brackets 를 벗기지만, 다른 경로로 들어온 호스트
    # (테스트·내부 헬퍼)도 동일 룰을 통과시키도록 strip("[]") 를 한 번 더 둔다.
    h = host.strip("[]").lower()
    if h in _BLOCKED_HOSTNAMES:
        return True
    return _is_blocked_ip_literal(h)


async def _resolved_addrs_blocked(hostname: str) -> bool:
    """hostname 의 모든 A/AAAA 응답을 _is_blocked_ip_literal 로 검증.

    하나라도 사설/loopback 범위면 True. 해석 결과는 dns_cache 의 짧은 TTL 캐시로 재사용 —
    같은 호스트 반복 트래픽에서 매번 DNS 비용이 들어가지 않게 한다.
    완전한 DNS rebind(검증 후 connect 시점에 다른 IP 로 재해석) 는 본 1선에서 막을 수 없다 —
    배포 단의 egress 방화벽으로 보강해야 한다.
    """
    infos = await resolve_host_addrs(hostname)
    seen: set[str] = set()
    for family, _type, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        addr = sockaddr[0]
        if not isinstance(addr, str):
            continue
        # %zone 같은 IPv6 scope id 가 붙어 들어오면 제거 — ip_address() 가 거부한다.
        # zone 이 다른 동일 IP 도 같은 정책을 적용하면 되므로 dedup 키에서 zone 은 의도적으로 뺀다.
        # link-local(fe80::*) 은 zone 유무와 무관하게 _is_link_local 로 잡혀 차단된다.
        ip = addr.split("%", 1)[0]
        if ip in seen:
            continue
        seen.add(ip)
        if _is_blocked_ip_literal(ip):
            return True
    return False


def _is_html_content_type(headers: httpx.Headers) -> bool:
    ct = headers.get("content-type", "").lower()
    return any(kw in ct for kw in _HTML_CT_KEYWORDS)


def _content_length_over_cap(headers: httpx.Headers, max_bytes: int) -> bool:
    raw = headers.get("content-length")
    if raw is None:
        return False
    try:
        return int(raw) > max_bytes
    except ValueError:
        return False


async def _read_capped(resp: httpx.Response, max_bytes: int) -> tuple[bytes, bool]:
    """응답 본문을 max_bytes 까지만 수집. 초과 시 (부분 본문, True) 반환."""
    buf = bytearray()
    async for chunk in resp.aiter_bytes():
        if len(buf) + len(chunk) > max_bytes:
            return bytes(buf), True
        buf.extend(chunk)
    return bytes(buf), False


def _decode(body: bytes, resp: httpx.Response) -> str:
    encoding = resp.charset_encoding or "utf-8"
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        # 서버가 이상한 encoding 을 선언했을 때의 안전망
        return body.decode("utf-8", errors="replace")


async def fetch_page(url: str) -> FetchResult:
    """단일 GET 요청으로 HTML 본문 취득. 실패해도 raise 하지 않고 FetchResult 로 반환."""
    # SSRF 1선 방어 — 내부망 IP/호스트로 떨어지는 요청을 connect 전에 차단.
    parsed = urlparse(url)
    if _is_blocked_host(parsed.hostname):
        logger.info("content_fetch.blocked_host", url=url, host=parsed.hostname)
        return FetchResult(ok=False, url=url, error="blocked_host")

    # SSRF 2선 — 호스트네임이 공인 도메인처럼 보여도 실제로 사설 IP 로 풀릴 수 있다
    # (ex. `evil.com → 127.0.0.1`). 사전 DNS 해석 후 모든 응답 IP 를 동일 룰로 검증.
    # IP 리터럴은 1선에서 이미 검증돼 통과된 것 — 같은 IP 를 다시 풀 필요 없다.
    if parsed.hostname and not _is_ip_literal(parsed.hostname.strip("[]")):
        try:
            blocked = await _resolved_addrs_blocked(parsed.hostname)
        except OSError:
            # 해석 실패는 connect 단계 ConnectError 로 떨어지게 그대로 둔다 —
            # 여기서 별도 코드 만들지 않는다.
            blocked = False
        if blocked:
            logger.info("content_fetch.blocked_resolved_ip", url=url, host=parsed.hostname)
            return FetchResult(ok=False, url=url, error="blocked_host")

    headers = {
        "User-Agent": _pick_user_agent(),
        # XHTML/XML 응답은 이후 _is_html_content_type 에서 거절되므로 Accept 에서도 빼둔다.
        "Accept": "text/html,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    }
    max_bytes = settings.content_fetch_max_bytes

    try:
        client = _get_client()
        req = client.build_request("GET", url, headers=headers)
        resp = await client.send(req, stream=True)
        try:
            # 3xx 는 unchainer 가 이미 해소했어야 하는 신호 — 여기서는 예외로 취급
            if 300 <= resp.status_code < 400:
                return FetchResult(
                    ok=False,
                    url=url,
                    status_code=resp.status_code,
                    error="unexpected_redirect",
                )

            if resp.status_code >= 400:
                return FetchResult(
                    ok=False,
                    url=url,
                    status_code=resp.status_code,
                    error=f"http_error_{resp.status_code}",
                )

            if not _is_html_content_type(resp.headers):
                return FetchResult(
                    ok=False,
                    url=url,
                    status_code=resp.status_code,
                    error="not_html",
                )

            if _content_length_over_cap(resp.headers, max_bytes):
                return FetchResult(
                    ok=False,
                    url=url,
                    status_code=resp.status_code,
                    error="too_large",
                )

            body, over = await _read_capped(resp, max_bytes)
            if over:
                return FetchResult(
                    ok=False,
                    url=url,
                    status_code=resp.status_code,
                    error="too_large",
                )

            html = _decode(body, resp)
            return FetchResult(ok=True, url=url, status_code=resp.status_code, html=html)
        finally:
            await resp.aclose()
    except httpx.TimeoutException:
        return FetchResult(ok=False, url=url, error="timeout")
    except httpx.ConnectError:
        return FetchResult(ok=False, url=url, error="connect_error")
    except httpx.HTTPError as exc:
        logger.warning("content_fetch.http_error", url=url, error=str(exc))
        return FetchResult(ok=False, url=url, error="http_error")
    except Exception as exc:
        logger.warning(
            "content_fetch.unexpected",
            url=url,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return FetchResult(ok=False, url=url, error="unexpected")
