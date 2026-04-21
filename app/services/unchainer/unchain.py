"""URL 언체이닝 — 파이프라인 2단계.

정규화된 URL의 리다이렉트 체인을 끝까지 추적해서
최종 목적지 URL과 경로상 의심 신호를 수집함.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import settings
from app.schemas.analysis import HopRecord, UnchainResult

_REDIRECT_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

# 리다이렉트 대상으로 허용하는 스킴 (javascript:, data: 등 차단)
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


def _is_private_ip(ip_str: str) -> bool:
    """외부 접근 불가(is_global=False)인 IP인지 확인.

    is_reserved는 NAT64(64:ff9b::/96) 같은 공개 도달 가능 대역까지 잡아서
    오탐이 발생하므로, is_global 기반으로 판단.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # 파싱 실패 시 안전하게 차단
    return not addr.is_global


async def _check_host_safety(url: str) -> str | None:
    """호스트를 DNS 조회 후 내부 IP이면 에러 사유 반환, 안전하면 None."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return "invalid_host"

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    loop = asyncio.get_running_loop()

    try:
        addrinfo = await loop.getaddrinfo(
            hostname,
            port,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return "dns_failure"

    for _, _, _, _, sockaddr in addrinfo:
        if _is_private_ip(sockaddr[0]):
            return "ssrf_blocked"

    return None


async def unchain_url(url: str) -> UnchainResult:
    """리다이렉트 체인을 추적하고 최종 URL·hop 기록·의심 신호를 반환."""
    try:
        return await asyncio.wait_for(
            _unchain_url_inner(url),
            timeout=settings.unchain_chain_timeout_seconds,
        )
    except TimeoutError:
        return UnchainResult(
            input_url=url,
            final_url=url,
            hops=[],
            hop_count=0,
            timed_out=True,
            error="chain_timeout",
            signals=[],
        )


async def _unchain_url_inner(url: str) -> UnchainResult:
    """실제 체인 추적 로직. unchain_url에서 총 timeout으로 감싸서 호출."""
    hops: list[HopRecord] = []
    signals: list[str] = []
    visited: set[str] = set()
    current_url = url
    error: str | None = None
    timed_out = False

    headers = {
        "User-Agent": settings.unchain_user_agent,
        "Accept": "*/*",
        "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    }

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(
            settings.unchain_timeout_seconds,
            connect=settings.unchain_connect_timeout_seconds,
        ),
        follow_redirects=False,
        verify=True,
        cookies=None,
    ) as client:
        for _ in range(settings.unchain_max_hops):
            if current_url in visited:
                signals.append("redirect_loop")
                break
            visited.add(current_url)

            # SSRF·DNS Rebinding 방어: 매 hop마다 목적지 IP 검증
            safety_error = await _check_host_safety(current_url)
            if safety_error is not None:
                error = safety_error
                if safety_error == "ssrf_blocked":
                    signals.append("ssrf_blocked")
                break

            hop, next_url, hop_error = await _follow_one_hop(
                client,
                current_url,
                headers,
                signals,
            )

            if hop is not None:
                hops.append(hop)

            if hop_error is not None:
                error = hop_error
                if hop_error == "timeout":
                    timed_out = True
                break

            # 리다이렉트가 아니면 체인 종료
            if next_url is None:
                break

            current_url = next_url
        else:
            # max_hops 도달
            signals.append("max_hops_reached")

    return UnchainResult(
        input_url=url,
        final_url=current_url,
        hops=hops,
        hop_count=len(hops),
        timed_out=timed_out,
        error=error,
        signals=signals,
    )


async def _follow_one_hop(
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    signals: list[str],
) -> tuple[HopRecord | None, str | None, str | None]:
    """단일 hop 요청. (hop_record, next_url_or_None, error_or_None) 반환.

    HEAD 우선 → 실패 시(상태 코드·네트워크 에러 모두) GET 폴백.
    """
    for method in ("HEAD", "GET"):
        try:
            # 헤더만 필요하므로 스트리밍으로 열고 본문은 즉시 닫음
            req = client.build_request(method, url, headers=headers)
            resp = await client.send(req, stream=True)
            await resp.aclose()
        except httpx.TimeoutException:
            if method == "HEAD":
                continue
            return None, None, "timeout"
        except httpx.ConnectError as e:
            if method == "HEAD":
                continue
            cause = str(e).lower()
            if "name or service not known" in cause or "getaddrinfo" in cause:
                return None, None, "dns_failure"
            return None, None, f"connection_refused: {e}"
        except httpx.HTTPError as e:
            if method == "HEAD":
                continue
            return None, None, f"http_error: {e}"

        # HEAD에서 405 등 클라이언트 에러면 GET 폴백
        if method == "HEAD" and resp.status_code in {405, 403, 400}:
            continue

        # 5xx 서버 에러 → 체인 중단
        if resp.status_code >= 500:
            hop = HopRecord(
                url=url,
                status_code=resp.status_code,
                method=method,
            )
            return hop, None, f"server_error_{resp.status_code}"

        if resp.status_code in _REDIRECT_CODES:
            raw_location = resp.headers.get("location")
            if not raw_location:
                # 일부 서버는 HEAD 응답에서 Location을 생략하므로 GET으로 재시도
                if method == "HEAD":
                    continue
                hop = HopRecord(
                    url=url,
                    status_code=resp.status_code,
                    method=method,
                )
                return hop, None, "missing_location_header"

            next_url = urljoin(url, raw_location)
            parsed_next = urlparse(next_url)

            # 허용되지 않는 스킴 방어 (javascript:, data: 등)
            if parsed_next.scheme not in _ALLOWED_SCHEMES:
                hop = HopRecord(
                    url=url,
                    status_code=resp.status_code,
                    raw_location=raw_location,
                    location=next_url,
                    method=method,
                )
                signals.append(f"unsafe_scheme:{parsed_next.scheme}")
                return hop, None, f"unsafe_redirect_scheme:{parsed_next.scheme}"

            parsed_url = urlparse(url)

            hop = HopRecord(
                url=url,
                status_code=resp.status_code,
                raw_location=raw_location,
                location=next_url,
                method=method,
            )

            # 스킴 다운그레이드 감지 (https → http)
            if parsed_url.scheme == "https" and parsed_next.scheme == "http":
                signals.append("scheme_downgrade")

            # 크로스 오리진 호스트 변화
            if parsed_url.hostname != parsed_next.hostname:
                signals.append(f"cross_origin:{parsed_url.hostname}->{parsed_next.hostname}")

            return hop, next_url, None

        # 리다이렉트 아닌 정상 응답 → 체인 종료
        hop = HopRecord(
            url=url,
            status_code=resp.status_code,
            method=method,
        )
        return hop, None, None

    # 여기 도달 불가하지만 타입 안전
    return None, None, "unexpected_fallthrough"  # pragma: no cover
