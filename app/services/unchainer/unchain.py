"""URL 언체이닝 — 파이프라인 2단계.

정규화된 URL의 리다이렉트 체인을 끝까지 추적해서
최종 목적지 URL과 경로상 의심 신호를 수집함.
"""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import settings
from app.schemas.analysis import HopRecord, UnchainResult

# 리다이렉트로 간주할 상태 코드
_REDIRECT_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})

# 리다이렉트 대상으로 허용하는 스킴 (javascript:, data: 등 차단)
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})


async def unchain_url(url: str) -> UnchainResult:
    """리다이렉트 체인을 추적하고 최종 URL·hop 기록·의심 신호를 반환."""
    try:
        return await asyncio.wait_for(
            _unchain_url_inner(url),
            timeout=settings.unchain_chain_timeout_seconds,
        )
    except asyncio.TimeoutError:
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
            # 무한 루프 감지
            if current_url in visited:
                signals.append("redirect_loop")
                break
            visited.add(current_url)

            hop, next_url, hop_error = await _follow_one_hop(
                client, current_url, headers, signals,
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
            resp = await client.request(method, url, headers=headers)
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
                url=url, status_code=resp.status_code, method=method,
            )
            return hop, None, f"server_error_{resp.status_code}"

        # 리다이렉트 처리
        if resp.status_code in _REDIRECT_CODES:
            raw_location = resp.headers.get("location")
            if not raw_location:
                hop = HopRecord(
                    url=url, status_code=resp.status_code, method=method,
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
            url=url, status_code=resp.status_code, method=method,
        )
        return hop, None, None

    # 여기 도달 불가하지만 타입 안전
    return None, None, "unexpected_fallthrough"  # pragma: no cover
