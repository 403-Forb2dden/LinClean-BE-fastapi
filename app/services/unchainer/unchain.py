"""URL 언체이닝 — 파이프라인 2단계.

정규화된 URL의 리다이렉트 체인을 끝까지 추적해서
최종 목적지 URL과 경로상 의심 신호를 수집함.
"""

from __future__ import annotations

import ssl
from socket import gaierror
from urllib.parse import urljoin, urlparse

import httpx

from app.core.config import settings
from app.schemas.analysis import HopRecord, UnchainResult

# 리다이렉트로 간주할 상태 코드
_REDIRECT_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})


async def unchain_url(url: str) -> UnchainResult:
    """리다이렉트 체인을 추적하고 최종 URL·hop 기록·의심 신호를 반환."""
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
            connect=settings.unchain_per_hop_timeout_seconds,
        ),
        follow_redirects=False,
        verify=True,
        # 쿠키·인증 비전송
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

    HEAD 우선 → 실패 시 GET 폴백.
    """
    for method in ("HEAD", "GET"):
        try:
            resp = await client.request(method, url, headers=headers)
        except httpx.TimeoutException:
            return None, None, "timeout"
        except gaierror:
            return None, None, "dns_failure"
        except ssl.SSLError as e:
            return None, None, f"tls_error: {e}"
        except httpx.ConnectError as e:
            # DNS 실패가 ConnectError 안에 래핑되는 경우도 처리
            cause = str(e).lower()
            if "name or service not known" in cause or "getaddrinfo" in cause:
                return None, None, "dns_failure"
            return None, None, f"connection_refused: {e}"
        except httpx.HTTPError as e:
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
            location = resp.headers.get("location")
            if not location:
                hop = HopRecord(
                    url=url, status_code=resp.status_code, method=method,
                )
                return hop, None, "missing_location_header"

            # 상대 경로 Location 해석
            next_url = urljoin(url, location)

            hop = HopRecord(
                url=url,
                status_code=resp.status_code,
                location=next_url,
                method=method,
            )

            # 스킴 다운그레이드 감지 (https → http)
            if urlparse(url).scheme == "https" and urlparse(next_url).scheme == "http":
                signals.append("scheme_downgrade")

            # 크로스 오리진 호스트 변화
            prev_host = urlparse(url).hostname
            next_host = urlparse(next_url).hostname
            if prev_host != next_host:
                signals.append(f"cross_origin:{prev_host}->{next_host}")

            return hop, next_url, None

        # 리다이렉트 아닌 정상 응답 → 체인 종료
        hop = HopRecord(
            url=url, status_code=resp.status_code, method=method,
        )
        return hop, None, None

    # 여기 도달 불가하지만 타입 안전
    return None, None, "unexpected_fallthrough"  # pragma: no cover
