"""호스트네임 → getaddrinfo 결과 짧은 TTL 캐시.

fetch / unchain 양쪽이 같은 호스트를 반복 해석하던 비용을 제거한다. TTL 은 30초로 짧게
잡아 캐시 hit 동안 공격자가 DNS 를 사설 대역으로 재해석하는 윈도우를 줄였다.
완전한 DNS rebind 방어는 호출 단(fetch / unchain) 의 IP 검증 + 배포 단의 egress 방화벽
조합이 본선이며, 이 캐시는 어디까지나 성능 보강이다.

캐시 키는 hostname 만이다 — port/service 는 getaddrinfo 의 IP 결과에 영향을 주지 않으므로
호출 측에서 별도 처리하면 된다(sockaddr 의 port 필드는 service 인자로만 채워진다).

실패(getaddrinfo 예외) 는 캐시하지 않는다. DNS 일시 장애가 TTL 동안 모든 후속 요청을
막아버리는 동작을 피한다.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Any, cast

from cachetools import TTLCache  # type: ignore[import-untyped]

from app.core.config import settings

# (family, type, proto, canonname, sockaddr) 튜플의 순서를 그대로 보존.
# socket.getaddrinfo 의 반환 형식과 동일.
AddrInfoTuple = tuple[int, int, int, str, tuple[Any, ...]]

_cache: TTLCache[str, tuple[AddrInfoTuple, ...]] = TTLCache(
    maxsize=settings.dns_cache_max_entries,
    ttl=settings.dns_cache_ttl_seconds,
)


async def resolve_host_addrs(hostname: str) -> tuple[AddrInfoTuple, ...]:
    """hostname 의 getaddrinfo 결과를 캐시. 실패 시 OSError 그대로 raise."""
    try:
        return cast(tuple[AddrInfoTuple, ...], _cache[hostname])
    except KeyError:
        pass

    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    result = cast(tuple[AddrInfoTuple, ...], tuple(infos))
    _cache[hostname] = result
    return result


def clear_cache() -> None:
    """테스트에서 호출. 운영에서는 직접 부르지 않는다."""
    _cache.clear()
