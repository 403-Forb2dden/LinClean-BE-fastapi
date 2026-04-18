"""URL 언체이닝 데모.

사용법:
    python -m tests.demo.demo_unchain
"""

from __future__ import annotations

import asyncio

from app.services.unchainer import unchain_url

DIVIDER = "-" * 72

# 실제 리다이렉트가 일어나는 공개 URL들 (데모 시점에 동작 보장 불가)
CASES: list[tuple[str, str]] = [
    # --- 기본 동작 ---
    ("리다이렉트 없음 (200 OK)", "https://www.google.com/"),
    ("HTTP→HTTPS 영구 이동 (301)", "http://github.com/"),
    ("단축 URL (bit.ly → 실제 목적지)", "https://bit.ly/4tGFJkf"),
    # --- 301 vs 302 차이 ---
    (
        "301 Permanent: 주소가 영구적으로 바뀜",
        "https://httpbin.org/redirect-to?url=https://httpbin.org/get&status_code=301",
    ),
    (
        "302 Found: 임시로 다른 곳으로 보냄",
        "https://httpbin.org/redirect-to?url=https://httpbin.org/get&status_code=302",
    ),
    # --- 다중 hop·경로 해석 ---
    ("다중 hop 체인 (3회 리다이렉트)", "https://httpbin.org/redirect/3"),
    ("상대 경로 Location 해석", "https://httpbin.org/relative-redirect/2"),
    # --- 의심 신호 탐지 ---
    (
        "스킴 다운그레이드 (HTTPS→HTTP)",
        "https://httpbin.org/redirect-to?url=http://httpbin.org/get&status_code=302",
    ),
    (
        "크로스 오리진 (호스트 변경)",
        "https://httpbin.org/redirect-to?url=https://www.google.com&status_code=302",
    ),
    # --- 에러 ---
    ("존재하지 않는 도메인 (DNS 실패)", "https://this-domain-does-not-exist-12345.com/"),
]


async def main() -> None:
    print()
    print("=" * 72)
    print("  LinClean -- URL Unchaining Demo")
    print("=" * 72)

    for i, (desc, url) in enumerate(CASES, 1):
        print(f"\n  [{i:02d}] {desc}")
        print(f"       input : {url}")

        result = await unchain_url(url)

        print(f"       final : {result.final_url}")
        print(f"       hops  : {result.hop_count}")

        for j, hop in enumerate(result.hops):
            loc = f" -> {hop.location}" if hop.location else ""
            print(f"         [{j}] {hop.method} {hop.status_code}{loc}")

        if result.signals:
            print(f"       signals: {result.signals}")
        if result.error:
            print(f"       error  : {result.error}")
        if result.timed_out:
            print("       ⚠ TIMED OUT")

        print(DIVIDER)

    print()


if __name__ == "__main__":
    asyncio.run(main())
