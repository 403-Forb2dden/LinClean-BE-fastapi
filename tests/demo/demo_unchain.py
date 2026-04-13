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
    ("리다이렉트 없음", "https://www.google.com/"),
    ("HTTP → HTTPS 업그레이드", "http://google.com/"),
    ("단축 URL (bit.ly 예시)", "https://bit.ly/3kF8Yv2"),
    ("t.co 단축 URL", "https://t.co/example"),
    ("HTTP 301 리다이렉트", "http://github.com/"),
    ("상대 경로 리다이렉트", "https://httpbin.org/relative-redirect/2"),
    ("절대 경로 리다이렉트", "https://httpbin.org/absolute-redirect/3"),
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
