"""
RDAP 조회는 실제 네트워크(`rdap.org` bootstrap)로 나감.
환경에 따라 일부 도메인은 RDAP 서버가 응답하지 않을 수 있으며,
그 경우 `rdap_error` 만 찍히고 파이프라인은 그대로 진행됨.
"""

from __future__ import annotations

import asyncio

from app.schemas.domain_heuristic import DomainHeuristicResult
from app.services.domain_heuristic import check_domain_heuristic
from app.services.domain_heuristic.rdap import aclose_client

DIVIDER = "-" * 72


CASES: list[tuple[str, str]] = [
    # --- 정상 도메인 (신호 없음 예상) ---
    ("정상 도메인 (google)", "https://www.google.com/"),
    ("정상 도메인 (naver)", "https://www.naver.com/"),
    # --- 패턴 기반 신호 ---
    ("IP 직접 접근", "http://192.168.1.1/login"),
    ("HTTPS 미사용", "http://example.com/"),
    ("의심 TLD (.xyz)", "https://free-money.xyz/"),
    ("의심 TLD (.zip)", "https://invoice.zip/"),
    ("하이픈 과다 + 긴 레이블", "https://login-secure-naver-auth-verify.com/"),
    ("서브도메인 과다 중첩", "https://signin.auth.account.verify.example.com/"),
    ("Punycode / IDN", "https://xn--nver-9na.com/"),
    ("오픈 리다이렉트 파라미터", "https://example.com/go?url=http://evil.xyz"),
    # --- 호스팅 플랫폼 (서브도메인 경유 vs 플랫폼 루트) ---
    ("호스팅 플랫폼 경유 (github.io)", "https://someuser.github.io/repo/"),
    ("호스팅 플랫폼 경유 (netlify.app)", "https://myapp.netlify.app/"),
    ("호스팅 플랫폼 루트 (typo 오탐 방어)", "https://netlify.app/"),
    # --- 타이포스쿼팅 ---
    ("타이포스쿼팅 (distance 1)", "https://naverr.com/"),
    ("타이포스쿼팅 (suffix 상이)", "https://naver.net/"),
    # --- DGA 유사 ---
    ("DGA 유사 (무작위 문자열)", "https://xjqkzvnpwmrbtld.com/"),
    # --- RDAP 신규 도메인 (실제 신규 등록 도메인이 있을 때만 NEW_DOMAIN 발동) ---
    ("RDAP 조회 (기성 도메인)", "https://www.cloudflare.com/"),
]


def _fmt_rdap(result: DomainHeuristicResult) -> str:
    if result.rdap_error:
        return f"error={result.rdap_error}"
    if result.rdap is None:
        return "없음"
    rdap = result.rdap
    return (
        f"registrar={rdap.registrar!r} "
        f"age_days={rdap.domain_age_days} "
        f"is_new={rdap.is_new_domain}"
    )


async def main() -> None:
    print()
    print("=" * 72)
    print("  LinClean -- Domain Heuristic Demo")
    print("=" * 72)

    try:
        for i, (desc, url) in enumerate(CASES, 1):
            print(f"\n  [{i:02d}] {desc}")
            print(f"       input  : {url}")

            result = await check_domain_heuristic(url)

            print(f"       domain : {result.domain}")
            print(f"       score  : {result.score}")
            print(f"       signals: {[s.value for s in result.signals]}")
            print(f"       rdap   : {_fmt_rdap(result)}")
            print(DIVIDER)
    finally:
        # 데모 종료 시 RDAP httpx client 정리 (앱 lifespan 외부에서 실행되므로)
        await aclose_client()

    print()


if __name__ == "__main__":
    asyncio.run(main())
