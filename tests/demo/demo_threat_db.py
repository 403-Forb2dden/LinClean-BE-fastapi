"""외부 위협 DB 대조 데모.

사용법:
    alembic upgrade head           # 최초 1회
    python -m tests.demo.demo_threat_db

환경변수 `GSB_API_KEY` 가 설정돼 있으면 실제 GSB Lookup API 호출.
없으면 GSB 는 `checked=False, error=not_configured` 로 반환된다.

URLhaus 는 로컬 SQLite 스냅샷 기반이므로 실행 첫 부분에서 1회
`sync_urlhaus()` 를 호출해 CSV 를 수신한다.
"""

from __future__ import annotations

import asyncio

from app.db.session import SessionLocal
from app.models.urlhaus_entry import URLhausEntry
from app.schemas.analysis import ThreatDbResult
from app.services.threat_db import check_threat_db
from app.services.threat_db.urlhaus_sync import sync_urlhaus
from sqlalchemy import func, select

DIVIDER = "-" * 72


# GSB 공식 테스트 URL — 실제 악성이 아니지만 Lookup API 가 항상 MALWARE 로
# 매치시켜 주는 시그니처. GSB_API_KEY 가 있어야 threat=True 로 반환된다.
GSB_TEST_URL = "http://malware.testing.google.test/testing/malware/"


async def _pick_urlhaus_sample() -> str | None:
    """동기화된 DB 에서 URLhaus 등재 URL 하나를 랜덤 추출.

    등재 URL 은 CSV 싱크 시점마다 달라지므로 하드코딩 불가 — 방금 받은
    스냅샷에서 아무거나 하나 뽑아서 실제 매치가 일어나는지 시연한다.
    """
    async with SessionLocal() as session:
        stmt = select(URLhausEntry.url).order_by(func.random()).limit(1)
        row = (await session.execute(stmt)).scalar_one_or_none()
    return row


def _print_result(label: str, url: str, result: ThreatDbResult) -> None:
    print(DIVIDER)
    print(f"[{label}]")
    print(f"  input         : {url}")
    print(f"  malicious     : {result.is_malicious}")
    print(f"  sources_check : {result.sources_checked}")
    print(f"  threat_types  : {result.threat_types}")
    print(
        f"  gsb           : checked={result.gsb.checked} "
        f"threat={result.gsb.is_threat} error={result.gsb.error}"
    )
    print(
        f"  urlhaus       : checked={result.urlhaus.checked} "
        f"threat={result.urlhaus.is_threat} "
        f"match_type={result.urlhaus.match_type} "
        f"matched_key={result.urlhaus.matched_key} "
        f"error={result.urlhaus.error}"
    )


async def main() -> None:
    print()
    print("=" * 72)
    print("  LinClean -- Threat DB (GSB + URLhaus) Demo")
    print("=" * 72)
    print()

    print(">>> 1) URLhaus 스냅샷 동기화 (수 MB CSV 다운로드·파싱 — 실제 수십 초 소요)")
    # stats = {inserted, updated, total, failed} — 청크(500행) 단위 커밋이라
    # 중간에 깨져도 직전 청크까지는 영속화되고 그만큼만 집계된다.
    stats = await sync_urlhaus()
    print(f"    stats: {stats}")
    print()

    urlhaus_sample = await _pick_urlhaus_sample()

    cases: list[tuple[str, str]] = [
        # 1) 둘 다 미매치 — 정상 URL
        ("둘 다 미매치 (정상 URL)", "https://www.google.com/"),
        # 2) 위협 DB 에 없는 평범한 샘플 도메인
        ("위험 DB 미등재 샘플 도메인", "https://example.com/"),
        # 3) GSB 공식 테스트 URL — API 키 있으면 항상 MALWARE 매치
        ("GSB 공식 테스트 URL (MALWARE 매치)", GSB_TEST_URL),
    ]
    if urlhaus_sample:
        cases.append(("URLhaus 로컬 스냅샷 등재 URL", urlhaus_sample))
    else:
        print("    (URLhaus 샘플이 비어있어 URLhaus 매치 케이스는 건너뜀)")

    async with SessionLocal() as session:
        for label, url in cases:
            result = await check_threat_db(session, url)
            _print_result(label, url, result)
    print(DIVIDER)


if __name__ == "__main__":
    asyncio.run(main())
