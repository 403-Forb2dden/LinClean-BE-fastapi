"""GSB + URLhaus 병렬 조회 후 결과 병합."""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.schemas.threat_db import GSBResult, ThreatDbResult, URLhausResult
from app.services.threat_db.gsb import check_gsb
from app.services.threat_db.urlhaus import check_urlhaus

logger = get_logger(__name__)


def _merge_threat_types(gsb: GSBResult, urlhaus: URLhausResult) -> list[str]:
    seen: list[str] = []
    for m in gsb.matches:
        if m.threat_type and m.threat_type not in seen:
            seen.append(m.threat_type)
    if urlhaus.threat and urlhaus.threat not in seen:
        seen.append(urlhaus.threat)
    return seen


def _candidate_urls(final_url: str, original_url: str | None) -> list[str]:
    candidates = [final_url]
    if original_url and original_url != final_url:
        candidates.append(original_url)
    return candidates


def _merge_gsb(results: list[GSBResult]) -> GSBResult:
    checked = any(result.checked for result in results)
    matches: list = []
    error = None
    for result in results:
        if result.matches:
            matches.extend(result.matches)
        if error is None and result.error:
            error = result.error
    return GSBResult(
        checked=checked,
        is_threat=bool(matches),
        matches=matches,
        error=None if checked else error,
    )


def _merge_urlhaus(results: list[URLhausResult]) -> URLhausResult:
    for result in results:
        if result.is_threat:
            return result
    checked = any(result.checked for result in results)
    error = next((result.error for result in results if result.error), None)
    return URLhausResult(checked=checked, is_threat=False, error=None if checked else error)


async def check_threat_db(
    session: AsyncSession,
    final_url: str,
    *,
    original_url: str | None = None,
) -> ThreatDbResult:
    """final_url 을 GSB + URLhaus 와 병렬 대조해 판정 결과 반환.

    어느 한쪽이 실패해도 다른 쪽 결과로 판정한다. 두 쪽 다 실패 시
    is_malicious=False, sources_checked=0 로 반환하여 상위 레이어가 보수적으로 처리.
    """
    candidates = _candidate_urls(final_url, original_url)
    gsb_tasks = [check_gsb(url) for url in candidates]
    urlhaus_tasks = [check_urlhaus(session, url) for url in candidates]

    raw_results = await asyncio.gather(*gsb_tasks, *urlhaus_tasks, return_exceptions=True)

    # CancelledError 는 상위 task 의 취소 신호이므로 절대 삼키지 않는다.
    # (shutdown / 요청 timeout 시 degraded 결과를 영속화하는 사고 방지)
    for raw in raw_results:
        if isinstance(raw, asyncio.CancelledError):
            raise raw

    gsb_results: list[GSBResult] = []
    urlhaus_results: list[URLhausResult] = []
    for raw in raw_results[: len(candidates)]:
        if isinstance(raw, BaseException):
            logger.warning("threat_db.gsb_unexpected", error=str(raw))
            gsb_results.append(GSBResult(checked=False, is_threat=False, error="unexpected"))
        else:
            gsb_results.append(raw)
    for raw in raw_results[len(candidates) :]:
        if isinstance(raw, BaseException):
            logger.warning("threat_db.urlhaus_unexpected", error=str(raw))
            urlhaus_results.append(
                URLhausResult(checked=False, is_threat=False, error="unexpected")
            )
        else:
            urlhaus_results.append(raw)

    gsb = _merge_gsb(gsb_results)
    urlhaus = _merge_urlhaus(urlhaus_results)

    is_malicious = gsb.is_threat or urlhaus.is_threat
    sources_checked = sum((gsb.checked, urlhaus.checked))

    return ThreatDbResult(
        final_url=final_url,
        is_malicious=is_malicious,
        sources_checked=sources_checked,
        gsb=gsb,
        urlhaus=urlhaus,
        threat_types=_merge_threat_types(gsb, urlhaus),
    )
