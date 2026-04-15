"""GSB + URLhaus 병렬 조회 후 결과 병합."""

from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.schemas.analysis import (
    GSBResult,
    ThreatDbResult,
    URLhausResult,
)
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


async def check_threat_db(session: AsyncSession, final_url: str) -> ThreatDbResult:
    """final_url 을 GSB + URLhaus 와 병렬 대조해 판정 결과 반환.

    어느 한쪽이 실패해도 다른 쪽 결과로 판정한다. 두 쪽 다 실패 시
    is_malicious=False, sources_checked=0 로 반환하여 상위 레이어가 보수적으로 처리.
    """
    gsb_task = check_gsb(final_url)
    urlhaus_task = check_urlhaus(session, final_url)

    gsb_raw, urlhaus_raw = await asyncio.gather(
        gsb_task, urlhaus_task, return_exceptions=True
    )

    if isinstance(gsb_raw, BaseException):
        logger.warning("threat_db.gsb_unexpected", error=str(gsb_raw))
        gsb = GSBResult(checked=False, is_threat=False, error="unexpected")
    else:
        gsb = gsb_raw

    if isinstance(urlhaus_raw, BaseException):
        logger.warning("threat_db.urlhaus_unexpected", error=str(urlhaus_raw))
        urlhaus = URLhausResult(checked=False, is_threat=False, error="unexpected")
    else:
        urlhaus = urlhaus_raw

    is_malicious = gsb.is_threat or urlhaus.is_threat
    sources_checked = int(gsb.checked) + int(urlhaus.checked)

    return ThreatDbResult(
        final_url=final_url,
        is_malicious=is_malicious,
        sources_checked=sources_checked,
        gsb=gsb,
        urlhaus=urlhaus,
        threat_types=_merge_threat_types(gsb, urlhaus),
    )
