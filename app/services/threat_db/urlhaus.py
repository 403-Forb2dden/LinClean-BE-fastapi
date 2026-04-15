"""URLhaus 로컬 SQLite 조회.

URL 완전일치 → match_key(host_path/host) 조회 순.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.urlhaus_entry import URLhausEntry
from app.schemas.analysis import URLhausResult
from app.services.threat_db.match_keys import derive_keys

logger = get_logger(__name__)


def _split_tags(tags: str | None) -> list[str]:
    if not tags:
        return []
    return [t.strip() for t in tags.split(",") if t.strip()]


def _to_result(
    entry: URLhausEntry,
    match_type: str,
    matched_key: str,
) -> URLhausResult:
    return URLhausResult(
        checked=True,
        is_threat=True,
        match_type=match_type,  # type: ignore[arg-type]
        matched_key=matched_key,
        threat=entry.threat,
        tags=_split_tags(entry.tags),
        urlhaus_link=entry.urlhaus_link,
    )


async def check_urlhaus(session: AsyncSession, url: str) -> URLhausResult:
    """URLhaus 로컬 스냅샷에서 URL 매칭 여부 조회."""
    try:
        # 1) URL 완전일치
        stmt = select(URLhausEntry).where(URLhausEntry.url == url)
        row = (await session.execute(stmt)).scalar_one_or_none()
        if row is not None:
            return _to_result(row, "url", row.url)

        # 2) match_key IN (...)
        keys = derive_keys(url)
        if not keys:
            return URLhausResult(checked=True, is_threat=False)

        stmt = select(URLhausEntry).where(URLhausEntry.match_key.in_(keys))
        rows = (await session.execute(stmt)).scalars().all()
        if not rows:
            return URLhausResult(checked=True, is_threat=False)

        # host_path(더 구체적) 우선
        by_key = {r.match_key: r for r in rows}
        for key in keys:
            hit = by_key.get(key)
            if hit is not None:
                match_type = "host_path" if "/" in key else "host"
                return _to_result(hit, match_type, key)

        return URLhausResult(checked=True, is_threat=False)
    except SQLAlchemyError as e:
        logger.warning("urlhaus.db_error", error=str(e))
        return URLhausResult(checked=False, is_threat=False, error="db_error")
