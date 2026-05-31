"""URLhaus 로컬 SQLite 조회.

URL 완전일치 → match_key(host_path/host) 조회 순.
"""

from __future__ import annotations

from typing import Literal
from urllib.parse import urlsplit, urlunsplit

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
    match_type: Literal["url", "host", "host_path"],
    matched_key: str,
) -> URLhausResult:
    return URLhausResult(
        checked=True,
        is_threat=True,
        match_type=match_type,
        matched_key=matched_key,
        threat=entry.threat,
        tags=_split_tags(entry.tags),
        urlhaus_link=entry.urlhaus_link,
    )


def _url_variants(url: str) -> list[str]:
    variants: list[str] = []

    def add(candidate: str) -> None:
        if candidate and candidate not in variants:
            variants.append(candidate)

    add(url)
    try:
        parts = urlsplit(url)
    except ValueError:
        return variants
    if not parts.scheme or not parts.netloc:
        return variants

    path_variants = [parts.path]
    if parts.path == "":
        path_variants.append("/")
    elif parts.path == "/":
        path_variants.append("")
    elif parts.path.endswith("/"):
        path_variants.append(parts.path.rstrip("/"))
    else:
        path_variants.append(parts.path + "/")

    schemes = [parts.scheme]
    if parts.scheme == "https":
        schemes.append("http")
    elif parts.scheme == "http":
        schemes.append("https")

    for scheme in schemes:
        for path in path_variants:
            add(urlunsplit((scheme, parts.netloc, path, parts.query, parts.fragment)))
    return variants


async def check_urlhaus(session: AsyncSession, url: str) -> URLhausResult:
    """URLhaus 로컬 스냅샷에서 URL 매칭 여부 조회."""
    try:
        # 1) URL 완전일치
        for candidate in _url_variants(url):
            stmt = select(URLhausEntry).where(URLhausEntry.url == candidate)
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
                match_type: Literal["host", "host_path"] = "host_path" if "/" in key else "host"
                return _to_result(hit, match_type, key)

        return URLhausResult(checked=True, is_threat=False)
    except SQLAlchemyError as e:
        logger.warning("urlhaus.db_error", error=str(e))
        return URLhausResult(checked=False, is_threat=False, error="db_error")
