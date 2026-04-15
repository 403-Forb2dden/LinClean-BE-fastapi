"""URLhaus CSV 다운로드 → 로컬 SQLite upsert.

CSV 포맷(abuse.ch):
    # comment lines starting with '#'
    id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.logging import get_logger
from app.db.session import SessionLocal
from app.models.urlhaus_entry import URLhausEntry
from app.services.threat_db.match_keys import derive_keys

logger = get_logger(__name__)

_CSV_FIELDS = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
]


def _parse_dt(raw: str | None) -> datetime | None:
    if not raw or raw in ("None", "N/A"):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC"):
        try:
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=UTC)
        except ValueError:
            continue
    return None


def _derive_match_key(url: str) -> tuple[str, str] | None:
    """(host, match_key) 반환. host 없으면 None."""
    keys = derive_keys(url)
    if not keys:
        return None
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    # derive_keys 는 [host_path, host] 또는 [host] — 첫 원소가 가장 구체적 키.
    return host, keys[0]


async def _fetch_csv() -> str | None:
    try:
        async with httpx.AsyncClient(
            timeout=settings.urlhaus_download_timeout_seconds
        ) as client:
            resp = await client.get(settings.urlhaus_recent_csv_url)
    except httpx.HTTPError as e:
        logger.warning("urlhaus_sync.fetch_failed", error=str(e))
        return None
    if resp.status_code != 200:
        logger.warning("urlhaus_sync.fetch_bad_status", status=resp.status_code)
        return None
    return resp.text


def _iter_rows(csv_text: str):
    # '#' 주석 라인 스킵 후 헤더 없는 CSV 로 파싱.
    clean = io.StringIO(
        "\n".join(
            line for line in csv_text.splitlines() if line and not line.startswith("#")
        )
    )
    reader = csv.reader(clean, quotechar='"', skipinitialspace=True)
    for row in reader:
        if len(row) < len(_CSV_FIELDS):
            continue
        yield dict(zip(_CSV_FIELDS, row[: len(_CSV_FIELDS)], strict=True))


async def sync_urlhaus() -> dict:
    """URLhaus CSV 를 동기화하고 {inserted, updated, total, failed} 통계 반환."""
    stats = {"inserted": 0, "updated": 0, "total": 0, "failed": 0}

    csv_text = await _fetch_csv()
    if csv_text is None:
        return stats

    now = datetime.now(UTC).replace(tzinfo=None)

    try:
        async with SessionLocal() as session, session.begin():
            for raw in _iter_rows(csv_text):
                stats["total"] += 1
                try:
                    entry_id = int(raw["id"])
                except (TypeError, ValueError):
                    stats["failed"] += 1
                    continue

                url = raw.get("url") or ""
                if not url:
                    stats["failed"] += 1
                    continue

                derived = _derive_match_key(url)
                if derived is None:
                    stats["failed"] += 1
                    continue
                host, match_key = derived

                values = {
                    "id": entry_id,
                    "url": url,
                    "host": host,
                    "match_key": match_key,
                    "threat": raw.get("threat") or None,
                    "tags": raw.get("tags") or None,
                    "url_status": raw.get("url_status") or None,
                    "date_added": _parse_dt(raw.get("dateadded")),
                    "last_online": _parse_dt(raw.get("last_online")),
                    "urlhaus_link": raw.get("urlhaus_link") or None,
                    "reporter": raw.get("reporter") or None,
                    "synced_at": now,
                }

                stmt = sqlite_insert(URLhausEntry).values(**values)
                update_cols = {
                    c: stmt.excluded[c]
                    for c in values
                    if c != "id"
                }
                stmt = stmt.on_conflict_do_update(
                    index_elements=["id"], set_=update_cols
                )
                result = await session.execute(stmt)
                # SQLite 는 upsert 시 rowcount 로 insert/update 구분이 애매 →
                # lastrowid 유무로 추정.
                if getattr(result, "is_insert", False) and result.inserted_primary_key:
                    stats["inserted"] += 1
                else:
                    stats["updated"] += 1
    except SQLAlchemyError as e:
        logger.warning("urlhaus_sync.db_error", error=str(e))
        return stats

    logger.info("urlhaus_sync.completed", **stats)
    return stats
