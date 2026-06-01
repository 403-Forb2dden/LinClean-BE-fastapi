"""URLhaus CSV 다운로드 → 로컬 SQLite upsert.

CSV 포맷(abuse.ch):
    # comment lines starting with '#'
    id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter

설계 메모
---------
- **부분 진행 보존**: 전체 행을 단일 트랜잭션으로 감싸지 않고 `CHUNK_SIZE` 단위로
  커밋한다. 중간에 DB 오류가 나도 직전 청크까지의 결과는 영속화되며, `stats` 는
  실제로 커밋된 카운트만 보고한다.
- **insert/update 정확 분리**: SQLite 의 `INSERT ... ON CONFLICT DO UPDATE` 는
  cursor 반환 값으로 두 경로를 구분할 수 없다. 청크 처리 직전에 해당 청크의 id
  들이 이미 존재하는지 한 번 SELECT 해 결과를 분류한다.
- **시각 정규화**: SQLite 에는 모두 naive UTC 로 저장한다. `_parse_dt` 와
  `synced_at` 양쪽이 동일한 규약을 따라야 비교/조회가 깨지지 않는다.
"""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable, Iterator
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import select
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

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

# 청크 크기 — 너무 작으면 트랜잭션 오버헤드, 너무 크면 부분 진행 보존 효과 약화.
CHUNK_SIZE = 500

RawCsvRow = dict[str, str]
ValueRow = dict[str, Any]
SyncStats = dict[str, int]


def _parse_dt(raw: str | None) -> datetime | None:
    """CSV 의 시각 문자열을 naive UTC datetime 으로 정규화."""
    if not raw or raw in ("None", "N/A"):
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S UTC"):
        try:
            # SQLite 컬럼이 naive 이므로 tzinfo 를 떼서 일관성 유지.
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=None)
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
    # derive_keys 는 [host_path] 또는 [host] — 첫 원소가 저장할 match_key.
    return host, keys[0]


async def _fetch_csv() -> str | None:
    try:
        async with httpx.AsyncClient(timeout=settings.urlhaus_download_timeout_seconds) as client:
            resp = await client.get(settings.urlhaus_recent_csv_url)
    except httpx.HTTPError as e:
        logger.warning("urlhaus_sync.fetch_failed", error=str(e))
        return None
    if resp.status_code != 200:
        logger.warning("urlhaus_sync.fetch_bad_status", status=resp.status_code)
        return None
    return resp.text


def _iter_raw_rows(csv_text: str) -> Iterator[list[str]]:
    """CSV 의 데이터 행을 list 로 yield. 주석/빈 줄 스킵."""
    clean = io.StringIO(
        "\n".join(line for line in csv_text.splitlines() if line and not line.startswith("#"))
    )
    reader = csv.reader(clean, quotechar='"', skipinitialspace=True)
    yield from reader


def _build_values(raw: RawCsvRow, now: datetime) -> ValueRow | None:
    """CSV 한 행을 ORM values dict 로 변환. 검증 실패 시 None."""
    try:
        entry_id = int(raw["id"])
    except (TypeError, ValueError):
        return None

    url = raw.get("url") or ""
    if not url:
        return None

    derived = _derive_match_key(url)
    if derived is None:
        return None
    host, match_key = derived

    return {
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


def _chunked(rows: Iterable[ValueRow], size: int) -> Iterator[list[ValueRow]]:
    chunk: list[ValueRow] = []
    for row in rows:
        chunk.append(row)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


async def _flush_chunk(session: AsyncSession, values_list: list[ValueRow]) -> tuple[int, int]:
    """한 청크를 upsert 하고 (inserted, updated) 카운트 반환.

    SQLite 의 `INSERT ... ON CONFLICT DO UPDATE` 는 cursor 결과로 insert/update
    를 구분할 수 없으므로, 청크 단위로 한 번 SELECT 해서 사전 분류한다.

    multi-row VALUES 한 번의 INSERT 로 청크 전체를 처리 — 종전 행당 INSERT 호출은
    청크 500건 기준 500회 round-trip 이라 SQLite 라도 비용이 더 든다.
    """
    if not values_list:
        return 0, 0

    ids = [v["id"] for v in values_list]
    existing_ids = set(
        (await session.execute(select(URLhausEntry.id).where(URLhausEntry.id.in_(ids))))
        .scalars()
        .all()
    )

    stmt = sqlite_insert(URLhausEntry).values(values_list)
    # 모든 values 가 동일한 키 셋을 갖는다는 전제 — _build_values 가 보장.
    update_cols = {c: stmt.excluded[c] for c in values_list[0] if c != "id"}
    stmt = stmt.on_conflict_do_update(index_elements=["id"], set_=update_cols)
    await session.execute(stmt)

    updated = sum(1 for v in values_list if v["id"] in existing_ids)
    inserted = len(values_list) - updated
    return inserted, updated


async def sync_urlhaus() -> SyncStats:
    """URLhaus CSV 를 동기화하고 {inserted, updated, total, failed} 통계 반환.

    `stats` 는 **실제 DB 에 커밋된 행 수** 만 누적한다. 중간 청크에서 오류가 나도
    직전까지의 청크는 영속화되어 있고, 그만큼만 카운트된다.
    """
    stats: SyncStats = {"inserted": 0, "updated": 0, "total": 0, "failed": 0}

    csv_text = await _fetch_csv()
    if csv_text is None:
        return stats

    now = datetime.now(UTC).replace(tzinfo=None)

    def _values_stream() -> Iterator[ValueRow]:
        for raw in _iter_raw_rows(csv_text):
            stats["total"] += 1
            if len(raw) < len(_CSV_FIELDS):
                stats["failed"] += 1
                continue
            row_dict = dict(zip(_CSV_FIELDS, raw[: len(_CSV_FIELDS)], strict=True))
            values = _build_values(row_dict, now)
            if values is None:
                stats["failed"] += 1
                continue
            yield values

    async with SessionLocal() as session:
        for chunk in _chunked(_values_stream(), CHUNK_SIZE):
            try:
                async with session.begin():
                    inserted, updated = await _flush_chunk(session, chunk)
                stats["inserted"] += inserted
                stats["updated"] += updated
            except SQLAlchemyError as e:
                logger.warning(
                    "urlhaus_sync.chunk_failed",
                    error=str(e),
                    inserted_so_far=stats["inserted"],
                    updated_so_far=stats["updated"],
                )
                # 실패한 청크는 롤백 — 그만큼은 retry 대상으로 failed 에 누적.
                stats["failed"] += len(chunk)
                # 후속 청크는 새 트랜잭션으로 계속 시도.
                continue

    logger.info("urlhaus_sync.completed", **stats)
    return stats
