"""URLhaus 로컬 스냅샷 엔트리."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class URLhausEntry(Base):
    """URLhaus CSV 한 행을 upsert 한 레코드.

    `match_key` 는 host 또는 host+path-prefix 로, 조회 시 빠른 exact match 용도.
    """

    __tablename__ = "urlhaus_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=False)
    url: Mapped[str] = mapped_column(String, nullable=False, unique=True, index=True)
    host: Mapped[str] = mapped_column(String, nullable=False, index=True)
    match_key: Mapped[str] = mapped_column(String, nullable=False, index=True)
    threat: Mapped[str | None] = mapped_column(String, nullable=True)
    tags: Mapped[str | None] = mapped_column(String, nullable=True)
    url_status: Mapped[str | None] = mapped_column(String, nullable=True)
    date_added: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    last_online: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    urlhaus_link: Mapped[str | None] = mapped_column(String, nullable=True)
    reporter: Mapped[str | None] = mapped_column(String, nullable=True)
    synced_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)

    __table_args__ = (Index("ix_urlhaus_entries_host_match_key", "host", "match_key"),)
