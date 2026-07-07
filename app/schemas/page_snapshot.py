from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class PageSnapshotStatus(StrEnum):
    AVAILABLE = "available"
    SKIPPED = "skipped"
    TIMEOUT = "timeout"
    FAILED = "failed"


class PageSnapshotResult(BaseModel):
    status: PageSnapshotStatus
    final_url: str
    storage_key: str | None = None
    elapsed_seconds: float | None = Field(default=None, ge=0)
    error: str | None = None
