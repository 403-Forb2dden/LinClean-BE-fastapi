"""drop unused urlhaus indexes

Revision ID: a1b2c3d4e5f6
Revises: 818a3f82f172
Create Date: 2026-04-16 00:00:00.000000+00:00

현재 조회 핫패스는 `url` 과 `match_key` 인덱스만 사용한다. `host` 단일 인덱스와
`(host, match_key)` 복합 인덱스는 생성만 되고 참조되는 쿼리가 없어 쓰기 오버헤드만
발생하므로 제거한다.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: str | None = "818a3f82f172"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    with op.batch_alter_table("urlhaus_entries", schema=None) as batch_op:
        batch_op.drop_index("ix_urlhaus_entries_host_match_key")
        batch_op.drop_index(batch_op.f("ix_urlhaus_entries_host"))


def downgrade() -> None:
    with op.batch_alter_table("urlhaus_entries", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_urlhaus_entries_host"), ["host"], unique=False)
        batch_op.create_index(
            "ix_urlhaus_entries_host_match_key", ["host", "match_key"], unique=False
        )
