"""SQLAlchemy ORM models.

Import all models here so Alembic autogenerate sees them via `Base.metadata`.
"""

from app.db.base import Base
from app.models.urlhaus_entry import URLhausEntry

__all__ = ["Base", "URLhausEntry"]
