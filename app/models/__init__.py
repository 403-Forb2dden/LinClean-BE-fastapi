"""SQLAlchemy ORM models.

Import all models here so Alembic autogenerate sees them via `Base.metadata`.
"""

from app.db.base import Base

__all__ = ["Base"]
