from __future__ import annotations

from typing import Any

__all__ = ["check_domain_heuristic"]


def __getattr__(name: str) -> Any:
    if name == "check_domain_heuristic":
        from app.services.domain_heuristic.check import check_domain_heuristic

        return check_domain_heuristic
    raise AttributeError(name)
