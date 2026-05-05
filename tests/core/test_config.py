from __future__ import annotations

from app.core.config import Settings


def test_rdap_cache_ttl_defaults_to_one_week() -> None:
    settings = Settings(_env_file=None, internal_api_key="test-key")

    assert settings.rdap_cache_ttl_seconds == 60 * 60 * 24 * 7
