from __future__ import annotations

import pytest
import tldextract


def test_extract_url_parts_does_not_use_default_disk_cached_extractor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.core.tld import extract_url_parts

    def fail_default_extractor(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("default tldextract extractor should not be used")

    monkeypatch.setattr(tldextract, "extract", fail_default_extractor)

    result = extract_url_parts("https://login.example.co.kr/path")

    assert result.domain == "example"
    assert result.suffix == "co.kr"
