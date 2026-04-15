"""match_keys.derive_keys 단위 테스트."""

from __future__ import annotations

from app.services.threat_db.match_keys import derive_keys


def test_host_only_for_standard_domain() -> None:
    assert derive_keys("https://example.com/path/deep") == ["example.com"]


def test_github_returns_host_path_and_host() -> None:
    keys = derive_keys("https://github.com/alice/repo/blob/main/x.exe")
    assert keys == ["github.com/alice/repo", "github.com"]


def test_raw_githubusercontent() -> None:
    keys = derive_keys("https://raw.githubusercontent.com/alice/repo/main/x.sh")
    assert keys[0] == "raw.githubusercontent.com/alice/repo"
    assert keys[-1] == "raw.githubusercontent.com"


def test_github_short_path_fallbacks_to_host() -> None:
    # path segment 가 2개 미만이면 host 만.
    assert derive_keys("https://github.com/alice") == ["github.com"]


def test_empty_host_returns_empty_list() -> None:
    assert derive_keys("not a url") == []


def test_host_case_is_normalized() -> None:
    assert derive_keys("https://Example.COM/x") == ["example.com"]
