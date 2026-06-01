"""match_keys.derive_keys 단위 테스트."""

from __future__ import annotations

from app.services.threat_db.match_keys import derive_keys


def test_host_only_for_standard_domain() -> None:
    assert derive_keys("https://example.com/path/deep") == ["example.com"]


def test_github_returns_host_path_only() -> None:
    keys = derive_keys("https://github.com/alice/repo/blob/main/x.exe")
    assert keys == ["github.com/alice/repo"]


def test_raw_githubusercontent() -> None:
    keys = derive_keys("https://raw.githubusercontent.com/alice/repo/main/x.sh")
    assert keys == ["raw.githubusercontent.com/alice/repo"]


def test_github_short_path_does_not_fallback_to_host() -> None:
    # 다중 테넌트 호스트는 특정 사용자/리포 단위 이하로는 매칭하지 않는다.
    assert derive_keys("https://github.com/alice") == []


def test_dropbox_root_does_not_fallback_to_host() -> None:
    assert derive_keys("https://www.dropbox.com/") == []


def test_dropbox_shared_file_uses_path_prefix() -> None:
    keys = derive_keys("https://www.dropbox.com/scl/fi/abc/report.exe?dl=0")
    assert keys == ["www.dropbox.com/scl/fi"]


def test_dropboxusercontent_download_host_uses_path_prefix() -> None:
    keys = derive_keys("https://dl.dropboxusercontent.com/scl/fi/abc/report.exe")
    assert keys == ["dl.dropboxusercontent.com/scl/fi"]


def test_empty_host_returns_empty_list() -> None:
    assert derive_keys("not a url") == []


def test_host_case_is_normalized() -> None:
    assert derive_keys("https://Example.COM/x") == ["example.com"]
