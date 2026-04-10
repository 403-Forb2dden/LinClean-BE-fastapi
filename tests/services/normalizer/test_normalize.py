"""normalize_url unit tests."""

import pytest
from app.core.exceptions import NormalizationError
from app.services.normalizer.normalize import normalize_url


class TestInputValidation:
    def test_empty_string_raises(self) -> None:
        with pytest.raises(NormalizationError, match="빈 URL"):
            normalize_url("")

    def test_whitespace_only_raises(self) -> None:
        with pytest.raises(NormalizationError, match="빈 URL"):
            normalize_url("   ")

    def test_whitespace_trimmed(self) -> None:
        result = normalize_url("  https://example.com/  ")
        assert result.original_url == "https://example.com/"
        assert result.normalized_url == "https://example.com/"

    def test_control_characters_removed(self) -> None:
        result = normalize_url("https://example\x00.com/pa\x01th")
        assert "\x00" not in result.normalized_url
        assert "\x01" not in result.normalized_url
        assert "example.com" in result.normalized_url

    def test_max_length_exceeded_raises(self) -> None:
        long_url = "https://example.com/" + "a" * 1024
        with pytest.raises(NormalizationError, match="최대 길이"):
            normalize_url(long_url)

    def test_max_length_boundary_passes(self) -> None:
        padding = 1024 - len("https://example.com/")
        url = "https://example.com/" + "a" * padding
        result = normalize_url(url)
        assert result.normalized_url.startswith("https://example.com/")

    def test_max_length_checked_after_scheme_prepend(self) -> None:
        padding = 1024 - len("https://") - len("example.com/")
        url_without_scheme = "example.com/" + "a" * padding
        result = normalize_url(url_without_scheme)
        assert result.normalized_url.startswith("https://example.com/")


class TestOriginalPreservation:
    def test_original_url_preserved_after_trim(self) -> None:
        result = normalize_url("  HTTP://EXAMPLE.COM/Path  ")
        assert result.original_url == "HTTP://EXAMPLE.COM/Path"

    def test_original_differs_from_normalized(self) -> None:
        result = normalize_url("HTTP://EXAMPLE.COM:80/Path#frag")
        assert result.original_url == "HTTP://EXAMPLE.COM:80/Path#frag"
        assert result.normalized_url == "http://example.com/Path"


class TestScheme:
    def test_lowercase_scheme(self) -> None:
        result = normalize_url("HTTP://Example.com")
        assert result.normalized_url == "http://example.com/"

    def test_https_preserved(self) -> None:
        result = normalize_url("HTTPS://Example.com/path")
        assert result.normalized_url == "https://example.com/path"

    def test_no_scheme_defaults_to_https(self) -> None:
        result = normalize_url("example.com/path")
        assert result.normalized_url == "https://example.com/path"

    def test_unsupported_scheme_raises(self) -> None:
        with pytest.raises(NormalizationError, match="지원하지 않는 스킴"):
            normalize_url("ftp2://example.com")

    def test_ftp_allowed(self) -> None:
        result = normalize_url("FTP://files.example.com/pub")
        assert result.normalized_url.startswith("ftp://")


class TestHost:
    def test_lowercase_host(self) -> None:
        result = normalize_url("https://EXAMPLE.COM/")
        assert result.normalized_url == "https://example.com/"

    def test_scheme_only_raises(self) -> None:
        with pytest.raises(NormalizationError, match="호스트가 비어있습니다"):
            normalize_url("https://")

    def test_userinfo_stripped_for_phishing(self) -> None:
        result = normalize_url("https://google.com@evil.com/path")
        assert "evil.com" in result.normalized_url
        assert "google.com@" not in result.normalized_url

    def test_basic_auth_userinfo_stripped(self) -> None:
        result = normalize_url("https://user:pass@example.com/api")
        assert "user:pass@" not in result.normalized_url
        assert "example.com/api" in result.normalized_url


class TestPort:
    def test_default_http_port_removed(self) -> None:
        result = normalize_url("http://example.com:80/path")
        assert result.normalized_url == "http://example.com/path"

    def test_default_https_port_removed(self) -> None:
        result = normalize_url("https://example.com:443/path")
        assert result.normalized_url == "https://example.com/path"

    def test_default_ftp_port_removed(self) -> None:
        result = normalize_url("ftp://example.com:21/file")
        assert result.normalized_url == "ftp://example.com/file"

    def test_non_default_port_kept(self) -> None:
        result = normalize_url("https://example.com:8080/")
        assert ":8080" in result.normalized_url


class TestPath:
    def test_empty_path_becomes_slash(self) -> None:
        result = normalize_url("https://example.com")
        assert result.normalized_url == "https://example.com/"

    def test_path_case_preserved(self) -> None:
        result = normalize_url("https://example.com/Path/To/Page")
        assert "/Path/To/Page" in result.normalized_url

    def test_double_slash_collapsed(self) -> None:
        result = normalize_url("https://example.com//a//b")
        assert "//" not in result.normalized_url.split("://", 1)[1]

    def test_dot_segment_resolved(self) -> None:
        result = normalize_url("https://example.com/a/b/../c")
        assert result.normalized_url == "https://example.com/a/c"

    def test_single_dot_resolved(self) -> None:
        result = normalize_url("https://example.com/a/./b")
        assert result.normalized_url == "https://example.com/a/b"

    def test_dot_beyond_root(self) -> None:
        result = normalize_url("https://example.com/../a")
        assert result.normalized_url == "https://example.com/a"

    def test_complex_dot_segments(self) -> None:
        result = normalize_url("https://example.com/a/b/c/../../d")
        assert result.normalized_url == "https://example.com/a/d"


class TestFragment:
    def test_fragment_removed(self) -> None:
        result = normalize_url("https://example.com/page#section")
        assert "#" not in result.normalized_url

    def test_fragment_with_query(self) -> None:
        result = normalize_url("https://example.com/page?q=1#top")
        assert "#" not in result.normalized_url
        assert "q=1" in result.normalized_url


class TestPercentEncoding:
    def test_unreserved_decoded(self) -> None:
        result = normalize_url("https://example.com/%41%42%43")
        assert "/ABC" in result.normalized_url

    def test_tilde_decoded(self) -> None:
        result = normalize_url("https://example.com/%7Euser")
        assert "/~user" in result.normalized_url

    def test_reserved_hex_uppercased(self) -> None:
        result = normalize_url("https://example.com/path%2fmore")
        assert "%2F" in result.normalized_url

    def test_already_uppercase_hex_unchanged(self) -> None:
        result = normalize_url("https://example.com/path%2Fmore")
        assert "%2F" in result.normalized_url

    def test_space_encoding_uppercased(self) -> None:
        result = normalize_url("https://example.com/my%20page")
        assert "%20" in result.normalized_url

    def test_query_encoding_normalized(self) -> None:
        result = normalize_url("https://example.com/?q=%61%62%63")
        assert "q=abc" in result.normalized_url

    def test_params_encoding_normalized(self) -> None:
        result = normalize_url("https://example.com/path;%7eparam?q=1")
        assert ";~param" in result.normalized_url


class TestIDN:
    def test_unicode_to_punycode(self) -> None:
        result = normalize_url("https://☃.com/")
        assert "xn--" in result.normalized_url

    def test_punycode_stays_punycode(self) -> None:
        result = normalize_url("https://xn--n3h.com/")
        assert "xn--n3h.com" in result.normalized_url

    def test_ascii_domain_unchanged(self) -> None:
        result = normalize_url("https://example.com/")
        assert result.normalized_url == "https://example.com/"


class TestIntegration:
    def test_full_normalization(self) -> None:
        raw = "  HTTP://EXAMPLE.COM:80/a/../b/./c?q=%7e#frag  "
        result = normalize_url(raw)
        assert result.original_url == "HTTP://EXAMPLE.COM:80/a/../b/./c?q=%7e#frag"
        assert result.normalized_url == "http://example.com/b/c?q=~"

    def test_preserves_meaningful_query(self) -> None:
        result = normalize_url("https://example.com/search?q=hello&lang=ko")
        assert "q=hello" in result.normalized_url
        assert "lang=ko" in result.normalized_url
