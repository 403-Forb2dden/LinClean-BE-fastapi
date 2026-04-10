"""URL canonicalization — pipeline stage 1.

Produces a canonical form so downstream stages (threat DB lookup,
heuristics, content analysis) can compare URLs consistently.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse, urlunparse

from app.core.config import settings
from app.core.exceptions import NormalizationError
from app.schemas.analysis import NormalizeResult

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443, "ftp": 21}
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https", "ftp"})

# RFC 3986 §2.3
_UNRESERVED: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PCT_ENCODED_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def normalize_url(raw_url: str) -> NormalizeResult:
    """Return a canonical NormalizeResult, or raise NormalizationError."""
    original = raw_url.strip()
    if not original:
        raise NormalizationError(message="빈 URL입니다.")

    cleaned = _CONTROL_CHAR_RE.sub("", original)
    cleaned = unicodedata.normalize("NFC", cleaned)

    # Scheme must be resolved before length check — prepending adds bytes.
    # Simple "://" check misses cases like "example.com/path://weird".
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', cleaned):
        cleaned = "https://" + cleaned

    max_len = settings.normalizer_max_url_length
    if len(cleaned) > max_len:
        raise NormalizationError(
            message=f"URL이 최대 길이({max_len}자)를 초과합니다.",
        )

    try:
        parsed = urlparse(cleaned)
    except ValueError as e:
        raise NormalizationError(message=f"URL 파싱 실패: {e}") from e

    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise NormalizationError(message=f"지원하지 않는 스킴: {scheme}")

    hostname = parsed.hostname or ""
    if ":" in hostname:
        raise NormalizationError(message="IPv6 주소는 지원하지 않습니다.")
    hostname = _normalize_idn(hostname.lower())
    if not hostname:
        raise NormalizationError(message="호스트가 비어있습니다.")

    # Reassembling netloc from parsed.hostname implicitly drops userinfo
    # (RFC 3986 §3.2.1), which is abused for phishing (google.com@evil.com).
    try:
        port = parsed.port
    except ValueError as e:
        raise NormalizationError(message=f"유효하지 않은 포트: {e}") from e
    if port and port == _DEFAULT_PORTS.get(scheme):
        port = None
    netloc = hostname if port is None else f"{hostname}:{port}"

    path = _normalize_path(parsed.path)
    params = _normalize_pct_encoding(parsed.params)
    query = _normalize_pct_encoding(parsed.query)

    normalized = urlunparse((scheme, netloc, path, params, query, ""))
    return NormalizeResult(original_url=original, normalized_url=normalized)


def _normalize_idn(hostname: str) -> str:
    """Convert unicode hostname to punycode for threat DB compatibility."""
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


def _normalize_path(raw_path: str) -> str:
    path = raw_path or "/"
    path = _normalize_pct_encoding(path)

    # RFC treats //a and /a as different resources, but attackers insert
    # extra slashes to dodge threat DB pattern matching.
    path = re.sub(r"/{2,}", "/", path)

    path = _resolve_dot_segments(path)
    return path or "/"


def _resolve_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4"""
    segments = path.split("/")
    resolved: list[str] = []
    for seg in segments:
        if seg == ".":
            continue
        if seg == "..":
            if resolved and resolved[-1] != "":
                resolved.pop()
        else:
            resolved.append(seg)
    if path.startswith("/") and (not resolved or resolved[0] != ""):
        resolved.insert(0, "")
    return "/".join(resolved)


def _normalize_pct_encoding(value: str) -> str:
    """Decode unreserved (%41->A), uppercase reserved hex (%2f->%2F)."""
    if not value:
        return value

    def _replace(match: re.Match[str]) -> str:
        hex_str = match.group(1)
        char = chr(int(hex_str, 16))
        if char in _UNRESERVED:
            return char
        return f"%{hex_str.upper()}"

    return _PCT_ENCODED_RE.sub(_replace, value)
