"""URL 정규화 — 파이프라인 1단계.

위협 DB 조회, 휴리스틱, 콘텐츠 분석 등 후속 단계에서
URL을 일관되게 비교할 수 있도록 정규 형태로 변환함.
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import urlparse, urlunparse

from app.core.config import settings
from app.core.exceptions import NormalizationError
from app.schemas.normalize import NormalizeResult

_DEFAULT_PORTS: dict[str, int] = {"http": 80, "https": 443, "ftp": 21}
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https", "ftp"})

_UNRESERVED: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_PCT_ENCODED_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def normalize_url(raw_url: str) -> NormalizeResult:
    """정규화된 NormalizeResult 반환. 실패 시 NormalizationError."""
    original = raw_url.strip()
    if not original:
        raise NormalizationError(message="빈 URL입니다.")

    cleaned = _CONTROL_CHAR_RE.sub("", original)
    cleaned = unicodedata.normalize("NFC", cleaned)

    # 길이 체크 전에 스킴 확정해야 함 — 스킴 붙이면 바이트 늘어남.
    # 단순 "://" 체크는 "example.com/path://weird" 같은 케이스 놓침.
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", cleaned):
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

    # parsed.hostname으로 netloc 재조립하면 userinfo 자동 제거됨.
    # 피싱에 악용되는 패턴임 (google.com@evil.com).
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
    """유니코드 호스트명을 punycode로 변환. 위협 DB 매칭 호환용."""
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return hostname


def _normalize_path(raw_path: str) -> str:
    path = raw_path or "/"
    path = _normalize_pct_encoding(path)

    # RFC상 //a와 /a는 다른 리소스지만, 공격자가 슬래시 추가해서
    # 위협 DB 패턴 매칭 우회하는 케이스 방지.
    path = re.sub(r"/{2,}", "/", path)

    path = _resolve_dot_segments(path)
    return path or "/"


def _resolve_dot_segments(path: str) -> str:
    """dot segment(. / ..) 해소."""
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
    """비예약 문자 디코딩(%41->A), 예약 문자 hex 대문자화(%2f->%2F)."""
    if not value:
        return value

    def _replace(match: re.Match[str]) -> str:
        hex_str = match.group(1)
        char = chr(int(hex_str, 16))
        if char in _UNRESERVED:
            return char
        return f"%{hex_str.upper()}"

    return _PCT_ENCODED_RE.sub(_replace, value)
