"""URL 정규화(Canonicalization) 모듈.

파이프라인 1단계 — 후속 단계(위협 DB 대조·휴리스틱·콘텐츠 분석)가
동일한 기준으로 URL을 비교할 수 있도록 canonical form으로 변환합니다.

수행 항목:
  - 입력 검증 (빈 문자열, 공백 trim, 제어 문자 제거, 최대 길이 제한)
  - 스킴 검증 / 기본값 보정 (http, https, ftp만 허용)
  - 스킴·호스트 소문자화 (경로는 대소문자 보존)
  - userinfo 제거 (피싱 방지 — google.com@evil.com 같은 트릭 차단)
  - 기본 포트 제거 (:80, :443, :21)
  - 프래그먼트 제거
  - 퍼센트 인코딩 정돈 (unreserved 디코딩, reserved 대문자 hex 통일)
  - 경로 정규화 (빈 경로 → "/", dot-segment 해소, 연속 슬래시 축소)
  - IDN 정규화 (유니코드 → 퓨니코드 통일, 외부 위협 DB 호환)
  - 원본 보존 (NormalizeResult.original_url)
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

# RFC 3986 §2.3 — unreserved characters
_UNRESERVED: frozenset[str] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)

# 제어 문자 패턴 (C0, C1, DEL + 유니코드 제어 카테고리)
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# percent-encoded triplet 패턴
_PCT_ENCODED_RE = re.compile(r"%([0-9A-Fa-f]{2})")


def normalize_url(raw_url: str) -> NormalizeResult:
    """원본 URL을 canonical form으로 정규화합니다.

    Returns:
        NormalizeResult: original_url(trim 후 원본)과 normalized_url.

    Raises:
        NormalizationError: 검증 실패 시.
    """
    # ---- 입력 검증 ----------------------------------------------------------
    original = raw_url.strip()
    if not original:
        raise NormalizationError(message="빈 URL입니다.")

    # 제어 문자 제거
    cleaned = _CONTROL_CHAR_RE.sub("", original)
    # NFC 정규화 (유니코드 합성)
    cleaned = unicodedata.normalize("NFC", cleaned)

    # ---- 스킴 보정 (길이 검사보다 먼저 수행) ---------------------------------
    if "://" not in cleaned:
        cleaned = "https://" + cleaned

    # ---- 최대 길이 검사 (스킴 보정 후) ---------------------------------------
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

    # ---- 호스트 소문자화 + IDN 정규화 ----------------------------------------
    hostname = parsed.hostname or ""
    hostname = _normalize_idn(hostname.lower())
    if not hostname:
        raise NormalizationError(message="호스트가 비어있습니다.")

    # ---- userinfo 제거 (보안) -----------------------------------------------
    # RFC 3986 §3.2.1의 userinfo (user:pass@)를 의도적으로 삭제합니다.
    # 사유: "https://google.com@evil.com/" 처럼 합법 도메인으로 위장하는
    # 피싱 트릭에 사용되며, 브라우저도 userinfo를 무시하거나 경고합니다.
    # parsed.hostname이 실제 호스트(evil.com)를 정확히 반환하므로 안전합니다.

    # ---- 기본 포트 제거 ------------------------------------------------------
    port = parsed.port
    if port and port == _DEFAULT_PORTS.get(scheme):
        port = None
    netloc = hostname if port is None else f"{hostname}:{port}"

    # ---- 경로 정규화 (대소문자 보존) -----------------------------------------
    path = _normalize_path(parsed.path)

    # ---- params: 퍼센트 인코딩 정돈 -----------------------------------------
    params = _normalize_pct_encoding(parsed.params)

    # ---- 쿼리: 퍼센트 인코딩 정돈 -------------------------------------------
    query = _normalize_pct_encoding(parsed.query)

    # ---- 프래그먼트 제거 -----------------------------------------------------
    normalized = urlunparse((scheme, netloc, path, params, query, ""))

    return NormalizeResult(original_url=original, normalized_url=normalized)


# ---------------------------------------------------------------------------
# 내부 헬퍼
# ---------------------------------------------------------------------------


def _normalize_idn(hostname: str) -> str:
    """호스트를 퓨니코드(ASCII-compatible encoding)로 통일합니다.

    GSB·URLhaus 등 외부 위협 DB가 퓨니코드 형태로 URL을 저장하므로,
    유니코드 도메인을 퓨니코드로 변환해야 매칭이 보장됩니다.
    이미 퓨니코드(ASCII)이면 그대로 반환합니다.
    """
    try:
        return hostname.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return hostname


def _normalize_path(raw_path: str) -> str:
    """경로를 정규화합니다.

    - 빈 경로 → "/"
    - 퍼센트 인코딩 정돈
    - dot-segment 해소 (RFC 3986 §5.2.4)
    - 연속 슬래시 축소
    """
    path = raw_path or "/"

    # 퍼센트 인코딩 정돈 (경로는 대소문자 보존하므로 safe에 슬래시 포함)
    path = _normalize_pct_encoding(path)

    # 연속 슬래시 축소 — 보안 목적의 의도적 정규화.
    # RFC 상 //a와 /a는 다른 리소스이지만, 공격자가 //를 삽입해
    # 위협 DB 패턴 매칭을 우회하는 것을 방지합니다.
    path = re.sub(r"/{2,}", "/", path)

    # dot-segment 해소
    path = _resolve_dot_segments(path)

    return path or "/"


def _resolve_dot_segments(path: str) -> str:
    """RFC 3986 §5.2.4 — dot-segment를 해소합니다."""
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
    # 원래 절대 경로면 선행 빈 문자열 보장
    if path.startswith("/") and (not resolved or resolved[0] != ""):
        resolved.insert(0, "")
    return "/".join(resolved)


def _normalize_pct_encoding(value: str) -> str:
    """퍼센트 인코딩을 정돈합니다.

    - unreserved 문자(%41 → A): 디코딩
    - reserved / 기타 문자: hex를 대문자로 통일 (%2f → %2F)
    """
    if not value:
        return value

    def _replace(match: re.Match[str]) -> str:
        hex_str = match.group(1)
        char = chr(int(hex_str, 16))
        # unreserved면 디코딩
        if char in _UNRESERVED:
            return char
        # 그 외는 대문자 hex 통일
        return f"%{hex_str.upper()}"

    return _PCT_ENCODED_RE.sub(_replace, value)
