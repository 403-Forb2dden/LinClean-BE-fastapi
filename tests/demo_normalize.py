"""URL 정규화 데모

Usage:
    python -m tests.demo_normalize
"""

from __future__ import annotations

from app.core.exceptions import NormalizationError
from app.services.normalizer import normalize_url

DIVIDER = "─" * 72

CASES: list[tuple[str, str]] = [
    # (설명, 입력 URL)
    ("스킴·호스트 소문자화 + 경로 대소문자 보존", "HTTP://EXAMPLE.COM/Path/To/Page"),
    ("기본 포트 제거 (80, 443)", "https://example.com:443/secure"),
    ("비기본 포트 유지", "https://example.com:8080/api"),
    ("프래그먼트 제거", "https://example.com/page#section-2"),
    ("스킴 없으면 https 보정", "example.com/hello"),
    ("퍼센트 인코딩: unreserved 디코딩 (%7E→~)", "https://example.com/%7Euser/%41%42"),
    ("퍼센트 인코딩: reserved 대문자 hex 통일 (%2f→%2F)", "https://example.com/a%2fb%3fc"),
    ("경로 dot-segment 해소 (/../)", "https://example.com/a/b/../c/./d"),
    ("연속 슬래시 축소 (보안: DB 매칭 우회 방지)", "https://example.com//a///b"),
    ("userinfo 제거 (피싱: google.com@evil.com)", "https://google.com@evil.com/login"),
    ("params 퍼센트 인코딩 정돈", "https://example.com/path;%7eparam?q=1"),
    ("IDN 유니코드 → 퓨니코드 통일 (외부 DB 호환)", "https://☃.com/path"),
    ("IDN 퓨니코드 유지", "https://xn--n3h.com/path"),
    ("제어 문자 제거", "https://exam\x00ple.com/pa\x01th"),
    ("공백 trim", "  https://example.com/page  "),
    ("종합", "  HTTP://EXAMPLE.COM:80/a/b/../c/./d?q=%7e&x=%2f#top  "),
]

ERROR_CASES: list[tuple[str, str]] = [
    ("빈 문자열", ""),
    ("공백만", "   "),
    ("지원하지 않는 스킴", "ftp2://example.com"),
    ("호스트 없음", "https://"),
    ("최대 길이 초과", "https://example.com/" + "a" * 2048),
]


def main() -> None:
    print()
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                 LinClean — URL Normalization Test                    ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")

    # ── 정상 케이스 ──────────────────────────────────────────────────────────
    print()
    print("■ 정상 케이스")
    print(DIVIDER)

    for i, (desc, raw) in enumerate(CASES, 1):
        result = normalize_url(raw)
        # 제어 문자가 포함된 입력은 repr로 표시
        display_input = repr(raw) if any(ord(c) < 32 for c in raw) else raw
        print(f"  [{i:02d}] {desc}")
        print(f"       입력  → {display_input}")
        print(f"       원본  → {result.original_url}")
        print(f"       정규화 → {result.normalized_url}")
        print(DIVIDER)

    # ── 에러 케이스 ──────────────────────────────────────────────────────────
    print()
    print("■ 에러 케이스 (NormalizationError)")
    print(DIVIDER)

    for i, (desc, raw) in enumerate(ERROR_CASES, 1):
        display_input = repr(raw) if len(raw) > 60 else (repr(raw) if not raw.strip() else raw)
        try:
            normalize_url(raw)
            print(f"  [{i:02d}] {desc}")
            print(f"       입력 → {display_input}")
            print(f"       결과 → ⚠ 예외가 발생하지 않음!")
        except NormalizationError as e:
            print(f"  [{i:02d}] {desc}")
            print(f"       입력 → {display_input}")
            print(f"       에러 → {e.message}")
        print(DIVIDER)

    print()


if __name__ == "__main__":
    main()
