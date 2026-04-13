"""URL 정규화 데모.

사용법:
    python -m tests.demo.demo_normalize
"""

from __future__ import annotations

from app.core.exceptions import NormalizationError
from app.services.normalizer import normalize_url

DIVIDER = "-" * 72

CASES: list[tuple[str, str]] = [
    ("Scheme/host lowercasing, path case preserved", "HTTP://EXAMPLE.COM/Path/To/Page"),
    ("Default port removal (80, 443)", "https://example.com:443/secure"),
    ("Non-default port kept", "https://example.com:8080/api"),
    ("Fragment removal", "https://example.com/page#section-2"),
    ("Missing scheme defaults to https", "example.com/hello"),
    ("Unreserved pct-decode (%7E->~)", "https://example.com/%7Euser/%41%42"),
    ("Reserved hex uppercased (%2f->%2F)", "https://example.com/a%2fb%3fc"),
    ("Dot-segment resolution (/../)", "https://example.com/a/b/../c/./d"),
    ("Consecutive slash collapse", "https://example.com//a///b"),
    ("Userinfo stripped (phishing vector)", "https://google.com@evil.com/login"),
    ("Params pct-encoding normalized", "https://example.com/path;%7eparam?q=1"),
    ("IDN unicode -> punycode", "https://xn--n3h.com/path"),
    ("IDN punycode passthrough", "https://xn--n3h.com/path"),
    ("Control character removal", "https://exam\x00ple.com/pa\x01th"),
    ("Whitespace trimming", "  https://example.com/page  "),
    ("Combined", "  HTTP://EXAMPLE.COM:80/a/b/../c/./d?q=%7e&x=%2f#top  "),
]

ERROR_CASES: list[tuple[str, str]] = [
    ("Empty string", ""),
    ("Whitespace only", "   "),
    ("Unsupported scheme", "ftp2://example.com"),
    ("No host", "https://"),
    ("Exceeds max length", "https://example.com/" + "a" * 1024),
]


def main() -> None:
    print()
    print("=" * 72)
    print("  LinClean -- URL Normalization Demo")
    print("=" * 72)

    print("\n[Success cases]")
    print(DIVIDER)

    for i, (desc, raw) in enumerate(CASES, 1):
        result = normalize_url(raw)
        display_input = repr(raw) if any(ord(c) < 32 for c in raw) else raw
        print(f"  [{i:02d}] {desc}")
        print(f"       input      : {display_input}")
        print(f"       original   : {result.original_url}")
        print(f"       normalized : {result.normalized_url}")
        print(DIVIDER)

    print("\n[Error cases (NormalizationError)]")
    print(DIVIDER)

    for i, (desc, raw) in enumerate(ERROR_CASES, 1):
        display_input = repr(raw) if len(raw) > 60 else (repr(raw) if not raw.strip() else raw)
        try:
            normalize_url(raw)
            print(f"  [{i:02d}] {desc}")
            print(f"       input  : {display_input}")
            print(f"       result : WARN -- expected error not raised!")
        except NormalizationError as e:
            print(f"  [{i:02d}] {desc}")
            print(f"       input  : {display_input}")
            print(f"       error  : {e.message}")
        print(DIVIDER)

    print()


if __name__ == "__main__":
    main()
