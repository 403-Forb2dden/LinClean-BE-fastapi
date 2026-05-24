from __future__ import annotations


def test_extract_url_parts_handles_multi_label_suffix() -> None:
    from app.core.tld import extract_url_parts

    result = extract_url_parts("https://login.example.co.kr/path")

    assert result.domain == "example"
    assert result.suffix == "co.kr"
    assert result.subdomain == "login"


def test_extract_url_parts_handles_private_hosting_suffix() -> None:
    from app.core.tld import extract_url_parts

    result = extract_url_parts("https://shop-login.vercel.app/path")

    assert result.domain == "shop-login"
    assert result.suffix == "vercel.app"
    assert result.top_domain_under_public_suffix == "shop-login.vercel.app"
