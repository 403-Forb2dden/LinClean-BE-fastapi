"""extract_features — BS4로 title, password, meta refresh, img alt, 외부 링크 비율 추출."""

from __future__ import annotations

import pytest
from app.services.content_analyzer.extract import extract_features


class TestTitle:
    def test_title_plain(self) -> None:
        html = "<html><head><title>NAVER 로그인</title></head><body></body></html>"
        features = extract_features(html, base_url="https://evil.test/")
        assert features.title == "NAVER 로그인"

    def test_title_trimmed(self) -> None:
        html = "<html><head><title>   Kakao   </title></head></html>"
        features = extract_features(html, base_url="https://x.test/")
        assert features.title == "Kakao"

    def test_no_title(self) -> None:
        html = "<html><body>hi</body></html>"
        features = extract_features(html, base_url="https://x.test/")
        assert features.title is None


class TestPasswordField:
    def test_has_password(self) -> None:
        html = '<form><input type="password" name="pw"></form>'
        features = extract_features(html, base_url="https://x.test/")
        assert features.has_password_field is True

    def test_no_password(self) -> None:
        html = '<form><input type="text" name="id"></form>'
        features = extract_features(html, base_url="https://x.test/")
        assert features.has_password_field is False

    def test_password_type_case_insensitive(self) -> None:
        html = '<input type="PASSWORD">'
        features = extract_features(html, base_url="https://x.test/")
        assert features.has_password_field is True


class TestMetaRefresh:
    def test_has_meta_refresh(self) -> None:
        html = '<head><meta http-equiv="refresh" content="0;url=https://evil.test/x"></head>'
        features = extract_features(html, base_url="https://x.test/")
        assert features.has_meta_refresh is True

    def test_no_meta_refresh(self) -> None:
        html = '<head><meta name="description" content="ok"></head>'
        features = extract_features(html, base_url="https://x.test/")
        assert features.has_meta_refresh is False

    def test_meta_refresh_case_insensitive(self) -> None:
        html = '<meta HTTP-EQUIV="Refresh" content="5">'
        features = extract_features(html, base_url="https://x.test/")
        assert features.has_meta_refresh is True


class TestImageAlts:
    def test_collect_alts(self) -> None:
        html = '<img src="a.png" alt="NAVER"><img src="b.png" alt="Google"><img src="c.png">'
        features = extract_features(html, base_url="https://x.test/")
        assert features.image_alts == ["NAVER", "Google"]

    def test_empty_alts_ignored(self) -> None:
        html = '<img src="a.png" alt=""><img src="b.png" alt="   ">'
        features = extract_features(html, base_url="https://x.test/")
        assert features.image_alts == []

    def test_alts_capped_at_extraction(self) -> None:
        """악성 페이지가 alt 수만 개를 박아 시그널 비용을 키우지 못하게 200 상한."""
        html = "".join(f'<img alt="alt-{i}">' for i in range(1000))
        features = extract_features(html, base_url="https://x.test/")
        assert len(features.image_alts) == 200


class TestExternalLinkRatio:
    def test_all_internal(self) -> None:
        html = """
        <a href="/a">A</a>
        <a href="https://example.test/b">B</a>
        """
        features = extract_features(html, base_url="https://example.test/")
        assert features.external_link_ratio == 0.0

    def test_all_external(self) -> None:
        html = """
        <a href="https://foo.test/">F</a>
        <a href="https://bar.test/">B</a>
        """
        features = extract_features(html, base_url="https://example.test/")
        assert features.external_link_ratio == 1.0

    def test_mixed(self) -> None:
        html = """
        <a href="/a">A</a>
        <a href="https://foo.test/">F</a>
        <a href="https://bar.test/">B</a>
        <a href="https://example.test/x">X</a>
        """
        features = extract_features(html, base_url="https://example.test/")
        # 4개 중 2개 외부
        assert features.external_link_ratio == 0.5

    def test_no_anchors_returns_none(self) -> None:
        html = "<p>no links</p>"
        features = extract_features(html, base_url="https://example.test/")
        assert features.external_link_ratio is None

    def test_ignore_non_http_schemes(self) -> None:
        """javascript:/mailto:/tel: 등은 네비게이션 링크가 아니므로 분모에서 제외."""
        html = """
        <a href="javascript:void(0)">J</a>
        <a href="mailto:a@b.test">M</a>
        <a href="tel:010">T</a>
        <a href="https://foo.test/">F</a>
        """
        features = extract_features(html, base_url="https://example.test/")
        assert features.external_link_ratio == 1.0

    def test_relative_resolved_against_base(self) -> None:
        html = '<a href="subpage">S</a>'
        features = extract_features(html, base_url="https://example.test/")
        assert features.external_link_ratio == 0.0


class TestSpaShellDetection:
    def test_react_vite_shell_detected(self) -> None:
        html = (
            '<!doctype html><html><head><title>x</title>'
            '<script type="module" src="./assets/index.js"></script></head>'
            '<body><div id="root"></div></body></html>'
        )
        features = extract_features(html, base_url="https://x.test/")
        assert features.is_spa_shell is True
        assert features.has_password_field is False  # 판정 불가 상태

    def test_vue_shell_detected(self) -> None:
        html = '<html><body><div id="app"></div></body></html>'
        assert extract_features(html, base_url="https://x.test/").is_spa_shell is True

    def test_nextjs_shell_detected(self) -> None:
        html = '<html><body><div id="__next"></div></body></html>'
        assert extract_features(html, base_url="https://x.test/").is_spa_shell is True

    def test_nuxt_shell_detected(self) -> None:
        html = '<html><body><div id="__nuxt"></div></body></html>'
        assert extract_features(html, base_url="https://x.test/").is_spa_shell is True

    def test_svelte_shell_detected(self) -> None:
        html = '<html><body><div id="svelte"></div></body></html>'
        assert extract_features(html, base_url="https://x.test/").is_spa_shell is True

    def test_angular_tag_shell_detected(self) -> None:
        html = "<html><body><app-root></app-root></body></html>"
        assert extract_features(html, base_url="https://x.test/").is_spa_shell is True

    def test_ssr_page_with_form_not_flagged(self) -> None:
        """SSR 결과로 이미 form 이 존재하면 id=root 가 있어도 판정 가능 상태 — 셸 아님."""
        html = (
            '<html><body><div id="root">'
            '<form><input type="password"></form>'
            "</div></body></html>"
        )
        features = extract_features(html, base_url="https://x.test/")
        assert features.is_spa_shell is False
        assert features.has_password_field is True

    def test_static_page_without_mount_point_not_flagged(self) -> None:
        """마운트 컨테이너도 form 도 없는 일반 정적 페이지는 셸 아님 — 그냥 콘텐츠 없는 페이지."""
        html = "<html><body><p>just text</p></body></html>"
        assert extract_features(html, base_url="https://x.test/").is_spa_shell is False

    def test_input_without_form_still_disqualifies(self) -> None:
        """form 없이 input 만 있어도 '판정 불가' 는 아니다 — 정적 추출이 이미 결정적이다."""
        html = '<html><body><div id="root"><input type="text"></div></body></html>'
        assert extract_features(html, base_url="https://x.test/").is_spa_shell is False

    def test_mount_id_case_insensitive(self) -> None:
        html = '<html><body><div id="ROOT"></div></body></html>'
        assert extract_features(html, base_url="https://x.test/").is_spa_shell is True


class TestInvalidHtml:
    def test_empty_html_does_not_raise(self) -> None:
        features = extract_features("", base_url="https://x.test/")
        assert features.title is None
        assert features.has_password_field is False
        assert features.has_meta_refresh is False
        assert features.external_link_ratio is None
        assert features.image_alts == []

    def test_malformed_html_recovers(self) -> None:
        """BS4 html.parser는 깨진 HTML도 best-effort 파싱 — 예외 없이 반환."""
        html = "<html><head><title>X</title></head><body><input type='password'></body>"
        features = extract_features(html, base_url="https://x.test/")
        assert features.title == "X"
        assert features.has_password_field is True


@pytest.mark.parametrize(
    "href,expected_external",
    [
        ("/path", False),
        ("https://example.test/x", False),
        ("https://www.example.test/x", False),  # www. 서브도메인은 같은 사이트로 취급
        ("https://other.test/", True),
        ("//other.test/", True),  # protocol-relative
    ],
)
def test_external_classification(href: str, expected_external: bool) -> None:
    html = f'<a href="{href}">L</a>'
    features = extract_features(html, base_url="https://example.test/")
    if expected_external:
        assert features.external_link_ratio == 1.0
    else:
        assert features.external_link_ratio == 0.0
