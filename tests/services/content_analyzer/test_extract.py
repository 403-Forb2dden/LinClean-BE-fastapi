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

    def test_password_field_after_node_cap_still_detected(self) -> None:
        """고위험 password 탐지는 일반 노드 순회 상한으로 우회되면 안 된다."""
        padding = "".join('<input type="text">' for _ in range(1500))
        html = f"{padding}<input type='password' name='pw'>"
        features = extract_features(html, base_url="https://x.test/")
        assert features.has_password_field is True


class TestCredentialFormAction:
    def test_password_form_external_action_detected(self) -> None:
        html = (
            '<form action="https://collector.test/login">'
            '<input type="password" name="pw">'
            "</form>"
        )
        features = extract_features(html, base_url="https://example.test/login")
        assert features.has_password_form_external_action is True

    def test_password_form_same_site_action_not_external(self) -> None:
        html = '<form action="/login"><input type="password"></form>'
        features = extract_features(html, base_url="https://example.test/")
        assert features.has_password_form_external_action is False


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

    def test_external_meta_refresh_target_detected(self) -> None:
        html = '<meta http-equiv="refresh" content="0; url=https://evil.test/login">'
        features = extract_features(html, base_url="https://example.test/")
        assert features.has_meta_refresh is True
        assert features.has_external_meta_refresh is True

    def test_same_site_meta_refresh_target_not_external(self) -> None:
        html = '<meta http-equiv="refresh" content="0; url=/next">'
        features = extract_features(html, base_url="https://example.test/")
        assert features.has_meta_refresh is True
        assert features.has_external_meta_refresh is False


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


class TestHighSignalStaticFeatures:
    def test_extracts_body_text_form_fields_and_ctas(self) -> None:
        html = """
        <html>
          <head><title>고유가 피해지원금 대상 조회</title></head>
          <body>
            <main>
              <h1>국민건강보험 고유가 피해지원금 지급대상 여부 조회</h1>
              <form action="https://example.invalid/pii">
                <label for="rrn">주민등록번호</label>
                <input id="rrn" name="resident_registration_number" placeholder="주민등록번호">
                <label for="phone">휴대폰 번호</label>
                <input id="phone" name="mobile_phone" placeholder="010-0000-0000">
                <button type="button">지원금 대상 조회하기</button>
              </form>
            </main>
          </body>
        </html>
        """

        features = extract_features(html, base_url="https://nhis-support.test/")

        assert any("고유가 피해지원금" in text for text in features.body_text_snippets)
        assert any(
            "resident_registration_number" in field
            for field in features.form_field_summaries
        )
        assert any("주민등록번호" in field for field in features.form_field_summaries)
        assert "지원금 대상 조회하기" in features.cta_texts
        assert "resident_registration_number" in features.sensitive_field_types
        assert "phone" in features.sensitive_field_types
        assert "지원금" in features.korean_lure_keywords
        assert "국민건강보험" in features.public_agency_keywords

    def test_extracts_risky_download_links_and_lure_text(self) -> None:
        html = """
        <html>
          <body>
            <p>故 홍길동님의 모바일 부고장을 카카오톡으로 확인하세요.</p>
            <a href="/downloads/kakaotalk.apk" download>카카오톡 최신버전 다운로드</a>
            <a href="/notice.pdf">일반 안내문</a>
          </body>
        </html>
        """

        features = extract_features(html, base_url="https://obituary.test/")

        assert features.download_links == ["https://obituary.test/downloads/kakaotalk.apk"]
        assert "부고" in features.korean_lure_keywords
        assert "카카오톡" in features.korean_lure_keywords
        assert "카카오톡 최신버전 다운로드" in features.cta_texts

    def test_regular_js_anchor_is_not_risky_download(self) -> None:
        html = """
        <html>
          <body>
            <a href="/assets/bundle.js">bundle</a>
          </body>
        </html>
        """

        features = extract_features(html, base_url="https://normal.test/")

        assert features.download_links == []

    def test_download_js_anchor_is_risky_download(self) -> None:
        html = """
        <html>
          <body>
            <a href="/payload.js" download>download script</a>
          </body>
        </html>
        """

        features = extract_features(html, base_url="https://suspicious.test/")

        assert features.download_links == ["https://suspicious.test/payload.js"]

    def test_extraction_caps_high_signal_lists(self) -> None:
        inputs = "".join(
            f'<label for="i{i}">휴대폰 번호 {i}</label>'
            f'<input id="i{i}" name="mobile_phone_{i}" placeholder="휴대폰">'
            for i in range(200)
        )
        links = "".join(f'<a href="/app-{i}.apk">download {i}</a>' for i in range(200))
        html = f"<html><body><form>{inputs}</form>{links}</body></html>"

        features = extract_features(html, base_url="https://x.test/")

        assert len(features.form_field_summaries) <= 80
        assert len(features.download_links) <= 40
        assert len(features.body_text_snippets) <= 40


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
        assert features.has_password_form_external_action is False
        assert features.has_meta_refresh is False
        assert features.has_external_meta_refresh is False
        assert features.external_link_ratio is None
        assert features.image_alts == []

    def test_malformed_html_recovers(self) -> None:
        """BS4 + lxml 은 깨진 HTML 도 best-effort 파싱 — 예외 없이 반환."""
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
