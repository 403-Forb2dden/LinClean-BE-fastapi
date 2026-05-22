"""signals.py — 규칙 기반 점수표."""

from __future__ import annotations

from app.core.config import settings
from app.schemas.content_analysis import ContentSignal
from app.services.content_analyzer.extract import ExtractedFeatures
from app.services.content_analyzer.signals import score_content


def _features(**kwargs: object) -> ExtractedFeatures:
    base = {
        "title": None,
        "has_password_field": False,
        "has_password_form_external_action": False,
        "has_meta_refresh": False,
        "has_external_meta_refresh": False,
        "external_link_ratio": None,
        "image_alts": [],
    }
    base.update(kwargs)
    return ExtractedFeatures(**base)  # type: ignore[arg-type]


class TestBrandImpersonationForm:
    def test_password_with_brand_in_title_on_unrelated_domain(self) -> None:
        features = _features(
            title="NAVER 로그인",
            has_password_field=True,
        )
        result = score_content(features, final_url="https://evil-naver.test/signin")
        assert ContentSignal.BRAND_IMPERSONATION_FORM in result.signals
        assert result.brand_impersonation is True
        assert result.score >= settings.score_weight_brand_impersonation

    def test_password_with_brand_matching_own_domain_is_not_impersonation(self) -> None:
        features = _features(
            title="NAVER 로그인",
            has_password_field=True,
        )
        result = score_content(features, final_url="https://naver.com/login")
        assert ContentSignal.BRAND_IMPERSONATION_FORM not in result.signals
        assert result.brand_impersonation is False

    def test_password_without_brand_in_title_not_impersonation(self) -> None:
        features = _features(
            title="일반 로그인 페이지",
            has_password_field=True,
        )
        result = score_content(features, final_url="https://something.test/")
        assert ContentSignal.BRAND_IMPERSONATION_FORM not in result.signals

    def test_no_password_even_with_brand_title_not_brand_form(self) -> None:
        features = _features(title="NAVER 소개", has_password_field=False)
        result = score_content(features, final_url="https://evil.test/")
        assert ContentSignal.BRAND_IMPERSONATION_FORM not in result.signals


class TestBrandMatchingFalsePositives:
    """영문 라벨은 단어 경계 매칭이라 substring 우연 매치를 일으키지 않아야 한다."""

    def test_pineapple_does_not_match_apple(self) -> None:
        """과거 substring 매칭에서 pineapple → apple 로 잡히던 케이스."""
        features = _features(title="Pineapple Express", has_password_field=True)
        result = score_content(features, final_url="https://pineapple-shop.test/")
        assert ContentSignal.BRAND_IMPERSONATION_FORM not in result.signals
        assert result.brand_impersonation is False

    def test_naverstore_does_not_match_naver(self) -> None:
        features = _features(title="naverstore login", has_password_field=True)
        result = score_content(features, final_url="https://other.test/")
        assert ContentSignal.BRAND_IMPERSONATION_FORM not in result.signals

    def test_googleblog_alt_does_not_match_google(self) -> None:
        features = _features(image_alts=["googleblog tutorials"])
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.LOGO_ALT_IMPERSONATION not in result.signals

    def test_word_boundary_still_matches_with_punctuation(self) -> None:
        # 경계 매칭이라 'NAVER 로그인', 'naver,', 'naver/login' 같은 자연 등장은 그대로 매치
        for title in ["NAVER 로그인", "naver, hello", "Login to naver."]:
            features = _features(title=title, has_password_field=True)
            result = score_content(features, final_url="https://evil.test/")
            assert ContentSignal.BRAND_IMPERSONATION_FORM in result.signals, title


class TestLogoAltImpersonation:
    def test_brand_in_alt_on_unrelated_domain(self) -> None:
        features = _features(image_alts=["KakaoTalk 로고"])
        result = score_content(features, final_url="https://phish.test/")
        assert ContentSignal.LOGO_ALT_IMPERSONATION in result.signals
        assert result.logo_alt_impersonation is True
        assert result.score >= settings.score_weight_logo_alt_impersonation

    def test_brand_in_alt_matching_own_domain(self) -> None:
        features = _features(image_alts=["kakao logo"])
        result = score_content(features, final_url="https://kakao.com/")
        assert ContentSignal.LOGO_ALT_IMPERSONATION not in result.signals

    def test_no_alt_text(self) -> None:
        features = _features(image_alts=[])
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.LOGO_ALT_IMPERSONATION not in result.signals


class TestMetaRefresh:
    def test_meta_refresh_adds_score(self) -> None:
        features = _features(has_meta_refresh=True)
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.META_REFRESH in result.signals
        assert result.score == settings.score_weight_meta_refresh

    def test_external_meta_refresh_adds_stronger_signal(self) -> None:
        features = _features(has_meta_refresh=True, has_external_meta_refresh=True)
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.META_REFRESH in result.signals
        assert ContentSignal.EXTERNAL_META_REFRESH in result.signals
        assert result.score == (
            settings.score_weight_meta_refresh
            + settings.score_weight_external_meta_refresh
        )


class TestCredentialFormExternalAction:
    def test_external_password_form_action_adds_score(self) -> None:
        features = _features(
            has_password_field=True,
            has_password_form_external_action=True,
        )
        result = score_content(features, final_url="https://example.test/")
        assert ContentSignal.CREDENTIAL_FORM_EXTERNAL in result.signals
        assert result.score == settings.score_weight_credential_form_external


class TestExternalLinkOveruse:
    def test_above_threshold_signals(self) -> None:
        features = _features(external_link_ratio=0.9)
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.EXTERNAL_LINK_OVERUSE in result.signals
        assert result.score == settings.score_weight_external_link_overuse

    def test_at_threshold_signals(self) -> None:
        features = _features(
            external_link_ratio=settings.content_external_link_ratio_threshold,
        )
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.EXTERNAL_LINK_OVERUSE in result.signals

    def test_below_threshold_no_signal(self) -> None:
        features = _features(external_link_ratio=0.3)
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.EXTERNAL_LINK_OVERUSE not in result.signals

    def test_none_ratio_no_signal(self) -> None:
        features = _features(external_link_ratio=None)
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.EXTERNAL_LINK_OVERUSE not in result.signals


class TestHighSignalKoreanPhishingRules:
    def test_public_agency_subsidy_resident_number_form_scores_strongly(self) -> None:
        features = _features(
            title="고유가 피해지원금 대상 여부 조회",
            body_text_snippets=["국민건강보험 고유가 피해지원금 지급대상 여부를 조회하세요."],
            form_field_summaries=[
                "label=주민등록번호 name=resident_registration_number placeholder=주민등록번호",
                "label=휴대폰 번호 name=mobile_phone placeholder=010-0000-0000",
            ],
            cta_texts=["지원금 대상 조회하기"],
            sensitive_field_types=["resident_registration_number", "phone"],
            korean_lure_keywords=["지원금"],
            public_agency_keywords=["국민건강보험"],
        )

        result = score_content(features, final_url="https://nhis-support.test/")

        assert ContentSignal.PII_COLLECTION_FORM in result.signals
        assert ContentSignal.SENSITIVE_ID_FIELD in result.signals
        assert ContentSignal.PUBLIC_AGENCY_LURE in result.signals
        assert ContentSignal.KOREAN_LURE_TEXT in result.signals
        assert result.score >= settings.score_danger_threshold

    def test_kakao_obituary_apk_download_scores_without_credentials(self) -> None:
        features = _features(
            body_text_snippets=["故 홍길동님의 모바일 부고장을 카카오톡으로 확인하세요."],
            cta_texts=["카카오톡 최신버전 다운로드"],
            download_links=["https://obituary.test/downloads/kakaotalk.apk"],
            korean_lure_keywords=["부고", "카카오톡"],
        )

        result = score_content(features, final_url="https://obituary.test/")

        assert ContentSignal.RISKY_DOWNLOAD_LINK in result.signals
        assert ContentSignal.KOREAN_LURE_TEXT in result.signals
        assert ContentSignal.PII_COLLECTION_FORM not in result.signals
        assert result.score >= settings.score_caution_threshold

    def test_financial_card_fields_score_but_readonly_free_text_alone_does_not(self) -> None:
        readonly_like_text_only = _features(
            body_text_snippets=["카드번호, CVC, 만료일 안내"],
            korean_lure_keywords=[],
        )
        text_result = score_content(readonly_like_text_only, final_url="https://safe.test/")
        assert ContentSignal.FINANCIAL_FIELD not in text_result.signals
        assert text_result.score == 0

        actual_form = _features(
            form_field_summaries=[
                "label=카드번호 name=card_number placeholder=카드번호 16자리",
                "label=CVC name=card_cvc placeholder=CVC",
            ],
            sensitive_field_types=["card", "cvc"],
        )
        form_result = score_content(actual_form, final_url="https://pay-check.test/")
        assert ContentSignal.FINANCIAL_FIELD in form_result.signals
        assert form_result.score >= settings.score_weight_financial_field

    def test_legitimate_login_with_birthdate_guidance_does_not_gain_new_scores(self) -> None:
        features = _features(
            title="명지대학교 통합로그인",
            has_password_field=True,
            body_text_snippets=[
                "최초 사용자는 주민등록 기재된 생년월일 6자리 입력 후 비밀번호를 변경해야 함"
            ],
            form_field_summaries=[
                "label=아이디 name=id placeholder=아이디",
                "label=비밀번호 name=pw type=password placeholder=비밀번호",
            ],
            cta_texts=["로그인"],
            sensitive_field_types=[],
            korean_lure_keywords=[],
            public_agency_keywords=[],
        )

        result = score_content(features, final_url="https://sso.mju.ac.kr/")

        assert ContentSignal.PII_COLLECTION_FORM not in result.signals
        assert ContentSignal.SENSITIVE_ID_FIELD not in result.signals
        assert ContentSignal.KOREAN_LURE_TEXT not in result.signals
        assert result.score == 0


class TestSpaShellSignal:
    def test_spa_shell_emits_signal_without_score(self) -> None:
        """판정 불가 플래그라 점수는 0, 시그널 코드만 올라간다."""
        features = _features(is_spa_shell=True)
        result = score_content(features, final_url="https://x.test/")
        assert ContentSignal.SPA_SHELL in result.signals
        assert result.score == 0

    def test_spa_shell_does_not_interfere_with_other_rules(self) -> None:
        """SPA 셸이어도 alt 브랜드 위장 같은 규칙은 정상 집계된다 (드문 케이스지만 방어)."""
        features = _features(is_spa_shell=True, image_alts=["NAVER"])
        result = score_content(features, final_url="https://evil.test/")
        assert ContentSignal.SPA_SHELL in result.signals
        assert ContentSignal.LOGO_ALT_IMPERSONATION in result.signals
        assert result.score == settings.score_weight_logo_alt_impersonation


class TestCombinedScoring:
    def test_all_signals_sum(self) -> None:
        features = _features(
            title="NAVER 로그인",
            has_password_field=True,
            has_meta_refresh=True,
            external_link_ratio=0.95,
            image_alts=["NAVER"],
        )
        result = score_content(features, final_url="https://evil.test/")
        expected = (
            settings.score_weight_brand_impersonation
            + settings.score_weight_logo_alt_impersonation
            + settings.score_weight_meta_refresh
            + settings.score_weight_external_link_overuse
        )
        assert result.score == min(expected, settings.content_analysis_score_cap)

    def test_score_cap(self) -> None:
        """합산 점수가 cap을 넘지 않는다."""
        features = _features(
            title="NAVER 로그인",
            has_password_field=True,
            has_meta_refresh=True,
            external_link_ratio=0.95,
            image_alts=["NAVER"],
        )
        result = score_content(features, final_url="https://evil.test/")
        assert result.score <= settings.content_analysis_score_cap
