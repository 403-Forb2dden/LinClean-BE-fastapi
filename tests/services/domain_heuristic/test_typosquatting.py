from __future__ import annotations

import pytest
from app.schemas.domain_heuristic import DomainHeuristicSignal
from app.services.domain_heuristic import typosquatting
from app.services.domain_heuristic.typosquatting import _levenshtein, check_typosquatting


def test_levenshtein_same():
    assert _levenshtein("naver", "naver") == 0


def test_levenshtein_one_insert():
    assert _levenshtein("naverr", "naver") == 1


def test_levenshtein_one_substitute():
    assert _levenshtein("navcr", "naver") == 1


def test_levenshtein_two():
    assert _levenshtein("naverr", "naver") == 1
    assert _levenshtein("naaver", "naver") == 1


def test_typo_distance_1(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquatting, "_BRANDS", [("naver", "com")])
    signal = check_typosquatting("https://naverr.com/")
    assert signal == DomainHeuristicSignal.TYPO_DOMAIN


def test_typo_distance_2(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquatting, "_BRANDS", [("naver", "com")])
    signal = check_typosquatting("https://naverro.com/")
    assert signal == DomainHeuristicSignal.TYPO_DOMAIN


def test_exact_match_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquatting, "_BRANDS", [("naver", "com")])
    signal = check_typosquatting("https://naver.com/")
    assert signal is None


def test_distance_3_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquatting, "_BRANDS", [("naver", "com")])
    signal = check_typosquatting("https://naverrrr.com/")
    assert signal is None


def test_same_label_different_tld(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquatting, "_BRANDS", [("naver", "com")])
    signal = check_typosquatting("https://naver.net/")
    assert signal == DomainHeuristicSignal.TYPO_DOMAIN


def test_no_registered_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquatting, "_BRANDS", [("naver", "com")])
    signal = check_typosquatting("http://localhost/")
    assert signal is None


def test_empty_brands(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquatting, "_BRANDS", [])
    signal = check_typosquatting("https://naverr.com/")
    assert signal is None


def test_multi_tld_brand_com_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # net 먼저 등록된 브랜드라도 com 버전은 정상 도메인으로 처리
    monkeypatch.setattr(typosquatting, "_BRANDS", [("daum", "net"), ("daum", "com")])
    assert check_typosquatting("https://daum.com/") is None


def test_multi_tld_brand_tv_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # tv 먼저 등록된 브랜드라도 com 버전은 정상 도메인으로 처리
    monkeypatch.setattr(typosquatting, "_BRANDS", [("twitch", "tv"), ("twitch", "com")])
    assert check_typosquatting("https://twitch.com/") is None


def test_short_brand_no_fuzzy_match(monkeypatch: pytest.MonkeyPatch) -> None:
    # 3자 브랜드 "ing" 기준 bing.com(4자)은 편집거리 1이지만 min(3,4)<5 → 오탐 방지
    monkeypatch.setattr(typosquatting, "_BRANDS", [("ing", "com")])
    assert check_typosquatting("https://bing.com/") is None


def test_short_brand_cnn_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # 3자 브랜드 "ocn"과 cnn은 편집거리 2지만 짧은 브랜드라 오탐 방지
    monkeypatch.setattr(typosquatting, "_BRANDS", [("ocn", "com")])
    assert check_typosquatting("https://cnn.com/") is None


def test_two_char_brand_no_fuzzy(monkeypatch: pytest.MonkeyPatch) -> None:
    # 2자 브랜드 "kb"는 완전 일치 외 모두 스킵 → kbs.com 오탐 방지
    monkeypatch.setattr(typosquatting, "_BRANDS", [("kb", "co.kr")])
    assert check_typosquatting("https://kbs.com/") is None


def test_short_brand_exact_label_diff_suffix_still_flagged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # 정확히 같은 label이면 suffix 달라도 여전히 typosquat 취급 (distance 0은 길이 무관)
    monkeypatch.setattr(typosquatting, "_BRANDS", [("kb", "co.kr")])
    assert check_typosquatting("https://kb.xyz/") == DomainHeuristicSignal.TYPO_DOMAIN


def test_hosting_platform_root_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    # netlify.app 루트가 brand netlify.com과 label 일치 + suffix 상이로 오탐되던 케이스
    monkeypatch.setattr(typosquatting, "_BRANDS", [("netlify", "com")])
    assert check_typosquatting("https://netlify.app/") is None


def test_hosting_platform_root_vercel_not_flagged(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(typosquatting, "_BRANDS", [("vercel", "com")])
    assert check_typosquatting("https://vercel.app/") is None
