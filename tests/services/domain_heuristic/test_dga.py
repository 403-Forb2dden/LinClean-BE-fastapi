from __future__ import annotations

import pytest
from app.schemas.domain_heuristic import DomainHeuristicSignal
from app.services.domain_heuristic.dga import (
    _consonant_ratio,
    _shannon_entropy,
    check_dga,
)


def test_shannon_entropy_uniform() -> None:
    # 모든 문자가 동일하면 엔트로피 0
    assert _shannon_entropy("aaaa") == pytest.approx(0.0)


def test_shannon_entropy_high() -> None:
    # 무작위 문자열은 엔트로피 높음
    entropy = _shannon_entropy("xkzqjvpm")
    assert entropy >= 3.0


def test_shannon_entropy_empty() -> None:
    assert _shannon_entropy("") == 0.0


def test_consonant_ratio_all_consonants() -> None:
    ratio = _consonant_ratio("bxkrptmn")
    assert ratio == pytest.approx(1.0)


def test_consonant_ratio_all_vowels() -> None:
    ratio = _consonant_ratio("aeiou")
    assert ratio == pytest.approx(0.0)


def test_consonant_ratio_empty() -> None:
    assert _consonant_ratio("") == 0.0


def test_dga_high_entropy_flagged() -> None:
    # "xkzqjvpmbn" — 높은 엔트로피 + 자음 비율
    signal = check_dga("https://xkzqjvpmbn.com/")
    assert signal == DomainHeuristicSignal.DGA_LIKE


def test_dga_normal_domain_not_flagged() -> None:
    signal = check_dga("https://naver.com/")
    assert signal is None


def test_dga_google_not_flagged() -> None:
    signal = check_dga("https://google.com/")
    assert signal is None


def test_dga_high_consonant_ratio() -> None:
    # "bxkrptmnsdf" — 자음 비율 > 0.6
    signal = check_dga("https://bxkrptmnsdf.com/")
    assert signal == DomainHeuristicSignal.DGA_LIKE


def test_dga_ip_url_not_flagged() -> None:
    # IP URL — 도메인 레이블 없음
    signal = check_dga("http://192.168.1.1/")
    assert signal is None


def test_dga_uses_registered_domain_label() -> None:
    # 서브도메인 무시, 등록 도메인 레이블만 분석
    # "naver"는 정상 엔트로피 → 미발동
    signal = check_dga("https://login.naver.com/")
    assert signal is None


def test_dga_entropy_only_triggers() -> None:
    # 자음 비율 < 0.8이지만 Shannon 엔트로피 >= 3.5 → DGA_LIKE 발동
    # "aeioubcdfghj": 12개 고유 문자, 엔트로피=3.585, 자음 비율=0.583
    signal = check_dga("https://aeioubcdfghj.com/")
    assert signal == DomainHeuristicSignal.DGA_LIKE


def test_dga_short_label_skipped() -> None:
    # 레이블 < 8자는 통계 신뢰도 낮아 스킵 — netflix/spotify 오탐 방지
    assert check_dga("https://netflix.com/") is None
    assert check_dga("https://spotify.com/") is None
    assert check_dga("https://samsung.com/") is None


def test_dga_consonant_ratio_below_new_threshold() -> None:
    # "snapchat" 8자, 자음 비율 6/8=0.75 < 0.8 → 미발동
    assert check_dga("https://snapchat.com/") is None


def test_dga_long_dga_like_still_flagged() -> None:
    # 8자 이상 + 자음 비율 >= 0.8 → 여전히 발동
    assert check_dga("https://bxkrptmnsdf.com/") == DomainHeuristicSignal.DGA_LIKE
