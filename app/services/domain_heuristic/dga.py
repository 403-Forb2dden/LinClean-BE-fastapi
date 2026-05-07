from __future__ import annotations

import math

from app.core.config import settings
from app.core.tld import extract_url_parts
from app.schemas.domain_heuristic import DomainHeuristicSignal

_CONSONANTS = frozenset("bcdfghjklmnpqrstvwxyz")


_MIN_DGA_LABEL_LEN = 8  # netflix(7), spotify(7) 같은 짧은 영어 브랜드 오탐 방지


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    total = sum((count / n) * math.log2(count / n) for count in freq.values())
    return -total


def _consonant_ratio(s: str) -> float:
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters:
        return 0.0
    return sum(1 for c in letters if c in _CONSONANTS) / len(letters)


def check_dga(url: str) -> DomainHeuristicSignal | None:
    ext = extract_url_parts(url)
    label = ext.domain  # 등록 도메인 레이블
    if not label or len(label) < _MIN_DGA_LABEL_LEN:
        # 짧은 레이블은 엔트로피/자음 비율 통계가 불안정 → 스킵
        return None

    entropy = _shannon_entropy(label)
    consonant_ratio = _consonant_ratio(label)

    if (
        entropy >= settings.dga_entropy_threshold
        or consonant_ratio >= settings.dga_consonant_ratio_threshold
    ):
        return DomainHeuristicSignal.DGA_LIKE
    return None
