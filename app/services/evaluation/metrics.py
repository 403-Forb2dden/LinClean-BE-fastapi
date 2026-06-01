from __future__ import annotations

from collections.abc import Iterable, Set
from dataclasses import dataclass

from app.schemas.pipeline import Verdict


@dataclass(frozen=True)
class VerdictCase:
    expected: Verdict
    predicted: Verdict


@dataclass(frozen=True)
class VerdictMetrics:
    total: int
    correct: int
    true_positive: int
    false_positive: int
    true_negative: int
    false_negative: int
    accuracy: float
    positive_precision: float
    positive_recall: float
    positive_f1: float
    false_positive_rate: float


def _ratio(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return round(numerator / denominator, 6)


def compute_verdict_metrics(
    cases: Iterable[VerdictCase],
    *,
    positive_expected: Set[Verdict],
    positive_predicted: Set[Verdict],
) -> VerdictMetrics:
    rows = list(cases)
    total = len(rows)
    correct = sum(1 for row in rows if row.expected == row.predicted)

    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0
    for row in rows:
        expected_positive = row.expected in positive_expected
        predicted_positive = row.predicted in positive_predicted
        if expected_positive and predicted_positive:
            true_positive += 1
        elif not expected_positive and predicted_positive:
            false_positive += 1
        elif expected_positive and not predicted_positive:
            false_negative += 1
        else:
            true_negative += 1

    precision = _ratio(true_positive, true_positive + false_positive)
    recall = _ratio(true_positive, true_positive + false_negative)
    f1 = (
        0.0
        if precision + recall == 0
        else round((2 * precision * recall) / (precision + recall), 6)
    )

    return VerdictMetrics(
        total=total,
        correct=correct,
        true_positive=true_positive,
        false_positive=false_positive,
        true_negative=true_negative,
        false_negative=false_negative,
        accuracy=_ratio(correct, total),
        positive_precision=precision,
        positive_recall=recall,
        positive_f1=f1,
        false_positive_rate=_ratio(false_positive, false_positive + true_negative),
    )
