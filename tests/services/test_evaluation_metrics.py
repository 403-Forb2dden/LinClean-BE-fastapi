from __future__ import annotations

from app.schemas.pipeline import Verdict
from app.services.evaluation.metrics import VerdictCase, compute_verdict_metrics


def test_compute_verdict_metrics_for_detection_goal() -> None:
    cases = [
        VerdictCase(expected=Verdict.DANGER, predicted=Verdict.DANGER),
        VerdictCase(expected=Verdict.DANGER, predicted=Verdict.DANGER),
        VerdictCase(expected=Verdict.DANGER, predicted=Verdict.CAUTION),
        VerdictCase(expected=Verdict.DANGER, predicted=Verdict.SAFE),
        VerdictCase(expected=Verdict.SAFE, predicted=Verdict.SAFE),
        VerdictCase(expected=Verdict.SAFE, predicted=Verdict.SAFE),
        VerdictCase(expected=Verdict.SAFE, predicted=Verdict.CAUTION),
        VerdictCase(expected=Verdict.SAFE, predicted=Verdict.DANGER),
    ]

    metrics = compute_verdict_metrics(
        cases,
        positive_expected={Verdict.DANGER},
        positive_predicted={Verdict.DANGER, Verdict.CAUTION},
    )

    assert metrics.total == 8
    assert metrics.accuracy == 0.5
    assert metrics.positive_recall == 0.75
    assert metrics.positive_precision == 0.6
    assert metrics.positive_f1 == 0.666667
    assert metrics.false_positive_rate == 0.5
