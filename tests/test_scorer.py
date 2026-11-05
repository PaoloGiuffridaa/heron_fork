from heron.models import Verdict
from heron.scorer import PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD, verdict_for


def test_suspicious_threshold_is_inclusive() -> None:
    assert verdict_for(SUSPICIOUS_THRESHOLD) == Verdict.SUSPICIOUS
    assert verdict_for(SUSPICIOUS_THRESHOLD - 1) == Verdict.BENIGN


def test_phishing_threshold_is_inclusive() -> None:
    assert verdict_for(PHISHING_THRESHOLD) == Verdict.PHISHING
    assert verdict_for(PHISHING_THRESHOLD - 1) == Verdict.SUSPICIOUS
