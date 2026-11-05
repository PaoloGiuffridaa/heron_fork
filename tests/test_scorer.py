from heron.models import ParsedEmail, Verdict
from heron.scorer import PHISHING_THRESHOLD, SUSPICIOUS_THRESHOLD, triage, verdict_for


def test_suspicious_threshold_is_inclusive() -> None:
    assert verdict_for(SUSPICIOUS_THRESHOLD) == Verdict.SUSPICIOUS
    assert verdict_for(SUSPICIOUS_THRESHOLD - 1) == Verdict.BENIGN


def test_phishing_threshold_is_inclusive() -> None:
    assert verdict_for(PHISHING_THRESHOLD) == Verdict.PHISHING
    assert verdict_for(PHISHING_THRESHOLD - 1) == Verdict.SUSPICIOUS


def test_a_harmless_message_scores_zero(benign_email: ParsedEmail) -> None:
    result = triage(benign_email)
    assert result.score == 0
    assert result.verdict == Verdict.BENIGN
    assert result.findings == ()


def test_fixtures_are_injected_by_name(
    benign_email: ParsedEmail, phishing_email: ParsedEmail
) -> None:
    assert triage(benign_email).verdict == Verdict.BENIGN
    assert triage(phishing_email).verdict == Verdict.PHISHING
