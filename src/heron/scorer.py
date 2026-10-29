"""Compute the indicators scores and the classification outcome"""
from typing import Callable
from heron.features import keyword_score, link_score, brand_score, auth_score, reply_to_score
from heron.models import ParsedEmail, TriageResult, Verdict


PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3

ALL_CHECKS : tuple[Callable[[ParsedEmail], int], ...]= (
    keyword_score,
    link_score,
    brand_score,
    auth_score,
    reply_to_score
)

def compute_verdict(score: int) :
    """Map a score to a verdict"""
    if score >= PHISHING_THRESHOLD:
        return Verdict.PHISHING
    elif score >= SUSPICIOUS_THRESHOLD:
        return  Verdict.SUSPICIOUS
    else:
        return Verdict.OK

def triage(email: ParsedEmail) -> TriageResult:
    """Run every check on one email and return the outcome"""
    score = sum(check(email) for check in ALL_CHECKS)
    verdict = compute_verdict(score)
    return TriageResult(
        email_id = email.email_id,
        score = score,
        verdict = verdict
    )