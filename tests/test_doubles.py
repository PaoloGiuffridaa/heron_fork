import pytest

from heron import scorer
from heron.models import Finding, ParsedEmail, Verdict
from tests.helpers import make_email


def always_flag(email: ParsedEmail) -> list[Finding]:
    """A stub check: it fires on every message."""
    return [Finding("stub", "always fires", 7)]


def test_monkeypatch_replaces_the_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scorer, "ALL_CHECKS", (always_flag,))

    result = scorer.triage(make_email())

    assert result.verdict == Verdict.PHISHING
    assert [f.code for f in result.findings] == ["stub"]
