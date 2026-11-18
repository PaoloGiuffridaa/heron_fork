import pytest

from heron.features import (
    W_AUTH_FAIL,
    W_BRAND_MISMATCH,
    W_EXECUTABLE_LINK,
    W_LOOKALIKE_SENDER,
    W_REPLY_TO_MISMATCH,
    W_URGENCY,
    check_auth,
    check_brand,
    check_executable_link,
    check_links,
    check_lookalike_sender,
    check_reply_to,
    check_urgency,
)
from tests.helpers import make_email


def test_urgency_fires_once_for_many_keywords() -> None:
    email = make_email(text="urgent: verify your password immediately")

    findings = check_urgency(email)

    assert [f.code for f in findings] == ["urgency"]
    assert findings[0].weight == W_URGENCY


def test_urgency_is_silent_without_keywords() -> None:
    assert check_urgency(make_email()) == []


def test_reply_to_fires_for_another_domain() -> None:
    email = make_email(reply_to_domain="mail-verify.net")

    findings = check_reply_to(email)

    assert [(f.code, f.weight) for f in findings] == [("reply_to_mismatch", W_REPLY_TO_MISMATCH)]


def test_reply_to_is_silent_when_a_domain_is_missing() -> None:
    assert check_reply_to(make_email(reply_to_domain=None)) == []
    assert check_reply_to(make_email(from_domain=None, reply_to_domain="x.example")) == []


@pytest.mark.parametrize(
    ("links", "codes"),
    [
        (("http://192.0.2.44/login",), ["ip_link"]),
        (("https://xn--pypal-4ve.com/signin",), ["punycode_link"]),
        (("https://www.example.com/news",), []),
        (("http://192.0.2.1/a", "http://192.0.2.2/b"), ["ip_link", "ip_link"]),
    ],
    ids=["bare-ip", "punycode", "plain", "two-ip-links"],
)
def test_check_links(links: tuple[str, ...], codes: list[str]) -> None:
    assert [f.code for f in check_links(make_email(links=links))] == codes


def test_brand_fires_when_the_sender_claims_a_brand_it_does_not_send_from() -> None:
    email = make_email(sender="PayPal Support <security@paypa1-secure.net>")
    assert [(f.code, f.detail, f.weight) for f in check_brand(email)] == [
        ("brand_mismatch", "paypal", W_BRAND_MISMATCH)
    ]


def test_brand_is_silent_for_the_real_domain() -> None:
    assert check_brand(make_email(sender="PayPal <service@paypal.com>")) == []


def test_brand_gives_one_finding_per_claimed_brand() -> None:
    email = make_email(sender="Amazon and Microsoft deals <deals@shop.example>")
    assert [f.detail for f in check_brand(email)] == ["microsoft", "amazon"]


@pytest.mark.parametrize(
    ("auth_results", "fires"),
    [("spf=fail; dmarc=pass", True), ("spf=pass; dmarc=pass", False), ("spf=softfail", False)],
    ids=["spf-fail", "all-pass", "softfail-is-not-fail"],
)
def test_check_auth(auth_results: str, fires: bool) -> None:
    findings = check_auth(make_email(auth_results=auth_results))
    assert [(f.code, f.weight) for f in findings] == ([("auth_fail", W_AUTH_FAIL)] if fires else [])


@pytest.mark.parametrize(
    ("domain", "details"),
    [
        ("paypa1-secure.net", ["paypa1 imitates paypal"]),
        ("xn--microsft-w2c.com", ["microsft imitates microsoft"]),
        ("arnazon.example", ["arnazon imitates amazon"]),
        ("paypal.com", []),
        ("marketing-blast.example", []),
        (None, []),
    ],
    ids=["one-char", "missing-char", "two-edits", "the-brand-itself", "unrelated", "no-domain"],
)
def test_check_lookalike_sender(domain: str | None, details: list[str]) -> None:
    findings = check_lookalike_sender(make_email(from_domain=domain))
    assert [f.detail for f in findings] == details
    assert all(f.weight == W_LOOKALIKE_SENDER for f in findings)


def test_executable_link_fires_for_a_program_but_not_for_a_page() -> None:
    email = make_email(
        links=("https://files.example/invoice.pdf.exe", "https://example.com/a.html")
    )
    assert [(f.code, f.detail, f.weight) for f in check_executable_link(email)] == [
        ("executable_link", "https://files.example/invoice.pdf.exe", W_EXECUTABLE_LINK)
    ]
