"""Phishing indicators: each check returns the findings of one indicator."""

import re
from collections.abc import Callable

from rapidfuzz.distance import Levenshtein

from heron.models import Finding, ParsedEmail

W_URGENCY = 2
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2

BRANDS = ["paypal", "microsoft", "amazon"]

KEYWORDS = [
    "urgent",
    "verify",
    "suspended",
    "password",
    "expires",
    "act now",
    "congratulations",
    "winner",
    "claim",
    "immediately",
    "gift card",
]

_IP_URL_RE = re.compile("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")


def levenshtein(a: str, b: str) -> int:
    """Return the number of one-character edits that turn ``a`` into ``b``."""
    return Levenshtein.distance(a, b)


def check_urgency(email: ParsedEmail) -> list[Finding]:
    """One finding, whatever the number of pressure keywords in the message."""
    hits = [kw for kw in KEYWORDS if kw in email.text]
    if not hits:
        return []
    return [Finding("urgency", ", ".join(hits), W_URGENCY)]


def check_links(email: ParsedEmail) -> list[Finding]:
    """One finding for each link to a bare IP address or to a punycode domain."""
    findings = []
    for url in email.links:
        if _IP_URL_RE.match(url):
            findings.append(Finding("ip_link", url, W_IP_LINK))
        if "xn--" in url:
            findings.append(Finding("punycode_link", url, W_PUNYCODE_LINK))
    return findings


def check_brand(email: ParsedEmail) -> list[Finding]:
    """One finding for each brand the sender claims but does not send from."""
    low = email.sender.lower()
    return [
        Finding("brand_mismatch", brand, W_BRAND_MISMATCH)
        for brand in BRANDS
        if brand in low and brand + ".com" not in low
    ]


def check_auth(email: ParsedEmail) -> list[Finding]:
    """Return a finding when SPF or DMARC failed."""
    if "spf=fail" in email.auth_results or "dmarc=fail" in email.auth_results:
        return [Finding("auth_fail", "SPF or DMARC failed", W_AUTH_FAIL)]
    return []


def check_reply_to(email: ParsedEmail) -> list[Finding]:
    """Return a finding when replies go to a different domain than the sender's."""
    sender, reply = email.from_domain, email.reply_to_domain
    if sender and reply and sender != reply:
        return [Finding("reply_to_mismatch", f"replies go to {reply}", W_REPLY_TO_MISMATCH)]
    return []


ALL_CHECKS: tuple[Callable[[ParsedEmail], list[Finding]], ...] = (
    check_urgency,
    check_links,
    check_brand,
    check_auth,
    check_reply_to,
)
