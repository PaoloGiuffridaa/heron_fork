"""Phishing indicators scoring functions."""
import re
from heron.models import ParsedEmail

#__all__ = ["keyword_score", "link_score", "brand_score", "auth_score", "reply_to_score"]    #if the code scales is not mantainable, avoid use this

W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2

BRANDS = ["paypal", "microsoft", "amazon"]

KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

#we want to compute path only one time (is computationally expensive) and reuse it in the scoring functions
_IP_URL_RE = re.compile(r"https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")

def keyword_score(email: ParsedEmail) -> int:
    """Assign one point for easch keyword found in the email"""
    return sum(W_KEYWORD for kw in KEYWORDS if kw in email.text)

def link_score(email: ParsedEmail) -> int:
    """Assign points for Links to Ip addresses or punycode domain."""
    s = 0
    for u in email.links:
        if re.match(_IP_URL_RE, u):
            s = s + W_IP_LINK  # ip address url, very bad
        if "xn--" in u:
            s = s + W_PUNYCODE_LINK
    return s

def brand_score(email: ParsedEmail) -> int:
    """Assign points when the sender claim tho be an organization but the domain missmatch"""
    s = 0
    low = email.sender.lower()
    for brand in BRANDS:
        if brand in low and f"{brand}.com" not in low:
            s = s + W_BRAND_MISMATCH
    return s

def auth_score(email: ParsedEmail) -> int:
    """assign points when the SPF or DMARC failed"""
    if "spf=fail" in email.auth_result or "dmarc=fail" in email.auth_result:
        return + W_AUTH_FAIL
    return 0

def reply_to_score(email: ParsedEmail) -> int:
    """assign point when sender and reply-to fields missmatch"""


    if email.from_domain and email.reply_to_domain and (email.from_domain != email.reply_to_domain):
        return W_REPLY_TO_MISMATCH
    return 0

