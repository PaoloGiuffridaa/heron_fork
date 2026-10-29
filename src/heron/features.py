"""Phishing indicators scoring functions."""
import re
from heron.parser import sender_domain

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
_URL_RE = re.compile(r"https?://[^\\s\"'<>]+")
_IP_URL_RE = re.compile(r"https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+")

def keyword_score(raw):
    """Assign one point for easch keyword found in the email"""
    low = raw.lower()
    return sum(W_KEYWORD for kw in KEYWORDS if kw in low)

def link_score(raw):
    """Assign points for Links to Ip addresses or punycode domain."""
    s = 0
    urls = re.findall(_URL_RE, raw)
    for u in urls:
        if re.match(_IP_URL_RE, u):
            s = s + W_IP_LINK  # ip address url, very bad
        if "xn--" in u:
            s = s + W_PUNYCODE_LINK
    return s

def brand_score(frm):
    """Assign points when the sender claim tho be an organization but the domain missmatch"""
    s = 0
    for brand in BRANDS:
        if brand in frm.lower() and f"{brand}.com" not in frm.lower():
            s = s + W_BRAND_MISMATCH
    return s

def auth_score(raw):
    low = raw.lower()
    """assign points when the SPF or DMARC failed"""
    if "spf=fail" in low or "dmarc=fail" in low:
        return + W_AUTH_FAIL
    return 0

def reply_to_score(frm, reply_to):
    """assign point when sender and reply-to fields missmatch"""
    from_domain = sender_domain(frm)
    reply_domain = sender_domain(reply_to) 

    if from_domain and reply_domain and (from_domain != reply_domain):
        return W_REPLY_TO_MISMATCH
    return 0

