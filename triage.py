from email import message_from_string, policy
from email.utils import parseaddr
import os
import sys

W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2
PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3

BRANDS = ["paypal", "microsoft", "amazon"]

KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]


def sender_domain(header_value):
    """return the email address domain if exists, otherwise None

    Args:
        address (_type_): _description_
    """
    _, address = parseaddr(header_value)
    if "@" not in address:
        return None
    return address.split("@")[1].lower()

def compute_verdict(score):
    """Map a score to a verdict"""
    if score >= PHISHING_THRESHOLD:
        return "PHISHING"
    elif score >= SUSPICIOUS_THRESHOLD:
        return  "suspicious"
    else:
        return "ok"

def report(verdicts):
    """print the verdicts and save them in the result file"""
    print(f"checked {len(verdicts)} mails")
    for v in verdicts:
        print(" ", v[0], "->", v[1], "(score", str(v[2]) + ")")
    with open("results.txt", "w") as out:
        out.write(str(verdicts))
    
    print("flagged:", [v[0] for v in verdicts if v[1] == 'PHISHING'])

def keyword_score(raw):
    """Assign one point for easch keyword found in the email"""
    low = raw.lower()
    return sum(W_KEYWORD for kw in KEYWORDS if kw in low)

def link_score(raw):
    """Assign points for Links to Ip addresses or punycode domain."""
    s = 0
    urls = re.findall("https?://[^\\s\"'<>]+", raw)
    for u in urls:
        if re.match("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", u):
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

def score_email(raw):
    """computes the score based on the indicators, given an email"""
    msg = message_from_string(raw, policy.default)
    frm = str(msg.get("From", ""))
    reply_to = str(msg.get("Reply-To", ""))

    score = sum(keyword_score(raw), link_score(raw), brand_score(frm), auth_score(raw), reply_to_score(frm,reply_to))


def check_mail(folder):
    """Score every email file in the folder. Return (filename, verdict, score) tuples."""

    scores = {}
    verdicts = []
    
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder,fn), encoding="utf-8", errors="ignore") as raw:
            raw = raw.read()

        scores[fn] = score_email(raw)
        verdicts.append((fn, compute_verdict(scores[fn]), scores[fn])) #append a tuple of filename, verdict, score 
    return verdicts


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("you have to pass a folder as argument", file=sys.stderr)
        sys.exit(2)
    try: 
        verdicts = check_mail(sys.argv[1])
        report(verdicts)
    except FileNotFoundError:
        print("error: No such folder", file=sys.stderr)
        sys.exit(1)
    check_mail(sys.argv[1])
