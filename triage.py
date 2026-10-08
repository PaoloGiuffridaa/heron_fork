# quick phishing checker for the mail export - L. Garcia, march 2025
# TODO: make this nicer at some point
import re
import os
import pathlib
import sys

W_KEYWORD = 1
W_IP_LINK = 3
W_PUNYCODE_LINK = 3
W_BRAND_MISMATCH = 3
W_AUTH_FAIL = 2
W_REPLY_TO_MISMATCH = 2
PHISHING_THRESHOLD = 5
SUSPICIOUS_THRESHOLD = 3


KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

def check_mail(folder, flagged = None):

    scores = {}
    verdicts = []

    if flagged is None:
        flagged = []
    
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        raw = open(os.path.join(folder,fn), encoding="utf-8", errors="ignore").read()
        s = 0
        try:
            frm = re.search("From: (.*)", raw).group(1)
        except:
            frm = "?"
        try:
            subj = re.search("Subject: (.*)", raw).group(1)
        except:
            subj = "?"
        low = raw.lower()
        for kw in KEYWORDS:
            if kw in low:
                s = s + W_KEYWORD
        # links that look bad
        urls = re.findall("https?://[^\\s\"'<>]+", raw)
        for u in urls:
            if re.match("https?://[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+", u):
                s = s + W_IP_LINK  # ip address url, very bad
            if "xn--" in u:
                s = s + W_PUNYCODE_LINK
        # sender says paypal/microsoft/amazon but domain is weird
        if "paypal" in frm.lower() and "paypal.com" not in frm.lower():
            s = s + W_BRAND_MISMATCH
        if "micrpathliboft" in frm.lower() and "micrpathliboft.com" not in frm.lower():
            s = s + W_BRAND_MISMATCH
        if "amazon" in frm.lower() and "amazon.com" not in frm.lower():
            s = s + W_BRAND_MISMATCH
        if "spf=fail" in low or "dmarc=fail" in low:
            s = s + W_AUTH_FAIL
        # reply-to different from from
        try:
            rt = re.search("Reply-To: (.*)", raw).group(1)
            m1 = re.search("@([a-zA-Z0-9.-]+)", frm).group(1)
            m2 = re.search("@([a-zA-Z0-9.-]+)", rt).group(1)
            if m1 != m2:
                s = s + W_REPLY_TO_MISMATCH
        except:
            pass
        scores[fn] = s
        if s >= PHISHING_THRESHOLD:
            verdicts.append((fn, "PHISHING", s))
            flagged.append(fn)
        elif s >= SUSPICIOUS_THRESHOLD:
            verdicts.append((fn, "suspicious", s))
        else:
            verdicts.append((fn, "ok", s))
    print("checked", len(scores), "mails")
    for v in verdicts:
        print(" ", v[0], "->", v[1], "(score", str(v[2]) + ")")
    out = open("results.txt", "w")
    out.write(str(verdicts))
    out.close()
    print("flagged:", flagged)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("you have to pass a folder as argument", file=sys.stderr)
        sys.exit(2)
    check_mail(sys.argv[1])
