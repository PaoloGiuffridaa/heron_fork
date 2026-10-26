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

BRANDS = ["paypal", "microsoft", "amazon"]


KEYWORDS = ["urgent", "verify", "suspended", "password", "expires", "act now",
            "congratulations", "winner", "claim", "immediately", "gift card"]

def header(raw, name):
    """_Return the value of the first occurence of the "name:" pattern in the email header, or '?' if missing

    Args:
        raw (file): the file where the pattern is searched
        name (str): the pattern to search 

    Returns:
        str: "?" is there in no match, otherwise the row matched
    """
    match = re.search(name + ': (.*)', raw) # (.*) means takes everithing after that and before a newline
    if match is None:
        return "?"
    else:
        return match.group(1)

def sender_domain(address):
    """return the email address domain if exists, otherwise None

    Args:
        address (_type_): _description_
    """
    match = re.search("@([a-zA-Z0-9.-]+)", address)
    if match is None:
        return None
    return match.group(1)

def check_mail(folder, flagged = None):

    scores = {}
    verdicts = []

    if flagged is None:
        flagged = []
    
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder,fn), encoding="utf-8", errors="ignore") as raw:
            raw.read()
            
        s = 0
        
        frm = header(raw, "From")
        subj = header(raw, "Subject")

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
        for brand in BRANDS:
            if brand in frm.lower() and f"{brand}.com" not in frm.lower():
                s = s + W_BRAND_MISMATCH

        if "spf=fail" in low or "dmarc=fail" in low:
            s = s + W_AUTH_FAIL

        # reply-to different from from
        from_domain = sender_domain(frm)
        reply_domain = sender_domain(header(raw, "Reply-To")) #we first extract the Reply-To field

        if from_domain and reply_domain and (from_domain != reply_domain):
            s = s + W_REPLY_TO_MISMATCH

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

    with open("results.txt", "w") as out:
        out.write(str(verdicts))
    
    print("flagged:", flagged)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("you have to pass a folder as argument", file=sys.stderr)
        sys.exit(2)
    try: 
        check_mail(sys.argv[1])
    except FileNotFoundError:
        print("error: No such folder", file=sys.stderr)
        sys.exit(1)
    check_mail(sys.argv[1])
