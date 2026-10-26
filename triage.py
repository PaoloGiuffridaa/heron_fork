import re
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

def check_mail(folder):
    """Score every email file in the folder. Return (filename, verdict, score) tuples."""

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
        verdicts.append((fn, compute_verdict(s), s)) #append a tuple of filename, verdict, score  


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
