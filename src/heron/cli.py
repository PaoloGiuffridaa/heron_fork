"""Command Line Interface: `python -m heron <folder>`"""

import os
import sys

from heron.scorer import compute_verdict, score_email

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
    
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder,fn), encoding="utf-8", errors="ignore") as raw:
            raw = raw.read()
        
        scores[fn] = score_email(raw)
        verdicts.append((fn, compute_verdict(scores[fn]), scores[fn])) #append a tuple of filename, verdict, score 
    return verdicts

def main(argv: list[str] | None = None):
    """run the triange on the given folder"""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("you have to pass a folder as argument", file=sys.stderr)
        sys.exit(2)
    try: 
        verdicts = check_mail(sys.argv[1])
        report(verdicts)
    except FileNotFoundError:
        print("error: No such folder", file=sys.stderr)
