"""Command Line Interface: `python -m heron <folder>`"""

import os
import sys

from heron.scorer import triage
from heron.parser import parse_eml
from heron.models import TriageResult, Verdict

def report(verdicts: list[TriageResult]) -> None:
    """print the verdicts and save them in the result file"""
    for v in verdicts:
        print(f"{v.email_id:<28} -> {v.verdict}, (score: {v.score})")

def check_mail(folder)-> list[TriageResult]:
    """Score every email file in the folder. Return (filename, verdict, score) tuples."""

    scores = {}
    verdicts = []
    
    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder,fn), encoding="utf-8", errors="ignore") as raw:
            raw = raw.read()
        parsed_email = parse_eml(raw, fn)
        result = triage(parsed_email)
        verdicts.append(result) 
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
