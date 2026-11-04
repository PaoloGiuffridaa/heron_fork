"""Command Line Interface: `python -m heron <folder>`"""

import argparse
import json
import os
import re  # noqa: F401
import sys
from dataclasses import asdict

from heron.models import TriageResult
from heron.parser import parse_eml
from heron.scorer import triage


def build_parser() -> argparse.ArgumentParser:
    """return the parser of the CLI arguments

    Returns
    -------
    argparse.ArgumentParser
        The parser of the CLI arguments
    """
    parser = argparse.ArgumentParser(prog="heron", description="Triage of phising email.")
    parser.add_argument("folder", help="a folder containing `.eml` files")
    parser.add_argument(
        "--json",
        action="store_true",  # if the argument is passed the arg is == True
        help="machine readable output",
    )
    return parser


def report(verdicts: list[TriageResult]) -> None:
    """print the verdicts and save them in the result file"""
    for v in verdicts:
        print(f"{v.email_id:<28} -> {v.verdict}, (score: {v.score})")


def check_mail(folder: str) -> list[TriageResult]:
    """Score every email file in the folder. Return (filename, verdict, score) tuples."""

    verdicts = []

    files = os.listdir(folder)
    for fn in files:
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(folder, fn), encoding="utf-8", errors="ignore") as raw:
            raw_email = raw.read()
        parsed_email = parse_eml(raw_email, fn)
        result = triage(parsed_email)
        verdicts.append(result)
    return verdicts


def main(argv: list[str] | None = None) -> None:
    """run the triange on the given folder"""
    args = build_parser().parse_args(argv)
    try:
        verdicts = check_mail(args.folder)
        if args.json:
            with open("output.json", "w") as f:
                json.dump([asdict(v) for v in verdicts], f)
        report(verdicts)
    except FileNotFoundError:
        print("error: No such folder", file=sys.stderr)
