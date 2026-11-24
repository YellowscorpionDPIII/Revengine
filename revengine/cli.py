"""RevEngine CLI.

  revengine score <binary> [--json]     B: reversibility score + fixes.
  revengine probe <binary> --i-am-authorized [--json]   A: internal probe.

`score` needs no authorisation: it only reports on hardening posture.
`probe` requires --i-am-authorized (see authz.py).
"""

from __future__ import annotations

import argparse
import json
import sys

from .checks import analyze
from .scorer import score
from .attacker import probe
from .authz import AuthorizationError
from .llm import LocalLlamaClient


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="revengine")
    sub = parser.add_subparsers(dest="command", required=True)

    p_score = sub.add_parser("score", help="Score a build's reversibility (B).")
    p_score.add_argument("binary")
    p_score.add_argument("--json", action="store_true")

    p_probe = sub.add_parser("probe", help="Internal behaviour probe (A).")
    p_probe.add_argument("binary")
    p_probe.add_argument("--i-am-authorized", action="store_true",
                         help="Confirm you own this binary or are "
                         "authorised to analyse it.")
    p_probe.add_argument("--llm", action="store_true",
                         help="Draft a narrative via REVENGINE_LLM_URL.")
    p_probe.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)

    if args.command == "score":
        analysis = analyze(args.binary)
        result = score(analysis)
        if args.json:
            print(json.dumps({
                "path": args.binary, **result.to_dict(),
                "checks": [
                    {"id": c.id, "title": c.title, "passed": c.passed,
                     "detail": c.detail, "evidence": c.evidence}
                    for c in analysis.checks]}, indent=2))
        else:
            print(f"{args.binary}: {result.value}/100 — {result.band}")
            for check in analysis.checks:
                mark = "?" if check.passed is None else (
                    "ok" if check.passed else "EXPOSED")
                print(f"  [{mark}] {check.title}: {check.detail}")
            if result.unknown:
                print(f"  unknown: {', '.join(result.unknown)}")
            for title, detail in result.recommendations:
                print(f"  fix: {title} — {detail}")
        return 0

    try:
        llm = LocalLlamaClient.from_env() if args.llm else None
        report = probe(args.binary, confirmed=args.i_am_authorized, llm=llm)
    except AuthorizationError as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        for finding in report.findings:
            print(f"[{finding.confidence}] {finding.claim}")
            for ev in finding.evidence:
                print(f"    {ev}")
        if report.narrative:
            print("\n--- narrative (LLM, evidence-cited) ---")
            print(report.narrative)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
