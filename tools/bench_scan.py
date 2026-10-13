#!/usr/bin/env python3
"""Worst-case performance bench for the scanner — card t_b8f748b1 (C1).

Generates a token-dense single-line file (minified-bundle shape: repeated
`curl`/`wget`/`/tmp` tokens without a payload — the input that used to trigger
catastrophic backtracking in SS017), then measures:

  1. the worst per-rule regex cost on that line (each catalog pattern applied
     once — the acceptance budget for a single rule is --rule-budget), and
  2. the full in-process scan of the file through skillsentinel.scan_path.

Exit status: 0 when the scan fits --budget and no single rule exceeds
--rule-budget; 1 otherwise. --json prints machine-readable numbers.

Usage:
    python3 tools/bench_scan.py --line 800KB --budget 5
"""

import argparse
import json
import re
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

# Same filler shape as tests/test_c1_perf_timeout.py: tokens that make chain
# rules (curl ... /tmp ... &&) explore their windows, but no payload, so the
# scan result must stay clean and the file isolates pure regex cost.
CHUNK = ('!function(){"use strict";var t=navigator.userAgent,'
         'o="curl",a="wget",r="/tmp";t=o+a+r}();')


def parse_size(text: str) -> int:
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([kKmMgG]?)([bB]?)\s*", text)
    if not m:
        raise argparse.ArgumentTypeError(f"bad size {text!r} (use 800KB, 1MB, 200000)")
    value = float(m.group(1))
    factor = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2).lower()]
    return int(value * factor)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--line", type=parse_size, default="800KB",
                    help="single-line file size, e.g. 800KB or 1MB (default 800KB)")
    ap.add_argument("--budget", type=float, default=5.0,
                    help="full-scan budget in seconds (default 5)")
    ap.add_argument("--rule-budget", type=float, default=0.5,
                    help="per-rule regex budget in seconds (default 0.5)")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    line = (CHUNK * (args.line // len(CHUNK) + 1))[:args.line]

    from skillsentinel.rules import load_rules
    from skillsentinel.scanner import scan_path

    rules = load_rules()

    # 1. worst-case per-rule cost on the pathological line
    per_rule = []
    for rule in rules:
        if rule.pattern is None:
            continue
        t0 = time.monotonic()
        rule.pattern.search(line)
        per_rule.append((time.monotonic() - t0, rule.id))
    per_rule.sort(reverse=True)
    worst_rule_time, worst_rule_id = per_rule[0]

    # 2. full scan of a real file through the production entry point
    with tempfile.TemporaryDirectory(prefix="skillsentinel-bench-") as tmp:
        f = Path(tmp) / "bundle.js"
        f.write_text(line, encoding="utf-8")
        t0 = time.monotonic()
        result = scan_path(f, rules_path=str(REPO / "rules" / "rules.json"))
        scan_time = time.monotonic() - t0
        findings = len(result.findings)

    ok = scan_time <= args.budget and worst_rule_time <= args.rule_budget
    if args.json:
        print(json.dumps({
            "line_bytes": args.line, "findings": findings,
            "scan_seconds": round(scan_time, 3),
            "budget_seconds": args.budget,
            "worst_rule": worst_rule_id,
            "worst_rule_seconds": round(worst_rule_time, 3),
            "rule_budget_seconds": args.rule_budget,
            "ok": ok,
        }))
    else:
        top3 = ", ".join(f"{rid}={t:.3f}s" for t, rid in per_rule[:3])
        print(f"line: {args.line} bytes, findings: {findings}")
        print(f"scan: {scan_time:.3f}s (budget {args.budget:g}s)")
        print(f"worst rules: {top3} (budget {args.rule_budget:g}s each)")
        print("PASS" if ok else "FAIL: over budget")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
