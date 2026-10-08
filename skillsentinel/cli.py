"""SkillSentinel CLI: scan / watch / rules."""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from . import __version__
from .detonate import detonate_tree
from .rules import load_rules, SEVERITY_ORDER
from .scanner import scan_path, to_sarif
from .watch import write_snapshot, load_snapshot, diff_snapshots, snapshot_dir

SEV_EXIT: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

SEV_COLOR = {
    "critical": "\033[91m", "high": "\033[31m",
    "medium": "\033[33m", "low": "\033[32m", "end": "\033[0m",
}


def _colorized(s: str, sev: str, enabled: bool) -> str:
    if not enabled:
        return s
    return f"{SEV_COLOR[sev]}{s}{SEV_COLOR['end']}"


def _print_findings(result, use_color: bool) -> None:
    c = result.counts
    print(f"SkillSentinel v{__version__} — scanned {result.path} "
          f"({result.files_scanned} files, {result.files_skipped} skipped)")
    total = sum(c.values())
    if not total:
        print("No findings. Supply chain looks clean. ✓")
        return
    print(f"Findings: {total} "
          f"(critical: {c['critical']}, high: {c['high']}, "
          f"medium: {c['medium']}, low: {c['low']})")
    cur = None
    for f in result.findings:
        if f.severity != cur:
            cur = f.severity
            print(_colorized(f"\n== {cur.upper()} ==", cur, use_color))
        print(_colorized(f"[{f.rule_id}] {f.file}:{f.line}", cur, use_color)
              + f"  {f.title}")
        print(f"    {f.snippet[:160]}")


def cmd_scan(args: argparse.Namespace) -> int:
    result = scan_path(args.path, args.rules)
    if args.json:
        payload = result.to_dict()
        if args.detonate:
            reports = detonate_tree(Path(args.path))
            payload["detonations"] = [r.to_dict() for r in reports]
        print(json.dumps(payload, indent=2))
    else:
        _print_findings(result, use_color=sys.stdout.isatty())
        if args.detonate:
            reports = detonate_tree(Path(args.path))
            print(f"\n-- Detonation ({len(reports)} scripts) --")
            for r in reports:
                if not r.executed:
                    print(f"[skip] {r.file}: {'; '.join(r.notes)}")
                    continue
                net = ", ".join(r.network_attempts) or "none observed"
                print(f"[ran ] {r.file}  exit={r.exit_code}  egress: {net}")
    if args.sarif:
        sarif = to_sarif(result)
        Path(args.sarif).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        if not args.json:
            print(f"\nSARIF written to {args.sarif}")
    threshold = SEVERITY_ORDER[args.severity]
    return 1 if result.max_severity_rank() >= threshold else 0


def cmd_watch(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if args.watch_cmd == "init":
        snap = write_snapshot(root, Path(args.snapshot))
        print(f"Snapshot saved: {args.snapshot} "
              f"({len(snap['entries'])} files under {snap['root']})")
        return 0
    if args.watch_cmd == "diff":
        snap_path = Path(args.snapshot)
        if not snap_path.exists():
            print(f"error: snapshot not found: {snap_path} — run `watch init` first",
                  file=sys.stderr)
            return 2
        old = load_snapshot(snap_path)
        new = snapshot_dir(root)
        d = diff_snapshots(old, new)
        if d["clean"]:
            print(f"Clean: no drift across {len(new['entries'])} files.")
            return 0
        print("DRIFT DETECTED:")
        for k in ("added", "changed", "removed"):
            for p in d[k]:
                print(f"  {k:>7}: {p}")
        return 1
    print(json.dumps(snapshot_dir(root), indent=2))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    if args.json:
        print(json.dumps({
            "count": len(rules),
            "rules": [{
                "id": r.id, "title": r.title, "severity": r.severity,
                "category": r.category, "owasp": r.owasp,
                "description": r.description,
            } for r in rules]}, indent=2))
    else:
        print(f"{len(rules)} rules:")
        for r in sorted(rules, key=lambda x: (x.category, x.id)):
            print(f"  {r.id}  {r.severity:<8} {r.category:<18} {r.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skillsentinel",
        description="Post-install security scanner for AI-agent skills and prompt configs.")
    p.add_argument("--version", action="version", version=f"skillsentinel {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a skill file or directory")
    s.add_argument("path", help="file or directory to scan")
    s.add_argument("--json", action="store_true", help="machine-readable JSON output")
    s.add_argument("--sarif", metavar="OUT.sarif", help="also write SARIF 2.1.0 report")
    s.add_argument("--severity", choices=list(SEVERITY_ORDER), default="low",
                   help="exit 1 only for findings at/above this severity (default: low)")
    s.add_argument("--rules", help="path to alternative rules.json")
    s.add_argument("--detonate", action="store_true",
                   help="run discovered scripts in a disposable bwrap sandbox "
                        "(requires bubblewrap; skipped with a notice otherwise)")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("watch", help="snapshot installed skills and detect drift")
    wsub = w.add_subparsers(dest="watch_cmd")
    for name, helptext in (("init", "record a hash snapshot"),
                           ("diff", "compare current tree against the snapshot"),
                           ("show", "print the current snapshot as JSON")):
        wp = wsub.add_parser(name, help=helptext)
        wp.add_argument("path", help="directory of installed skills")
        wp.add_argument("--snapshot", default=".skillsentinel-snapshot.json",
                        help="snapshot file path (default: .skillsentinel-snapshot.json)")
    w.set_defaults(func=cmd_watch, watch_cmd="show")

    r = sub.add_parser("rules", help="list detection rules")
    r.add_argument("--json", action="store_true", help="JSON output")
    r.add_argument("--rules", help="path to alternative rules.json")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
