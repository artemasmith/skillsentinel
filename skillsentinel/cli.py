"""SkillSentinel CLI: scan / watch / rules."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

from . import __version__
from .detonate import DetonationRefusedError, detonate_tree
from .rules import load_rules, SEVERITY_ORDER
from .scanner import (DEFAULT_ARCHIVE_MAX_BYTES, InputError, scan_path, to_sarif)
from .verifier import VERIFIERS_BY_NAME
from .watch import (write_snapshot, load_snapshot, diff_snapshots, snapshot_dir,
                    rescan_changes)

SEV_EXIT: dict[str, int] = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# `scan --help` must state the contract a CI pipeline relies on.
EXIT_CODES_EPILOG = """\
exit codes:
  0  clean — no confirmed findings
  1  at least one confirmed finding at/above the --severity threshold
  2  input error: missing or unreadable path, invalid or empty --rules, a .skillsentinelignore
     pattern that ignores the whole skill, a scan that saw zero scannable files,
     --timeout expiry, --max-files limit reached
  3  internal error — a bug, please report it"""

SEV_COLOR = {
    "critical": "\033[91m", "high": "\033[31m",
    "medium": "\033[33m", "low": "\033[32m", "end": "\033[0m",
}


def _colorized(s: str, sev: str, enabled: bool) -> str:
    if not enabled:
        return s
    return f"{SEV_COLOR[sev]}{s}{SEV_COLOR['end']}"


def _park_stdout_on_devnull() -> None:
    """After a stdout write failed, point fd 1 at /dev/null so the interpreter's
    shutdown flush of the leftover buffer cannot re-raise — without this a
    broken pipe turns into an "Exception ignored" dump and rc=120. Call only
    after the real error line is already on stderr."""
    if sys.stdout is None:
        return  # no stdout buffer was ever created — nothing to re-point or flush
    try:
        null = os.open(os.devnull, os.O_WRONLY)
    except OSError:  # nothing to hide the failure behind: best effort only
        return
    try:
        os.dup2(null, sys.stdout.fileno())
    except (OSError, ValueError):
        pass  # already detached/closed — nothing buffered can re-raise then
    finally:
        os.close(null)


def _emit_stdout(emit: Callable[[], None], what: str) -> bool:
    """Run a stdout-writing report block AND flush it here, so a stdout that
    cannot be written (closed pipe, full device, fd 1 closed at exec so
    sys.stdout is None) fails now as one clean error naming the output — not
    at interpreter shutdown. Returns False after printing that line and
    muting fd 1 (see _park_stdout_on_devnull)."""
    if sys.stdout is None:
        # fd 1 was closed before the interpreter started: print() discards
        # silently, so treat the missing stream exactly like an unwritable
        # one — an output error, not an internal one.
        print(f"skillsentinel: error: cannot write {what}: stdout is closed "
              f"(fd 1 was closed at startup)", file=sys.stderr)
        return False
    try:
        emit()
        sys.stdout.flush()
    except (BrokenPipeError, OSError) as e:
        print(f"skillsentinel: error: cannot write {what}: {e}",
              file=sys.stderr)
        _park_stdout_on_devnull()
        return False
    return True


def _print_findings(result, use_color: bool, suppressed: int = 0,
                    show_inconclusive: bool = False) -> None:
    c = result.counts
    total = sum(c.values())
    dropped = len(result.demoted)
    inconclusive = [f for f in result.demoted if f.verdict == "inconclusive"]
    print(f"SkillSentinel v{__version__} — scanned {result.path} "
          f"({result.files_scanned} text, {result.binary_files_skipped} binary "
          f"skipped, {result.files_skipped} skipped, "
          f"profile: {result.profile})")
    if result.undecodable_files:
        # D3: undecodable files are reported loudly, never silently dropped.
        names = ", ".join(result.undecodable_files[:3])
        more = f" (+{len(result.undecodable_files) - 3} more)" \
            if len(result.undecodable_files) > 3 else ""
        print(f"warning: {len(result.undecodable_files)} file(s) could not be "
              f"decoded as text: {names}{more}", file=sys.stderr)
    if not total:
        note = f", {suppressed} suppressed by inline markers" if suppressed else ""
        if dropped:
            note += f"; {dropped} candidate(s) demoted — see --json for reasons"
        print(f"No exploitable findings. Supply chain looks clean. ✓{note}")
    else:
        print(f"Confirmed findings: {total} "
              f"(critical: {c['critical']}, high: {c['high']}, "
              f"medium: {c['medium']}, low: {c['low']})"
              + (f" — {suppressed} suppressed by inline markers" if suppressed else "")
              + (f"; {dropped} candidate(s) demoted" if dropped else ""))
        cur = None
        for f in result.findings:
            if f.severity != cur:
                cur = f.severity
                print(_colorized(f"\n== {cur.upper()} ==", cur, use_color))
            print(_colorized(f"[{f.rule_id}] {f.file}:{f.line}", cur, use_color)
                  + (f"  (x{f.count})" if f.count > 1 else "")
                  + f"  {f.title}")
            print(f"    {f.snippet[:160]}")
            print(f"    verdict: {f.verdict} — {f.reason}")
    if show_inconclusive or inconclusive:
        print(f"\n{len(inconclusive)} inconclusive candidate(s):")
        for f in inconclusive:
            print(f"  [{f.rule_id}] {f.file}:{f.line} — {f.reason}")


def load_ignore_file(root: Path) -> list[str]:
    p = root if root.is_file() else root / ".skillsentinelignore"
    if not p.exists() or not p.is_file():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser()
    # `.skillsentinelignore` is input from the scanned tree, so it is trusted
    # only under --honor-ignores — exactly like inline suppression markers.
    ignore_patterns = load_ignore_file(root) if args.honor_ignores else []
    result = scan_path(args.path, args.rules,
                       honor_ignores=args.honor_ignores,
                       exclude=list(args.exclude),
                       ignore_patterns=ignore_patterns,
                       profile=args.profile,
                       timeout=args.timeout,
                       max_files=args.max_files,
                       follow_symlinks=not args.no_follow_symlinks,
                       archive_max_bytes=args.archive_max_bytes)
    reports = None
    if args.detonate:
        try:
            reports = detonate_tree(Path(args.path), allow_net=args.allow_net,
                                    timeout=args.detonate_timeout)
        except DetonationRefusedError as e:
            print(f"detonation refused: {e}", file=sys.stderr)
            return 2
    def _text_report() -> None:
        _print_findings(result, use_color=sys.stdout is not None and sys.stdout.isatty(),
                        suppressed=result.suppressed,
                        show_inconclusive=args.show_inconclusive)
        if reports is not None:
            print(f"\n-- Detonation ({len(reports)} scripts) --")
            for r in reports:
                if not r.executed:
                    print(f"[skip] {r.file}: {'; '.join(r.notes)}")
                    continue
                net = ", ".join(r.network_attempts) or "none observed"
                print(f"[ran ] {r.file}  exit={r.exit_code}  egress: {net}")
                for n in r.notes:
                    if "timed out" in n.lower():
                        print(f"[warn] {r.file}: {n}")
                if any("network NOT isolated" in n for n in r.notes):
                    print("[warn] network NOT isolated (--allow-net): the "
                          "sandbox shares the host network — real egress "
                          "is possible")

    if args.json:
        payload = result.to_dict()
        if reports is not None:
            payload["detonations"] = [r.to_dict() for r in reports]
        if not _emit_stdout(lambda: print(json.dumps(payload, indent=2)),
                            "the JSON report to stdout"):
            return 2
    elif not _emit_stdout(_text_report, "the report to stdout"):
        return 2
    if args.sarif:
        sarif = to_sarif(result)
        try:
            Path(args.sarif).write_text(json.dumps(sarif, indent=2), encoding="utf-8")
        except OSError as e:  # the report target is part of the input contract too
            print(f"skillsentinel: error: cannot write the SARIF report to "
                  f"{args.sarif}: {e}", file=sys.stderr)
            return 2
        if not args.json and not _emit_stdout(
                lambda: print(f"\nSARIF written to {args.sarif}"),
                "the SARIF confirmation to stdout"):
            return 2
    # R1c/R1d/R3b: refusals the scan accounted for (loops, unfollowed or
    # broken links, guarded archives) are part of the verdict's evidence —
    # they go to stderr in both output modes, never silently dropped.
    for w in result.warnings:
        print(w, file=sys.stderr)
    if result.limit_reached is not None:
        n, m = result.limit_reached
        print(f"error: limit reached: {n} of {m} files scanned "
              f"(raise --max-files to see the rest)", file=sys.stderr)
        return 2
    if result.unreadable_files:
        # V5: the readable files' findings are printed above; an unreadable
        # file is still an input problem, so the run warns and exits 2.
        names = ", ".join(result.unreadable_files[:3])
        more = f" (+{len(result.unreadable_files) - 3} more)" \
            if len(result.unreadable_files) > 3 else ""
        print(f"warning: {len(result.unreadable_files)} file(s) could not be "
              f"read: {names}{more}", file=sys.stderr)
        return 2
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
        try:
            old = load_snapshot(snap_path)
        except (OSError, ValueError) as e:
            raise InputError(f"cannot read snapshot {snap_path}: {e}") from None
        snap_root = old.get("root")
        if snap_root and Path(snap_root) != root:
            # V2: diffing another tree used to silently compare apples to
            # oranges — a fresh install dir reads as "clean" against any
            # snapshot. The snapshot pins the root it was taken under.
            raise InputError(
                f"snapshot root mismatch: the snapshot was taken under "
                f"{snap_root}, not {root} — re-run watch init")
        new = snapshot_dir(root)
        d = diff_snapshots(old, new)
        if d["clean"]:
            print(f"Clean: no drift across {len(new['entries'])} files.")
            return 0
        print("DRIFT DETECTED:")
        for k in ("added", "changed", "removed"):
            for p in d[k]:
                print(f"  {k:>7}: {p}")
        if getattr(args, "rescan", False):
            findings = rescan_changes(root, d)
            if findings:
                print(f"\nRescan of changed/added files — "
                      f"{len(findings)} confirmed finding(s):")
                for f in findings:
                    print(f"  [{f.rule_id}] {f.file}:{f.line}  {f.title}")
                    print(f"    {f.snippet[:160]}")
                    print(f"    verdict: {f.verdict} — {f.reason}")
            else:
                print("\nRescan of changed/added files: no confirmed findings.")
        return 1
    print(json.dumps(snapshot_dir(root), indent=2))
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as e:
        raise InputError(
            f"cannot load rules from {args.rules or 'the built-in catalog'}: {e}") from None
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

    s = sub.add_parser("scan", help="scan a skill file or directory",
                       epilog=EXIT_CODES_EPILOG,
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    s.add_argument("path", help="file or directory to scan")
    s.add_argument("--json", action="store_true", help="machine-readable JSON output")
    s.add_argument("--sarif", metavar="OUT.sarif", help="also write SARIF 2.1.0 report")
    s.add_argument("--severity", choices=list(SEVERITY_ORDER), default="low",
                   help="exit 1 only for findings at/above this severity (default: low)")
    s.add_argument("--rules", help="path to alternative rules.json")
    s.add_argument("--profile", choices=list(VERIFIERS_BY_NAME), default="balanced",
                   help="verification strictness: strict (every candidate confirmed, "
                        "demoted is empty) / balanced (default) / loose / paranoid")
    s.add_argument("--honor-ignores", action="store_true",
                   help="honor inline `skillsentinel:ignore` markers and "
                        "`.skillsentinelignore` patterns (OFF by default: a scanned "
                        "file must not be able to silence its own detection)")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                   help="skip files matching this glob (repeatable)")
    s.add_argument("--timeout", type=float, default=None, metavar="SEC",
                   help="abort the scan after SEC seconds and exit 2 (0 disables); "
                        "protects CI against pathological trees")
    s.add_argument("--max-files", type=int, default=None, metavar="N",
                   help="scan at most N files, then exit 2 with a limit report; "
                        "bounds huge trees without silently ignoring the rest")
    s.add_argument("--no-follow-symlinks", action="store_true",
                   help="do not descend into or scan symlinked files/directories; "
                        "every declined link is counted in files_skipped with a "
                        "warning naming it (symlinked skill dirs ARE followed by "
                        "default — that is how skills are installed)")
    s.add_argument("--archive-max-bytes", type=int,
                   default=DEFAULT_ARCHIVE_MAX_BYTES, metavar="N",
                   help="per-member uncompressed byte budget for archives scanned "
                        "in memory (zip/tar.gz/tgz/whl); members over N are skipped "
                        f"with a warning (default: {DEFAULT_ARCHIVE_MAX_BYTES})")
    s.add_argument("--detonate", action="store_true",
                   help="run discovered scripts (.sh/.bash/.py/.js/.rb/.pl/.ps1 "
                        "and files named `install`) in a disposable bwrap sandbox "
                        "with no network access (--unshare-net; requires "
                        "bubblewrap, skipped with a notice otherwise)")
    s.add_argument("--allow-net", action="store_true",
                   help="with --detonate: lift network isolation — the sandbox "
                        "CAN open real connections (each detonation prints a "
                        "'network NOT isolated' warning)")
    s.add_argument("--detonate-timeout", type=int, default=10, metavar="SEC",
                   help="with --detonate: kill each sandboxed script after SEC "
                        "seconds and record a timeout warning (0 disables; "
                        "default: 10)")
    s.add_argument("--show-inconclusive", action="store_true",
                   help="also list candidates the verifier graded inconclusive "
                        "(unknown context) with their file:line and reason")
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
    wsub.choices["diff"].add_argument(
        "--rescan", action="store_true",
        help="also re-scan changed/added files and print their confirmed findings")
    w.set_defaults(func=cmd_watch, watch_cmd="show")

    r = sub.add_parser("rules", help="list detection rules")
    r.add_argument("--json", action="store_true", help="JSON output")
    r.add_argument("--rules", help="path to alternative rules.json")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except InputError as e:
        print(f"skillsentinel: error: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        # IO trouble reaching the input (vanished path, unreadable file): the
        # scan target's problem, not the scanner's — still exit 2, one line.
        print(f"skillsentinel: error: {e}", file=sys.stderr)
        return 2
    except Exception as e:  # noqa: BLE001 — the CLI boundary turns bugs into exit 3
        print(f"skillsentinel: internal error: {type(e).__name__}: {e}",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
