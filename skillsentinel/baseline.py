"""Content-addressed baseline of accepted findings (P4d/P4e).

A baseline records the scan's confirmed findings as (path, rule id, snippet
hash) triples plus the rules catalog version it was written under. Matching is
by CONTENT, never by line number: deleting a file or a line above a finding
must not shift the baseline onto an unrelated finding.

The baseline hides known-accepted findings from the EXIT CODE only. It never
hides them from the report — every finding is still printed and still lands in
the JSON/SARIF output exactly as before.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from .scanner import Finding, ScanResult, rules_version

BASELINE_FORMAT = 1

# (path, rule, snippet_sha256) — the content identity of one accepted finding.
BaselineKey = tuple[str, str, str]


def finding_key(f: Finding) -> BaselineKey:
    """Content identity of a finding.

    The snippet is the matched line's text (whitespace-stripped), so editing an
    unrelated line above does not change the key — but editing the matched line
    itself does, deliberately: that is a new finding to re-review.
    """
    digest = hashlib.sha256(f.snippet.encode("utf-8")).hexdigest()
    return (f.file, f.rule_id, digest)


def write_baseline(result: ScanResult, path: str | Path) -> int:
    """Record the scan's confirmed findings into `path`. Returns the count."""
    entries = sorted(finding_key(f) for f in result.confirmed())
    payload = {
        "skillentinel_baseline": BASELINE_FORMAT,
        "rules_version": rules_version(),
        "findings": [
            {"path": p, "rule": r, "snippet_sha256": h} for p, r, h in entries
        ],
    }
    Path(path).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def load_baseline(path: str | Path) -> tuple[set[BaselineKey], str]:
    """Return (baselined content keys, the baseline's rules_version).

    Raises ValueError with a one-line message for anything that is not a
    readable baseline file — the CLI maps that to exit 2.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"cannot read baseline {p}: {e}") from None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"baseline {p} is not valid JSON: {e}") from None
    if (not isinstance(data, dict)
            or "skillentinel_baseline" not in data
            or not isinstance(data.get("findings"), list)):
        raise ValueError(f"{p} is not a SkillSentinel baseline "
                         f"(missing skillentinel_baseline/findings)")
    keys: set[BaselineKey] = set()
    for e in data["findings"]:
        if not isinstance(e, dict) or not all(
                isinstance(e.get(k), str) and e[k]
                for k in ("path", "rule", "snippet_sha256")):
            raise ValueError(
                f"{p}: malformed baseline entry (need path/rule/snippet_sha256)")
        keys.add((e["path"], e["rule"], e["snippet_sha256"]))
    return keys, data.get("rules_version", "")


def classify(result: ScanResult, baseline_path: str | Path,
             ) -> tuple[list[Finding], list[Finding]]:
    """Split the scan's confirmed findings into (new, baselined).

    Per-finding matching (P4e): a key is (path, rule, snippet hash), so a file
    baselined for one rule never hides a different rule's finding in the same
    file.

    A baseline written under a different rules_version is not trusted: every
    finding is reported as new (the exit code then behaves as if no baseline
    had been supplied), after a loud warning on stderr. An outdated baseline
    must not be able to buy a silent exit 0.
    """
    keys, baseline_rules_version = load_baseline(baseline_path)
    installed = rules_version()
    if baseline_rules_version != installed:
        print(f"warning: baseline rules_version {baseline_rules_version!r} != "
              f"installed {installed!r}; ignoring the baseline and "
              f"re-evaluating every finding as new", file=sys.stderr)
        return list(result.confirmed()), []
    baselined: list[Finding] = []
    new: list[Finding] = []
    for f in result.confirmed():
        (baselined if finding_key(f) in keys else new).append(f)
    return new, baselined
