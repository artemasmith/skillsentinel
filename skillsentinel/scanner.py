"""Core scanner: walk a tree, match rules, emit findings."""

from __future__ import annotations

import fnmatch
import hashlib
import os
import stat
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

from .rules import Rule, load_rules, SEVERITY_ORDER
from .verifier import (VERDICT_ORDER, VERIFIERS_BY_NAME, bind_rules,
                       verify_findings)

MAX_FILE_BYTES = 2_000_000  # larger files are scanned as head+tail windows
SCAN_WINDOW_BYTES = 512 * 1024  # window size on each side of an oversize file

# Directory subtrees the walker never enters. `.git` is special-cased below:
# all of it is repo metadata except `.git/hooks/` — hook scripts are executable
# attack surface (a payload planted there fires on the user's next `git pull`).
SKIP_DIR_PARTS = {".venv", "venv", "node_modules", "__pycache__"}
HOOKS_DIR = "hooks"

# A `.skillsentinelignore` pattern from this set excludes the whole skill (with
# --honor-ignores). Scanning nothing and reporting "clean" is the worst lie a
# security tool can tell, so it is refused as an input error instead.
WHOLE_SKILL_IGNORE_PATTERNS = {"*", "**", "**/*"}

# Executable content whose suffix does not announce it. The verifier grades by
# suffix-derived context, so these are verified under a shell-script alias —
# see `_verification_alias`.
EXECUTABLE_BLOB_SUFFIXES = {".pyc", ".bin"}
VERIFICATION_ALIAS_SUFFIX = ".skillsentinel-exec.sh"

# Inline suppression markers. They are honored ONLY with `--honor-ignores`: a scanner
# whose findings a scanned artifact can silence is itself the vulnerability (an
# attacker ships a skill that suppresses its own detection). Default = markers are
# plain text and everything is reported.
NOQA = "skillsentinel:ignore"
NOQA_FILE = "skillsentinel:ignore-file"


class InputError(Exception):
    """Bad input: missing path, unreadable file, broken rules, expired --timeout.

    The CLI maps it to one stderr line and exit code 2 — never a traceback.
    """


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    category: str
    owasp: str
    file: str
    line: int
    snippet: str
    description: str = ""
    kind: str = "intent"
    verdict: str = "exploitable"
    reason: str = ""
    count: int = 1

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    path: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)
    suppressed: int = 0
    verdicts: dict[str, int] = field(default_factory=dict)
    profile: str = "balanced"
    demoted: list[Finding] = field(default_factory=list)
    ignored_files: list[str] = field(default_factory=list)
    truncated: bool = False
    truncated_files: list[str] = field(default_factory=list)
    limit_reached: tuple[int, int] | None = None

    @property
    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in ("critical", "high", "medium", "low")}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def confirmed(self) -> list[Finding]:
        """Findings the verifier kept as actually exploitable."""
        return [f for f in self.findings if f.verdict == "exploitable"]

    def max_severity_rank(self) -> int:
        return max((SEVERITY_ORDER[f.severity] for f in self.confirmed()), default=-1)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "profile": self.profile,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "suppressed": self.suppressed,
            "counts": self.counts,
            "verdicts": self.verdicts,
            "confirmed": len(self.confirmed()),
            "findings": [f.to_dict() for f in self.findings],
            "demoted": [f.to_dict() for f in self.demoted],
            "ignored_files": self.ignored_files,
            "truncated": self.truncated,
            "truncated_files": self.truncated_files,
            "limit_reached": list(self.limit_reached) if self.limit_reached else None,
        }


def _is_excluded(rel: str, patterns: list[str]) -> bool:
    """Globs match the path or the basename. A pattern ending in `/` is a directory
    prefix (gitignore-style), so `tests/` excludes everything underneath."""
    for pat in patterns:
        if pat.endswith("/"):
            if rel == pat[:-1] or rel.startswith(pat):
                return True
            continue
        if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(Path(rel).name, pat):
            return True
    return False


def _git_visible(parts: tuple[str, ...]) -> bool:
    """`.git/**` is excluded, but `.git/hooks/**` is scanned: hook scripts run."""
    if ".git" not in parts:
        return True
    i = parts.index(".git")
    return len(parts) > i + 1 and parts[i + 1] == HOOKS_DIR


def _iter_target_files(root: Path) -> Iterable[Path]:
    """Yield every candidate entry under `root`, sorted for a stable order.

    Every file is a candidate regardless of suffix — a payload does not care
    which extension hides it. Directories are filtered here; symlinks
    (resolvable, broken or looped) are yielded so the caller can classify them.
    """
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        parts = p.relative_to(root).parts
        if not _git_visible(parts) or any(seg in SKIP_DIR_PARTS for seg in parts):
            continue
        yield p


def _read_scannable(path: Path) -> tuple[str, bool]:
    """Read a file into scannable text. Returns (text, truncated).

    Oversize files are windowed (head + tail) instead of skipped: a rug pull
    must not be able to hide behind megabytes of padding. Content that is not
    valid UTF-8 — bytecode, binaries, mixed encodings — is decoded as latin-1
    so the attack strings inside are still visible to the rules.
    """
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size <= MAX_FILE_BYTES:
            raw, truncated = fh.read(), False
        else:
            head = fh.read(SCAN_WINDOW_BYTES)
            fh.seek(-SCAN_WINDOW_BYTES, os.SEEK_END)
            tail = fh.read(SCAN_WINDOW_BYTES)
            raw = (head
                   + b"\n\n[... skillsentinel: file over "
                   + str(MAX_FILE_BYTES).encode() + b" bytes, middle not scanned ...]\n\n"
                   + tail)
            truncated = True
    try:
        return raw.decode("utf-8"), truncated
    except UnicodeDecodeError:
        return raw.decode("latin-1", errors="replace"), truncated


def scan_file(path: Path, rules: list[Rule], root: Path,
              honor_ignores: bool = False) -> tuple[list[Finding], int, str, bool]:
    """Scan one file. Returns (candidates, suppressed, text, truncated).

    Candidates are unverified: `scan_path` runs them through the verifier before
    they become findings. Correlation rules (`requires_pattern`) are resolved
    here, because only this function has the whole file text.
    """
    try:
        text, truncated = _read_scannable(path)
    except OSError as e:
        # unreadable (mode 000), vanished mid-scan: an input problem, not a bug
        raise InputError(f"cannot read {path}: {e.strerror or e}") from None
    candidates: list[Finding] = []
    suppressed = 0
    rel = str(path.relative_to(root)) if path != root else path.name
    lines = text.splitlines()
    if honor_ignores and NOQA_FILE in "\n".join(lines[:10]):
        return [], len(lines), text, truncated  # wholesale suppression, counted as suppressed
    for rule in rules:
        if rule.pattern is None:
            continue
        # file-level correlation: a blob is not evidence unless the file also decodes it
        if rule.requires_pattern is not None and not rule.requires_pattern.search(text):
            continue
        for m in rule.pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else m.group(0)[:200]
            if honor_ignores and NOQA in snippet:
                suppressed += 1
                continue
            candidates.append(Finding(
                rule_id=rule.id, severity=rule.severity, title=rule.title,
                category=rule.category, owasp=rule.owasp, file=rel, line=line,
                snippet=snippet, description=rule.description, kind=rule.kind,
            ))
    return candidates, suppressed, text, truncated


def _verification_alias(rel: str) -> str:
    """Key under which a file is presented to the verifier.

    The verifier's context table is suffix-driven: `post-merge` or `x.pyc`
    would be graded "unknown context" and dropped as inconclusive. Hook
    scripts and binary blobs are executable, so they are verified as shell
    code — under an alias suffix, with findings reported under the real path.
    """
    parts = Path(rel).parts
    for i, seg in enumerate(parts[:-1]):
        if seg == ".git" and parts[i + 1] == HOOKS_DIR:
            return rel + VERIFICATION_ALIAS_SUFFIX
    if Path(rel).suffix.lower() in EXECUTABLE_BLOB_SUFFIXES:
        return rel + VERIFICATION_ALIAS_SUFFIX
    return rel


def scan_path(target: str | Path, rules_path: str | None = None, *,
              honor_ignores: bool = False,
              exclude: list[str] | None = None,
              ignore_patterns: list[str] | None = None,
              profile: str = "balanced",
              timeout: float | None = None,
              max_files: int | None = None) -> ScanResult:
    """Scan a path. Pattern matches are candidates; the verifier grades them.

    Only `exploitable` findings are reported as findings — everything else is kept in
    `result.verdicts` with a reason, so a dropped hit is auditable rather than
    invisible. `ignore_patterns` (from `.skillsentinelignore`) and inline markers
    both apply only under `honor_ignores`: a scanned artifact must not be able
    to silence its own detection by default.

    `timeout`/`max_files` bound the walk; expiry or hitting the limit is an
    input error for the CLI to report — never a silently partial scan.
    """
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise InputError(f"path not found: {root}")
    if profile not in VERIFIERS_BY_NAME:
        raise ValueError(f"unknown profile {profile!r}; "
                         f"choose from {', '.join(VERIFIERS_BY_NAME)}")
    try:
        rules = load_rules(rules_path)
    except (OSError, ValueError) as e:
        raise InputError(
            f"cannot load rules from {rules_path or 'the built-in catalog'}: {e}") from None
    bind_rules(rules)
    cfg = VERIFIERS_BY_NAME[profile]
    excludes = list(exclude or [])
    ignores = [p for p in (ignore_patterns or []) if honor_ignores]
    for pat in ignores:
        if pat in WHOLE_SKILL_IGNORE_PATTERNS:
            raise InputError(
                f".skillsentinelignore pattern {pat!r} ignores the whole skill — "
                "refusing to report an empty scan as clean")
    result = ScanResult(path=str(root), profile=profile)
    sources: dict[str, str] = {}
    candidates: list[Finding] = []
    deadline = time.monotonic() + timeout if timeout else None
    linked: set[tuple[int, int]] = set()  # (st_dev, st_ino) of resolved symlink targets
    over_limit = 0
    for p in _iter_target_files(root):
        rel = str(p.relative_to(root)) if p != root else p.name
        if p.is_symlink():
            # Resolve the link: broken links and loops surface as skipped
            # files, never as hangs; a target inode seen before is a cycle or
            # a second link to an already-scanned file.
            try:
                st = os.stat(p)  # follows the chain; ELOOP on a cycle
            except OSError:
                result.files_skipped += 1
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            target = (st.st_dev, st.st_ino)
            if target in linked:
                result.files_skipped += 1
                continue
            linked.add(target)
        elif not p.is_file():
            continue  # directories and other non-regular entries
        if excludes and _is_excluded(rel, excludes):
            result.files_skipped += 1
            continue
        if ignores and _is_excluded(rel, ignores):
            result.files_skipped += 1
            result.ignored_files.append(rel)
            continue
        if max_files is not None and result.files_scanned >= max_files:
            over_limit += 1
            continue
        if deadline is not None and time.monotonic() > deadline:
            raise InputError(f"timed out after {timeout:g} s")
        found, suppressed, text, truncated = scan_file(p, rules, root,
                                                       honor_ignores=honor_ignores)
        result.files_scanned += 1
        result.suppressed += suppressed
        if truncated:
            result.truncated = True
            result.truncated_files.append(rel)
        if found:
            candidates.extend(found)
            sources[found[0].file] = text
    if over_limit:
        result.limit_reached = (max_files, result.files_scanned + over_limit)

    # Executable content whose suffix does not say so (git hooks, bytecode) is
    # verified under a code suffix so the verifier grades it as the code it is.
    taken = set(sources)
    alias_back: dict[str, str] = {}
    for f in candidates:
        alias = _verification_alias(f.file)
        if alias != f.file and alias not in taken:
            sources[alias] = sources[f.file]
            alias_back[alias] = f.file
            f.file = alias
    verdicts = verify_findings(candidates, sources, cfg)
    for f in candidates:
        if f.file in alias_back:
            f.file = alias_back[f.file]
    for v in verdicts:
        if v.file in alias_back:
            v.file = alias_back[v.file]
    by_key: dict[tuple[str, int, str], tuple[str, str]] = {}
    for v in verdicts:
        by_key.setdefault((v.file, v.line, v.rule_id), (v.verdict, v.reason))
    result.verdicts = {}
    for v in verdicts:
        result.verdicts[v.verdict] = result.verdicts.get(v.verdict, 0) + 1
    for f in candidates:
        f.verdict, f.reason = by_key.get((f.file, f.line, f.rule_id),
                                         ("inconclusive", "not graded"))
        if f.verdict == "exploitable":
            result.findings.append(f)
        else:
            result.demoted.append(f)

    def _dedupe(items: list[Finding]) -> list[Finding]:
        """One line matching a rule 32 times is one finding, not 32."""
        merged: dict[tuple[str, int, str], Finding] = {}
        for f in items:
            key = (f.file, f.line, f.rule_id)
            if key in merged:
                merged[key].count += 1
            else:
                merged[key] = f
        return list(merged.values())

    result.findings = _dedupe(result.findings)
    result.demoted = _dedupe(result.demoted)
    # stable order: severity desc, then file, then rule, then line
    result.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.rule_id, f.line))
    return result


def to_sarif(result: ScanResult, rules: list[Rule] | None = None) -> dict:
    rules = rules or load_rules()
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/json/gitHubAndroidWorkflow-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SkillSentinel",
                "informationUri": "https://github.com/artemasmith/skillsentinel",
                "rules": [{
                    "id": r.id, "name": r.id,
                    "shortDescription": {"text": r.title},
                    "properties": {"severity": r.severity, "category": r.category, "owasp": r.owasp},
                } for r in rules],
            }},
            "results": [{
                "ruleId": f.rule_id,
                "level": {"critical": "error", "high": "error",
                          "medium": "warning", "low": "note"}[f.severity],
                "message": {"text": f"{f.title}: {f.snippet}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": f.line},
                }}],
            } for f in result.findings],
            "properties": {"suppressed": result.suppressed},
        }],
    }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()
