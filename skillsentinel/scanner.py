"""Core scanner: walk a tree, match rules, emit findings."""

from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

from .rules import Rule, load_rules, SEVERITY_ORDER
from .verifier import (VERDICT_ORDER, VERIFIERS_BY_NAME, bind_rules,
                       verify_findings)

MAX_FILE_BYTES = 2_000_000  # skip huge blobs

# Files whose content is scanned as text/code
TEXT_SUFFIXES = {
    ".md", ".markdown", ".txt", ".rst", ".py", ".sh", ".bash", ".zsh", ".fish",
    ".js", ".mjs", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml",
    ".cfg", ".ini", ".conf", ".env", ".tf", ".go", ".rb", ".pl", ".ps1",
    ".lua", ".vim", ".editorconfig", ".gitignore", ".npmrc", ".netrc", "",
}
KEY_FILENAMES = {
    "agents.md", "skill.md", "claudemd", "claude.md", "geminimd", "codexmd",
    "copilot-instructions.md", "settings.json", "config.toml", "mcp.json",
    "cursorrules", ".bashrc", ".zshrc", ".profile", ".bash_profile",
    "dockerfile", "makefile", "procfile",
}

# Inline suppression markers. They are honored ONLY with `--honor-ignores`: a scanner
# whose findings a scanned artifact can silence is itself the vulnerability (an
# attacker ships a skill that suppresses its own detection). Default = markers are
# plain text and everything is reported.
NOQA = "skillsentinel:ignore"
NOQA_FILE = "skillsentinel:ignore-file"


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


def _should_scan(path: Path) -> bool:
    if path.name.lower() in KEY_FILENAMES:
        return True
    return path.suffix.lower() in TEXT_SUFFIXES


def _iter_target_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p.is_symlink():
            continue
        parts = p.relative_to(root).parts
        if any(seg in (".git", ".venv", "venv", "node_modules", "__pycache__") for seg in parts):
            continue
        yield p


def scan_file(path: Path, rules: list[Rule], root: Path,
              honor_ignores: bool = False) -> tuple[list[Finding], bool, int, str]:
    """Scan one file. Returns (candidates, scanned?, suppressed, text).

    Candidates are unverified: `scan_path` runs them through the verifier before they
    become findings. Correlation rules (`requires_pattern`) are resolved here, because
    only this function has the whole file text.
    """
    if not _should_scan(path):
        return [], False, 0, ""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [], False, 0, ""
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], False, 0, ""
    candidates: list[Finding] = []
    suppressed = 0
    rel = str(path.relative_to(root)) if path != root else path.name
    lines = text.splitlines()
    if honor_ignores and NOQA_FILE in "\n".join(lines[:10]):
        return [], True, len(lines), text  # wholesale suppression, counted as suppressed
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
    return candidates, True, suppressed, text


def scan_path(target: str | Path, rules_path: str | None = None, *,
              honor_ignores: bool = False,
              exclude: list[str] | None = None,
              profile: str = "balanced") -> ScanResult:
    """Scan a path. Pattern matches are candidates; the verifier grades them.

    Only `exploitable` findings are reported as findings — everything else is kept in
    `result.verdicts` with a reason, so a dropped hit is auditable rather than invisible.
    """
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")
    if profile not in VERIFIERS_BY_NAME:
        raise ValueError(f"unknown profile {profile!r}; "
                         f"choose from {', '.join(VERIFIERS_BY_NAME)}")
    rules = load_rules(rules_path)
    bind_rules(rules)
    cfg = VERIFIERS_BY_NAME[profile]
    excludes = list(exclude or [])
    result = ScanResult(path=str(root), profile=profile)
    sources: dict[str, str] = {}
    candidates: list[Finding] = []
    for p in _iter_target_files(root):
        if excludes and _is_excluded(str(p.relative_to(root)) if p != root else p.name, excludes):
            result.files_skipped += 1
            continue
        found, scanned, suppressed, text = scan_file(p, rules, root, honor_ignores=honor_ignores)
        if scanned:
            result.files_scanned += 1
            result.suppressed += suppressed
            if found:
                candidates.extend(found)
                sources[found[0].file] = text
        else:
            result.files_skipped += 1
    verdicts = verify_findings(candidates, sources, cfg)
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
