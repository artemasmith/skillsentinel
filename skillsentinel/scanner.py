"""Core scanner: walk a tree, match rules, emit findings."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable

from .rules import Rule, load_rules, SEVERITY_ORDER

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

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanResult:
    path: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        c = {s: 0 for s in ("critical", "high", "medium", "low")}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def max_severity_rank(self) -> int:
        return max((SEVERITY_ORDER[f.severity] for f in self.findings), default=-1)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.findings],
        }


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


def scan_file(path: Path, rules: list[Rule], root: Path) -> tuple[list[Finding], bool]:
    """Scan one file. Returns (findings, scanned?) — scanned=False when skipped."""
    if not _should_scan(path):
        return [], False
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [], False
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], False
    findings: list[Finding] = []
    rel = str(path.relative_to(root)) if path != root else path.name
    lines = text.splitlines()
    for rule in rules:
        if rule.pattern is None:
            continue
        for m in rule.pattern.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            snippet = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else m.group(0)[:200]
            findings.append(Finding(
                rule_id=rule.id, severity=rule.severity, title=rule.title,
                category=rule.category, owasp=rule.owasp, file=rel, line=line,
                snippet=snippet, description=rule.description,
            ))
    return findings, True


def scan_path(target: str | Path, rules_path: str | None = None) -> ScanResult:
    root = Path(target).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")
    rules = load_rules(rules_path)
    result = ScanResult(path=str(root))
    for p in _iter_target_files(root):
        findings, scanned = scan_file(p, rules, root)
        if scanned:
            result.files_scanned += 1
            result.findings.extend(findings)
        else:
            result.files_skipped += 1
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
        }],
    }


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()
