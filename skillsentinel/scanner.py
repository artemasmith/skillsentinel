"""Core scanner: walk a tree, match rules, emit findings."""

from __future__ import annotations

import base64
import binascii
import fnmatch
import gzip
import hashlib
import json
import re
import unicodedata
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
    # set for stage-2 findings: "P@2" — the variable and assignment line the
    # decoded payload was carried in
    decoded_from: str = ""

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
            "profile_variant": self.profile,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "suppressed": self.suppressed,
            "counts": self.counts,
            "verdicts": self.verdicts,
            "confirmed": len(self.confirmed()),
            "findings": [f.to_dict() for f in self.findings],
            "demoted": [f.to_dict() for f in self.demoted],
        }


# --- F5: invisible-character smuggling -----------------------------------------
# Zero-width/format characters spliced into a directive ("Ig\u200bnore all ...") hide
# it from pattern matching while the rendered text still reads as the instruction.
# The fix is a second matching pass over the normalized text; the raw pass keeps the
# invisible-character rules (SS008-SS011) firing on the original bytes.
INVISIBLE_NORM_RULE_ID = "SS039"  # marker rule, emitted by the normalization pass only
INVISIBLE_EXTRA = "\u00ad\u034f"  # soft hyphen, combining grapheme joiner (Mn, not Cf)


def _normalize_invisibles(text: str) -> tuple[str, list[int], set[int]]:
    """NFKC + strip format/soft-hyphen/CGJ characters.

    Returns (normalized text, normalized-index -> original-offset map, line numbers
    that had a character stripped). Newlines are never stripped, so line numbers
    computed through the offset map are exact even though lengths shift.
    """
    out: list[str] = []
    idx: list[int] = []
    stripped_lines: set[int] = set()
    line = 1
    for i, ch in enumerate(text):
        if ch == "\n":
            out.append(ch)
            idx.append(i)
            line += 1
        elif unicodedata.category(ch) == "Cf" or ch in INVISIBLE_EXTRA:
            stripped_lines.add(line)
        else:
            for nch in unicodedata.normalize("NFKC", ch):
                out.append(nch)
                idx.append(i)
    return "".join(out), idx, stripped_lines


# --- F7: stage-2 obfuscation ----------------------------------------------------
# A payload assigned to a variable as a base64/hex blob on one line and executed
# from another. Correlated, not assumed: the file must reference the variable from
# an exec/eval/decode line — a blob without an execution line is inert data (test
# fixtures are full of base64 and must not light up).
_B64_VAR = re.compile(r"""^\s*([A-Za-z_]\w*)\s*=\s*["']?([A-Za-z0-9+/]{16,}={0,2})["']?\s*$""")
_XHEX_VAR = re.compile(r"""^\s*([A-Za-z_]\w*)\s*=\s*["']((?:\\x[0-9a-fA-F]{2}){8,})["']\s*$""")
_HEX_VAR = re.compile(r"""^\s*([A-Za-z_]\w*)\s*=\s*["']?([0-9a-fA-F]{16,})["']?\s*$""")
_EXEC_LINE = re.compile(
    r"\b(exec|eval|system|popen|subprocess|b64decode|fromhex|unhexlify|"
    r"gzip\.decompress|zlib\.decompress|base64\s+-d)\b", re.IGNORECASE)


def _decode_blob(blob: str, kind: str, exec_line: str) -> str:
    """Decode an assignment blob to text, or "" if it is not decodable text.
    Any malformed blob is simply not a payload."""
    try:
        if kind == "xhex":
            raw = bytes(int(h, 16) for h in re.findall(r"\\x([0-9a-fA-F]{2})", blob))
        elif kind == "hex":
            if len(blob) % 2:
                return ""
            raw = binascii.unhexlify(blob)  # spelled this way: the hex-API name is itself an SS015 trigger
        else:  # b64 — the gzip.decompress variant unwraps one more layer
            padded = blob + "=" * (-len(blob) % 4)
            raw = base64.b64decode(padded, validate=True)
            if re.search(r"gzip\.decompress|zlib\.decompress", exec_line, re.I):
                raw = gzip.decompress(raw)
        return raw.decode("utf-8")  # strict: binary garbage is not a payload
    except (ValueError, binascii.Error, OSError, EOFError, UnicodeDecodeError):
        return ""


def _stage2_payloads(text: str) -> list[tuple[int, int, str, str]]:
    """(assignment line, execution line, decoded text, variable name) for every
    blob variable this file also executes/decodes."""
    lines = text.splitlines()
    out: list[tuple[int, int, str, str]] = []
    for i, line in enumerate(lines):
        var = blob = kind = None
        for rx, k in ((_XHEX_VAR, "xhex"), (_HEX_VAR, "hex"), (_B64_VAR, "b64")):
            m = rx.match(line)
            if m:
                var, blob, kind = m.group(1), m.group(2), k
                break
        if blob is None:
            continue
        for j, other in enumerate(lines):
            if j == i or not _EXEC_LINE.search(other):
                continue
            if not re.search(rf"\b{re.escape(var)}\b", other):
                continue
            decoded = _decode_blob(blob, kind, other)
            if decoded:
                out.append((i + 1, j + 1, decoded, var))
            break  # first execution line settles it, decoded or not
    return out


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
              honor_ignores: bool = False) -> tuple[list[Finding], bool, int, str,
                                                    list[Finding]]:
    """Scan one file. Returns (candidates, scanned?, suppressed, text, final).

    Candidates are unverified: `scan_path` runs them through the verifier before they
    become findings. Correlation rules (`requires_pattern`) are resolved here, because
    only this function has the whole file text. `final` carries evidence-backed
    findings (invisible-unicode marker, stage-2 decoded payloads) that skip grading
    because the evidence is the decode itself, not a judgement about the line.
    """
    if not _should_scan(path):
        return [], False, 0, "", []
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [], False, 0, "", []
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], False, 0, "", []
    candidates: list[Finding] = []
    final: list[Finding] = []
    suppressed = 0
    rel = str(path.relative_to(root)) if path != root else path.name
    lines = text.splitlines()
    if honor_ignores and NOQA_FILE in "\n".join(lines[:10]):
        return [], True, len(lines), text, []  # wholesale suppression, counted as suppressed
    rule_by_id = {r.id: r for r in rules}
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

    # Second pass over the normalized text (F5): same rules, run against the file
    # with invisibles stripped and compatibility forms folded, so a directive
    # smuggled as "Ig\u200bnore ..." matches. Hits the raw pass already found at
    # the same line are not re-emitted.
    norm, norm_idx, stripped_lines = _normalize_invisibles(text)
    if norm != text:
        seen = {(c.rule_id, c.line) for c in candidates}
        revealed: list[int] = []
        for rule in rules:
            if rule.pattern is None or rule.id == INVISIBLE_NORM_RULE_ID:
                continue
            if rule.requires_pattern is not None and not rule.requires_pattern.search(text):
                continue
            for m in rule.pattern.finditer(norm):
                orig = norm_idx[m.start()] if m.start() < len(norm_idx) else len(text) - 1
                line = text.count("\n", 0, orig) + 1
                if (rule.id, line) in seen:
                    continue
                seen.add((rule.id, line))
                snippet = lines[line - 1].strip()[:200] if 0 < line <= len(lines) else m.group(0)[:200]
                candidates.append(Finding(
                    rule_id=rule.id, severity=rule.severity, title=rule.title,
                    category=rule.category, owasp=rule.owasp, file=rel, line=line,
                    snippet=snippet, description=rule.description, kind=rule.kind,
                ))
                revealed.append(line)
        smuggled = next((n for n in revealed if n in stripped_lines), None)
        if smuggled is not None:
            marker = rule_by_id.get(INVISIBLE_NORM_RULE_ID)
            if marker is not None:
                final.append(Finding(
                    rule_id=marker.id, severity=marker.severity, title=marker.title,
                    category=marker.category, owasp=marker.owasp, file=rel, line=smuggled,
                    snippet=lines[smuggled - 1].strip()[:200] if smuggled <= len(lines) else "",
                    description=marker.description, kind=marker.kind,
                    verdict="exploitable",
                    reason="invisible characters normalized — this line matched a rule "
                           "only after zero-width/format characters were stripped",
                ))

    # Stage-2 decode (F7): payload blobs that this file also executes.
    for assign_line, exec_line, decoded, var in _stage2_payloads(text):
        for rule in rules:
            if rule.pattern is None or rule.id == INVISIBLE_NORM_RULE_ID:
                continue
            if rule.requires_pattern is not None and not rule.requires_pattern.search(decoded):
                continue
            m = rule.pattern.search(decoded)
            if not m:
                continue
            final.append(Finding(
                rule_id=rule.id, severity=rule.severity, title=rule.title,
                category=rule.category, owasp=rule.owasp, file=rel, line=exec_line,
                snippet=lines[exec_line - 1].strip()[:200] if exec_line <= len(lines) else "",
                description=rule.description, kind=rule.kind, verdict="exploitable",
                reason=f"confirmed from decoded payload of {var} (assigned on line "
                       f"{assign_line}): {m.group(0)[:60]!r} in the decoded text",
                decoded_from=f"{var}@{assign_line}",
            ))
    return candidates, True, suppressed, text, final


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
    final: list[Finding] = []
    for p in _iter_target_files(root):
        if excludes and _is_excluded(str(p.relative_to(root)) if p != root else p.name, excludes):
            result.files_skipped += 1
            continue
        found, scanned, suppressed, text, file_final = scan_file(
            p, rules, root, honor_ignores=honor_ignores)
        if scanned:
            result.files_scanned += 1
            result.suppressed += suppressed
            if found:
                candidates.extend(found)
                sources[found[0].file] = text
            final.extend(file_final)
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
    result.findings.extend(final)  # evidence-backed, already graded by the scanner

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
