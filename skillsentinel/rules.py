"""Detection rules catalog for SkillSentinel.

The catalog lives in rules/rules.json (JSON — zero-dependency, stdlib json).
This module loads and validates it.

Three fields do the precision work, and they replace the old `applies_to` guesswork:

- `kind`: `intent` (exploitation — a directive to an agent, no benign reading)
  or `capability` (dual-use — reading a credential file is normal for a backup skill).
- `context`: `directive` (agent instruction files) / `code` / `any`. A rule scoped to
  `code` firing inside a README is not a finding.
- `not_pattern`: cancels a hit whose own line is documentation, negation or a
  placeholder. Applied as a verdict (`low_trust`), never as a silent drop.
- `requires_pattern`: file-level correlation. A base64 blob is only interesting if the
  same file also decodes base64; otherwise the rule is guessing.
"""

from __future__ import annotations

import json
import re
import site
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

def _default_rules_path() -> Path:
    """Locate the rule catalog in both layouts.

    Source checkout: <repo>/rules/rules.json. Installed wheel: the data file lands
    in <prefix>/share/skillsentinel/rules/rules.json (see [tool.setuptools.data-files])
    while site-packages/skillsentinel/ has no sibling rules/ directory. A
    `pip install --user` wheel lands the data file under the *user base*
    (<userbase>/share/...), not under sys.prefix, so that layout is probed too.
    """
    pkg_dir = Path(__file__).resolve().parent
    candidates = [
        pkg_dir.parent / "rules" / "rules.json",                     # source tree
        Path(sys.prefix) / "share" / "skillsentinel" / "rules" / "rules.json",  # installed
    ]
    if site.USER_BASE:  # None in some embedded interpreters
        candidates.append(Path(site.USER_BASE) / "share" / "skillsentinel"
                          / "rules" / "rules.json")              # pip install --user
    for c in candidates:
        if c.is_file():
            return c
    return candidates[0]  # missing path -> the caller's error names the source layout


RULES_PATH = _default_rules_path()

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
KINDS = {"intent", "capability"}
CONTEXTS = {"directive", "code", "any"}

# Doc-context demotion policy (card t_3501ae36). A match sitting in a
# documentation context — a fenced code block, an inline code span, a
# blockquote line, a markdown table row, an example/usage section, or a
# JSONL log line quoting an earlier command — is a quoted specimen, not
# the artifact acting. That reading is granted to every rule class except
# the two for which prose is the attack surface wherever it is quoted
# from: injection directives (prompt-injection, invisible-unicode — the
# doc_surface family) and download-and-exec (rce-download — a piped
# installer is the payload inside a fence too). Even those two keep the
# specimen reading when the fence is explicitly documentation-framed
# (see DOC_FRAME): real skills legitimately document `curl … | bash`
# installers under Installation/Quick Start headings.
NEVER_DEMOTE_CATEGORIES = frozenset(
    {"prompt-injection", "invisible-unicode", "rce-download"})

# Fail-closed combo signal (card t_3501ae36, rework): reading a secret and
# shipping it out (or staging it through a shell) within the same few lines is
# exfiltration, wherever it sits — a fence, an inline code span, a blockquote,
# a table row, an example/usage section or a JSONL log line never turns that
# pair into a quoted specimen, because a copy-paste-runnable two-liner is
# exactly what "documentation" framing hides best (the C1 probe: a fenced
# python block in a SKILL.md that reads a private key and posts it to a
# collector). Narrow by design: each side alone is graded exactly as before
# (a backup skill that reads credentials, an install block that pipes a
# downloader into a shell); only BOTH inside one +-5-line window forbid
# demotion.
#
# Two deliberate narrowings, both measured on the live corpus, the repo
# self-scan and the pinned fixtures (the persistence fixture's rc-writer
# line, the changelog's RCE-class line, the GitHub-API table in
# pr-workflow.md):
#   1. The env-var name class is CASE-SENSITIVE — lowercase `token`/`secret`
#      as prose words must not arm the combo; the uppercase constants a
#      payload actually reads can. An env-var name also arms the combo only
#      from the matched line itself (see has_exfil_combo) — a name in prose
#      five lines from a data-flagged command is an API table, not exfil.
#   2. A bare pipe into sh/bash is NOT on the send side — it is mention-not-use
#      in every category enumeration (a changelog line naming the RCE class),
#      and the executable shape it names is owned by the rce-download category,
#      which NEVER_DEMOTE_CATEGORIES already keeps un-demoted wherever it is
#      quoted. The send side keeps the exfil shapes: POST/PUT/PATCH, the
#      data/upload flags below, nc/scp/base64-pipes (C1's POST call included).
# Secret paths mirror the credential surface the catalog already keys on
# (SS021/SS022/SS026).
SECRET_SRC = re.compile(
    r"(?:"
    r"\.ssh[/\\][^\s\"'`]*|id_rsa|id_ed25519|id_ecdsa"       # key files
    r"|\.aws[/\\]credentials|\.netrc\b|/etc/shadow"
    r"|\.kube[/\\]config|\.gnupg[/\\]"
    r"|(?<![\w.-])\.env\b"                                    # env file, not .environment
    r")",
    re.IGNORECASE)

# Uppercase by construction: env vars are shouted, prose is not.
SECRET_ENV_NAMES = re.compile(
    r"\b(?:GITHUB_TOKEN|API_KEY|APIKEY|ACCESS_TOKEN|"
    r"AWS_SECRET_ACCESS_KEY|SECRET|PASSWORD|PASSWD|TOKEN)\b")

# Network egress / subprocess staging: the send side of the combo. GET-style
# fetches (requests.get, plain curl without a data flag) are reading, not
# sending — they do not arm the combo.
EGRESS = re.compile(
    r"(?:"
    r"requests\.(?:post|put|patch)\b"
    r"|urlopen\b|urllib\.[^\n\"']{0,80}\bPost\b"
    r"|(?:curl|wget)\b[^|\n]{0,120}"
    r"(?:--data(?:-[a-z]+)?|-d\b|--upload-file|-T\b|--form|-F\b|-T\s"
    r"|--post-file|--body-(?:data|file))"
    r"|fetch\s*\([^)]{0,120}method\s*:\s*['\"](?:POST|PUT|PATCH)"
    r"|\b(?:nc|netcat)\b|\bscp\b"
    r"|base64\s*\|"
    r")",
    re.IGNORECASE)

COMBO_WINDOW = 5


def has_exfil_combo(lines: list[str], line_no: int) -> bool:
    """Do (a) a secret source and (b) egress/subprocess both appear within
    +-COMBO_WINDOW lines of `line_no` (1-based)? Path-shaped secret evidence
    (a key file, a credentials store) spans the whole window — a staged
    read-then-post is the payload. An env-var NAME is ubiquitous in prose
    ("set GITHUB_TOKEN before running", GitHub-API tables that never ship the
    token), so it arms the combo only from the matched line itself — the line
    where the hit and the send stand together."""
    if not lines:
        return False
    lo = max(0, line_no - 1 - COMBO_WINDOW)
    hi = min(len(lines), line_no + COMBO_WINDOW)
    window = "\n".join(lines[lo:hi])
    if not EGRESS.search(window):
        return False
    if SECRET_SRC.search(window):
        return True
    hit_line = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
    return bool(SECRET_ENV_NAMES.search(hit_line))

# A heading whose section is example/usage documentation.
DOC_SECTION_HEADING = re.compile(r"\b(?:example|usage)\b", re.IGNORECASE)

# Frame evidence that keeps even an injection/download-exec fence a
# specimen: an Installation/Example/Quick Start heading, an intro line
# above the fence, or an in-fence `#` installer comment. The boundaries
# exclude tokens glued into hosts/paths (`x.example`, `install.sh`) — a
# URL the payload cites is not framing prose, and the payload line itself
# is never frame evidence (an attacker controls it).
DOC_FRAME = re.compile(
    r"(?<![\w./@-])(?:example|install\w*|usage|quick[ -]?starts?|sampl\w*|"
    r"demos?)(?![\w./@-])", re.IGNORECASE)

# A pipe or redirect into a shell interpreter — the download-and-exec
# shape that an unframed fence does not excuse. `curl … | python -c` is
# output parsing (data plumbing ubiquitous in API docs), not an exec pipe.
SHELL_PIPE = re.compile(r"[|>]\s*(?:sudo\s+)?(?:bash|zsh|sh|dash|ksh)\b",
                        re.IGNORECASE)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str
    description: str
    owasp: str
    pattern: Pattern[str] | None
    kind: str = "intent"
    context: str = "any"
    not_pattern: Pattern[str] | None = None
    requires_pattern: Pattern[str] | None = None
    escalate_pattern: Pattern[str] | None = None
    syntax: str = "regex"
    # `doc_surface`: this rule's instruction surface includes documentation.
    # A README.md is read by an agent exactly like a SKILL.md is; scoping an
    # injection rule to directive files alone leaves the most-read file in the
    # repository outside the detection surface. Only meaningful for
    # kind=intent + context=directive (enforced in _compile): the payload is an
    # instruction, not a dual-use primitive, so prose in a doc *is* the attack.
    doc_surface: bool = False

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]


def _re(raw: Any, default_flags: int = re.IGNORECASE) -> Pattern[str] | None:
    if not raw:
        return None
    try:
        return re.compile(raw, default_flags)
    except (re.error, TypeError) as e:
        # re.PatternError is not a ValueError: without this wrap a bad regex
        # in the catalog escapes as an "internal error" instead of a bad input.
        raise ValueError(f"invalid regex {raw!r}: {e}") from None


def _compile(raw: dict[str, Any]) -> Rule:
    for key in ("id", "title", "category", "severity"):
        if key not in raw:
            raise ValueError(f"rule entry is missing required key {key!r}")
    flags = 0
    if raw.get("ignore_case", True):
        flags |= re.IGNORECASE
    if raw.get("multiline", False):
        flags |= re.MULTILINE
    kind = raw.get("kind", "intent")
    context = raw.get("context", "any")
    if kind not in KINDS:
        raise ValueError(f"rule {raw['id']}: bad kind {kind!r}")
    if context not in CONTEXTS:
        raise ValueError(f"rule {raw['id']}: bad context {context!r}")
    doc_surface = bool(raw.get("doc_surface", False))
    if doc_surface and (kind != "intent" or context != "directive"):
        # A dual-use primitive (a piped installer, an authorized_keys write) in
        # prose is mention-not-use wherever it sits; widening its surface to docs
        # would make every install instruction a finding. Reject the flag instead
        # of silently ignoring it, so a copy-paste cannot widen a capability rule.
        raise ValueError(
            f"rule {raw['id']}: doc_surface requires kind=intent and "
            f"context=directive (got kind={kind!r}, context={context!r})")
    return Rule(
        id=raw["id"],
        title=raw["title"],
        category=raw["category"],
        severity=raw["severity"],
        description=raw.get("description", ""),
        owasp=raw.get("owasp", ""),
        pattern=_re(raw.get("pattern"), flags),
        kind=kind,
        context=context,
        not_pattern=_re(raw.get("not_pattern")),
        # requires_pattern does file-level correlation, so it must honor the
        # rule's own flags (a multiline ^...$ blob-assignment shape would
        # otherwise never match past line one).
        requires_pattern=_re(raw.get("requires_pattern"), flags),
        escalate_pattern=_re(raw.get("escalate_pattern")),
        doc_surface=doc_surface,
    )


def load_rules(path: Path | str | None = None) -> list[Rule]:
    p = Path(path) if path else RULES_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    # A valid-JSON document of the wrong shape is a bad input file, not a bug:
    # every shape/regex problem here is ValueError, which both call sites wrap
    # into an input error naming the path (exit 2) — never KeyError/TypeError
    # leaking as "internal error" exit 3. An explicit empty 'rules' array is
    # NOT a shape error: it loads as zero rules and the caller (scan_path)
    # refuses a zero-rule catalog as an input error.
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError("not a rules catalog: expected an object "
                         "with a 'rules' array")
    rules = []
    for i, raw in enumerate(data["rules"]):
        if not isinstance(raw, dict):
            raise ValueError(f"rule #{i}: expected an object, "
                             f"got {type(raw).__name__}")
        rules.append(_compile(raw))
    ids = [r.id for r in rules]
    if len(ids) != len(set(ids)):
        dupes = {i for i in ids if ids.count(i) > 1}
        raise ValueError(f"duplicate rule ids: {dupes}")
    for r in rules:
        if r.severity not in SEVERITY_ORDER:
            raise ValueError(f"bad severity in rule {r.id}: {r.severity}")
        if r.pattern is None:
            raise ValueError(f"rule {r.id} has no pattern")
    return rules
