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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.json"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
KINDS = {"intent", "capability"}
CONTEXTS = {"directive", "code", "any"}


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

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]


def _re(raw: Any, default_flags: int = re.IGNORECASE) -> Pattern[str] | None:
    if not raw:
        return None
    return re.compile(raw, default_flags)


def _compile(raw: dict[str, Any]) -> Rule:
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
        requires_pattern=_re(raw.get("requires_pattern")),
        escalate_pattern=_re(raw.get("escalate_pattern")),
    )


def load_rules(path: Path | str | None = None) -> list[Rule]:
    p = Path(path) if path else RULES_PATH
    data = json.loads(p.read_text(encoding="utf-8"))
    rules = [_compile(r) for r in data["rules"]]
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
