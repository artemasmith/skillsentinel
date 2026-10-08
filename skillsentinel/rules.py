"""Detection rules catalog for SkillSentinel.

The catalog lives in rules/rules.json (JSON — zero-dependency, stdlib json).
This module loads and validates it.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern

RULES_PATH = Path(__file__).resolve().parent.parent / "rules" / "rules.json"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    category: str
    severity: str
    description: str
    owasp: str
    applies_to: tuple[str, ...]  # file glob-ish targets: "text", "code", "mcp_json", ...
    pattern: Pattern[str] | None
    syntax: str = "regex"  # "regex" | "unicode-category" handled via pattern anyway

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]


def _compile(raw: dict[str, Any]) -> Rule:
    pat = raw["pattern"]
    flags = 0
    if raw.get("ignore_case", True):
        flags |= re.IGNORECASE
    if raw.get("multiline", False):
        flags |= re.MULTILINE
    return Rule(
        id=raw["id"],
        title=raw["title"],
        category=raw["category"],
        severity=raw["severity"],
        description=raw.get("description", ""),
        owasp=raw.get("owasp", ""),
        applies_to=tuple(raw.get("applies_to", ["text"])),
        pattern=re.compile(pat, flags) if pat else None,
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
    return rules
