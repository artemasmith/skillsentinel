"""`watch` subcommand: hash snapshot of installed skills + drift / rug-pull detection."""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from pathlib import Path

from .scanner import _iter_target_files, sha256_file

SNAPSHOT_VERSION = 1


@dataclass
class Entry:
    path: str
    sha256: str
    size: int


def snapshot_dir(root: Path) -> dict:
    root = root.resolve()
    entries = []
    for p in _iter_target_files(root):
        try:
            entries.append(Entry(str(p.relative_to(root)), sha256_file(p), p.stat().st_size))
        except OSError:
            continue
    return {
        "version": SNAPSHOT_VERSION,
        "root": str(root),
        "entries": {e.path: {"sha256": e.sha256, "size": e.size} for e in entries},
    }


def write_snapshot(root: Path, out: Path) -> dict:
    snap = snapshot_dir(root)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snap, indent=2, sort_keys=True), encoding="utf-8")
    return snap


def diff_snapshots(old: dict, new: dict) -> dict:
    old_e, new_e = old["entries"], new["entries"]
    added = sorted(set(new_e) - set(old_e))
    removed = sorted(set(old_e) - set(new_e))
    changed = sorted(
        k for k in set(old_e) & set(new_e) if old_e[k]["sha256"] != new_e[k]["sha256"]
    )
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "clean": not (added or removed or changed),
    }


def load_snapshot(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))
