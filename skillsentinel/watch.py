"""`watch` subcommand: hash snapshot of installed skills + drift / rug-pull detection."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .scanner import (Finding, InputError, _iter_target_files, scan_path,
                      sha256_file)

SNAPSHOT_VERSION = 1


@dataclass
class Entry:
    path: str
    sha256: str
    size: int


def _iter_snapshot_files(root: Path) -> Iterable[Path]:
    """Every file in the tree except `.git/`.

    Deliberately no suffix filter and no skip list, unlike the scanner's
    walker: a snapshot that only watches "interesting" files is a rug-pull
    tunnel — `node_modules/`, `.venv/` and binary blobs must be hashed too.
    `.git/` alone is excluded: it is repo machinery that rewrites itself on
    every commit and would drown every diff in noise.
    """
    for p in sorted(root.rglob("*")):
        if ".git" in p.relative_to(root).parts:
            continue
        if p.is_file():  # follows symlinks; a broken link has nothing to hash
            yield p


def snapshot_dir(root: Path) -> dict:
    root = root.resolve()
    if not root.is_dir():
        # V1: a typo'd path used to yield a 0-entry snapshot that `init`
        # reported as success ("0 files") — every later diff then watched the
        # wrong tree and always reported it clean.
        raise InputError(f"watch path is not an existing directory: {root}")
    entries = []
    for p in _iter_snapshot_files(root):
        try:
            entries.append(Entry(str(p.relative_to(root)), sha256_file(p), p.stat().st_size))
        except OSError:
            continue
    if not entries:
        # Defence in depth, mirroring the scanner's empty-scan refusal: a
        # 0-entry snapshot is indistinguishable from having watched the wrong
        # path, so it is refused instead of recorded as a baseline.
        raise InputError(f"no files found under {root} — "
                         "refusing to record an empty snapshot")
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


def rescan_changes(root: Path, diff: dict) -> list[Finding]:
    """Re-scan the changed/added files of a diff_snapshots() result.

    Returns their confirmed findings so `watch diff --rescan` explains WHAT
    drifted, not only that something did. Removed files have nothing left to
    scan and are skipped. Each file is scanned standalone (path == root), so
    `file` in the findings is the basename.
    """
    findings: list[Finding] = []
    for rel in sorted(set(diff.get("added", [])) | set(diff.get("changed", []))):
        p = Path(root) / rel
        if not p.is_file():
            continue  # vanished between diff and rescan — the removal already reports it
        findings.extend(scan_path(p).findings)
    return findings
