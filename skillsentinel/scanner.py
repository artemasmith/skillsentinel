"""Core scanner: walk a tree, match rules, emit findings."""

from __future__ import annotations

import base64
import binascii
import errno
import fnmatch
import gzip
import hashlib
import json
import os
import re
import stat
import tarfile
import time
import unicodedata
import zlib
import zipfile
from dataclasses import dataclass, field, asdict
from itertools import islice
from pathlib import Path, PurePosixPath
from typing import Iterable

from . import __version__
from .rules import (DOC_FRAME, DOC_SECTION_HEADING, NEVER_DEMOTE_CATEGORIES,
                    RULES_PATH, Rule, SHELL_PIPE, load_rules, SEVERITY_ORDER)
from .verifier import (VERDICT_ORDER, VERIFIERS_BY_NAME, _ctx_of,
                       _directive_roots, _fenced_state, _in_code_span,
                       bind_rules, verify_findings)

MAX_FILE_BYTES = 2_000_000  # larger files are scanned as head+tail windows
SCAN_WINDOW_BYTES = 512 * 1024  # window size on each side of an oversize file
BINARY_PROBE_BYTES = 4096  # the binary sniff reads only this much of a file

# Directory subtrees the walker never enters. `.git` is special-cased below:
# all of it is repo metadata except `.git/hooks/` — hook scripts are executable
# attack surface (a payload planted there fires on the user's next `git pull`).
SKIP_DIR_PARTS = {".venv", "venv", "node_modules", "__pycache__"}
HOOKS_DIR = "hooks"

# A `.skillsentinelignore` pattern from this set excludes the whole skill (with
# --honor-ignores). Scanning nothing and reporting "clean" is the worst lie a
# security tool can tell, so it is refused as an input error instead.
WHOLE_SKILL_IGNORE_PATTERNS = {"*", "**", "**/*"}

# Skill manifests: a `.skillsentinelignore` that drops the manifest silences the
# file every directive lives in (D2) — the scan that remains proves nothing.
MANIFEST_NAMES = {"skill.md", "skill.yaml", "skill.json", "plugin.json"}

# Executable content whose suffix does not announce it. The verifier grades by
# suffix-derived context, so these are verified under a shell-script alias —
# see `_verification_alias`.
EXECUTABLE_BLOB_SUFFIXES = {".pyc", ".bin"}
VERIFICATION_ALIAS_SUFFIX = ".skillsentinel-exec.sh"

# R3 (v0.3.4): archives shipped as skills are opened and their text members
# scanned in memory — nothing is ever extracted to disk, so zip-slip has
# nowhere to write and a bomb is bounded by the read itself. Three guards
# refuse the archive (with a warning) instead of trusting it.
ARCHIVE_SUFFIXES_ZIP = (".zip", ".whl")
ARCHIVE_SUFFIXES_TAR = (".tar.gz", ".tgz")
DEFAULT_ARCHIVE_MAX_BYTES = 5_000_000  # uncompressed member budget (--archive-max-bytes)
ARCHIVE_MAX_ENTRIES = 200              # member-count cap
ARCHIVE_BOMB_RATIO = 100               # compressed:uncompressed ratio cap

# Inline suppression markers. They are honored ONLY with `--honor-ignores`: a scanner
# whose findings a scanned artifact can silence is itself the vulnerability (an
# attacker ships a skill that suppresses its own detection). Default = markers are
# plain text and everything is reported.
NOQA = "skillsentinel:ignore"
NOQA_FILE = "skillsentinel:ignore-file"

_rules_version_cache: str | None = None

# First non-whitespace index of a line, C-speed, without strip()'s full copy:
# a 1 MB single-line bundle matched many times must not be copied per match.
_NONSPACE = re.compile(r"\S", re.UNICODE)


def _line_snippet(line: str, limit: int = 200) -> str:
    """The line's first `limit` characters after str.strip(), cheaply.

    Equivalent to `line.strip()[:limit]`: stripping only removes leading
    whitespace (skipped via `_NONSPACE`) and trailing whitespace beyond the
    window, so the visible result is `line[start:start + limit]` — with an
    rstrip only when the stripped line is shorter than the limit.
    """
    m = _NONSPACE.search(line)
    start = m.start() if m else len(line)
    snippet = line[start:start + limit]
    return snippet.rstrip() if len(snippet) < limit else snippet


def rules_version() -> str:
    """The catalog's own `_version` key (rules/rules.json), read once per process."""
    global _rules_version_cache
    if _rules_version_cache is None:
        try:
            _rules_version_cache = json.loads(
                RULES_PATH.read_text(encoding="utf-8")).get("_version", "")
        except (OSError, json.JSONDecodeError):
            _rules_version_cache = ""
    return _rules_version_cache


class InputError(Exception):
    """Bad input: missing path, unreadable file, broken rules, expired --timeout.

    The CLI maps it to one stderr line and exit code 2 — never a traceback.
    """


class UnreadableFileError(InputError):
    """One file could not be read (mode 000, vanished mid-scan).

    Unlike a plain InputError the walk does not abort: `scan_path` records the
    path on the result and keeps scanning, so the readable files' findings
    survive; the CLI warns about the recorded files and still exits 2.
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
    ignored_files: list[str] = field(default_factory=list)
    truncated: bool = False
    truncated_files: list[str] = field(default_factory=list)
    limit_reached: tuple[int, int] | None = None
    undecodable_files: list[str] = field(default_factory=list)
    unreadable_files: list[str] = field(default_factory=list)
    binary_files_skipped: int = 0
    # R1d/R3b: every refused entry (unfollowed/broken/looping symlink, guarded
    # archive) lands here with its reason — a skip the output does not explain
    # is indistinguishable from a clean scan.
    warnings: list[str] = field(default_factory=list)

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
            "version": __version__,
            "rules_version": rules_version(),
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
            "ignored_files": self.ignored_files,
            "truncated": self.truncated,
            "truncated_files": self.truncated_files,
            "limit_reached": list(self.limit_reached) if self.limit_reached else None,
            "undecodable_files": self.undecodable_files,
            "unreadable_files": self.unreadable_files,
            "binary_files_skipped": self.binary_files_skipped,
            "warnings": self.warnings,
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


def _stage2_payloads(text: str, *, deadline: float | None = None,
                     timeout: float | None = None
                     ) -> list[tuple[int, int, str, str]]:
    """(assignment line, execution line, decoded text, variable name) for every
    blob variable this file also executes/decodes.

    The cross-reference is quadratic in pathological files (8000 hex
    assignments), so the `--timeout` deadline is checked in BOTH loops (D7):
    expiry raises InputError instead of outliving the budget.
    """
    def _check_deadline() -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise InputError(f"timed out after {timeout:g} s")

    lines = text.splitlines()
    out: list[tuple[int, int, str, str]] = []
    for i, line in enumerate(lines):
        _check_deadline()
        var = blob = kind = None
        for rx, k in ((_XHEX_VAR, "xhex"), (_HEX_VAR, "hex"), (_B64_VAR, "b64")):
            m = rx.match(line)
            if m:
                var, blob, kind = m.group(1), m.group(2), k
                break
        if blob is None:
            continue
        for j, other in enumerate(lines):
            _check_deadline()  # inner half of the quadratic: bound it too
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


def _git_visible(parts: tuple[str, ...]) -> bool:
    """`.git/**` is excluded, but `.git/hooks/**` is scanned: hook scripts run."""
    if ".git" not in parts:
        return True
    i = parts.index(".git")
    return len(parts) > i + 1 and parts[i + 1] == HOOKS_DIR


@dataclass
class _WalkEntry:
    """One entry the walk produced: a file to scan, or a refused entry.

    `path` is None for entries the link policy declines (broken link, loop,
    `--no-follow-symlinks`); `reason` then carries the skip reason the result
    must report instead of silently shrinking the scan (R1d). Files reached
    through a symlink carry a `rel` of the form `link -> target` (R1b) so a
    finding names both.
    """
    path: Path | None
    rel: str
    reason: str = ""


def _dir_key(path: Path) -> tuple[int, int]:
    st = path.stat()
    return st.st_dev, st.st_ino


def _within_root(target: Path, root: Path) -> bool:
    """Is `target` inside the scanned `root`? (Both resolved.)"""
    return target == root or root in target.parents


def _dir_visible(parts: tuple[str, ...]) -> bool:
    """May the walker descend into this directory? Prunes skip-listed
    subtrees early (rglob walked them anyway; refusing at the branch is the
    same result for less work) and prunes `.git` to its `hooks/` branch."""
    for i, seg in enumerate(parts):
        if seg in SKIP_DIR_PARTS:
            return False
        if seg == ".git":
            rest = parts[i + 1:]
            return rest == () or (len(rest) >= 1 and rest[0] == HOOKS_DIR)
    return True


def _iter_target_files(root: Path, follow_symlinks: bool = True
                       ) -> Iterable[_WalkEntry]:
    """Yield every candidate entry under `root`, sorted for a stable order.

    Every file is a candidate regardless of suffix — a payload does not care
    which extension hides it. R1: symlinked directories are descended by
    default (a skills tree of symlinks — 35 of 37 entries in the reproduced
    install — is the normal layout, not an attack), and a visited set keyed
    by (st_dev, st_ino) makes loops and repeat targets terminate as refused
    entries instead of hangs. `--no-follow-symlinks` refuses every link with
    a reason. Out-of-root targets are followed; their files are reported as
    `link -> target` so the finding names both (R1b).
    """
    if root.is_file():
        yield _WalkEntry(root, root.name)
        return
    try:
        visited = {_dir_key(root)}  # a `link -> .` self-loop resolves here
    except OSError:
        visited = set()

    def _walk(directory: Path, logical: str,
              link_pair: tuple[str, str] | None) -> Iterable[_WalkEntry]:
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            return  # unreadable directory: scan_path's zero-scan refusal reports it
        for entry in entries:
            rel = f"{logical}/{entry.name}" if logical else entry.name
            parts = tuple(rel.split("/"))
            if any(seg in SKIP_DIR_PARTS for seg in parts):
                continue
            path = directory / entry.name
            if entry.is_symlink():
                yield from _symlink_entry(path, rel, follow_symlinks, visited)
                continue
            if entry.is_dir(follow_symlinks=False):
                # `_git_visible` would reject `.git` itself and the walk would
                # never reach `.git/hooks/**` — descent permission is
                # `_dir_visible`'s job; the file-level check below re-applies
                # the .git policy to leaves.
                if _dir_visible(parts):
                    try:
                        visited.add(_dir_key(path))
                    except OSError:
                        pass
                    yield from _walk(path, rel, link_pair)
                continue
            if entry.is_file(follow_symlinks=False) and _git_visible(parts):
                if link_pair is None:
                    yield _WalkEntry(path, rel)
                else:
                    # file under a symlinked directory: name link and target
                    sub = rel[len(link_pair[0]) + 1:]
                    yield _WalkEntry(path, f"{rel} -> {link_pair[1]}/{sub}")

    def _symlink_entry(path: Path, rel: str, follow: bool,
                       seen: set[tuple[int, int]]) -> Iterable[_WalkEntry]:
        try:
            st = os.stat(path)  # follows the chain; ELOOP on a cycle
        except OSError as e:
            # NB: this is a generator, so refusals must be *yielded* — a
            # `return (entry,)` would only set StopIteration.value and vanish.
            if e.errno == errno.ELOOP:
                yield _WalkEntry(None, rel, "symlink loop (ELOOP) — not followed")
            else:
                yield _WalkEntry(None, rel,
                                 "broken symlink (unresolvable target)")
            return
        if stat.S_ISDIR(st.st_mode):
            if not follow:
                yield _WalkEntry(None, rel,
                                 "symlink not followed (--no-follow-symlinks)")
                return
            key = (st.st_dev, st.st_ino)
            if key in seen:
                yield _WalkEntry(None, rel,
                                 "symlink loop — target directory already "
                                 "scanned, skipped")
                return
            seen.add(key)
            target = Path(os.path.realpath(path))
            # R1b: the 'link -> target' attribution names where content
            # really lives — only when that is OUTSIDE the scan root. An
            # in-root link (a convenience alias inside the tree) keeps its
            # plain relative path, which is already unambiguous.
            pair = None if _within_root(target, root) else (rel, str(target))
            yield from _walk(path, rel, pair)
            return
        if stat.S_ISREG(st.st_mode):
            if not follow:
                yield _WalkEntry(None, rel,
                                 "symlink not followed (--no-follow-symlinks)")
                return
            target = os.path.realpath(path)
            display = rel if _within_root(Path(target), root) \
                else f"{rel} -> {target}"
            yield _WalkEntry(path, display)
            return
        return  # fifo/socket/device behind a link: nothing to scan

    yield from _walk(root, "", None)


# BOM sniffing order matters: UTF-32-LE's BOM starts with UTF-16-LE's, so the
# longer prefix must win. Files written by `iconv -t UTF-16LE` carry no BOM at
# all — the NUL-density fallback below catches those.
_BOMS = ((b"\xff\xfe\x00\x00", "utf-32"), (b"\x00\x00\xfe\xff", "utf-32"),
         (b"\xef\xbb\xbf", "utf-8-sig"),
         (b"\xff\xfe", "utf-16"), (b"\xfe\xff", "utf-16"))

# C0 control bytes (tab/CR/LF excepted) plus DEL: a dense cluster of these in
# the first chunk is the fingerprint of binary content. Counted via translate
# so the sniff stays C-speed — it runs on every file of every walk.
_CONTROL_BYTES = bytes(b for b in range(0x20) if b not in (0x09, 0x0A, 0x0D)) + b"\x7f"

# V8: the controls plus every byte >= 0x80. Real-world binaries — PNG, gzip —
# keep their entropy in non-control bytes, so their fingerprint is density in
# this wider set combined with a failed strict UTF-8 decode. Same translate
# trick, same C-speed.
_NONPRINT_BYTES = _CONTROL_BYTES + bytes(range(0x80, 0x100))


def _read_head(path: Path) -> bytes:
    """The first BINARY_PROBE_BYTES of a file — all the binary sniff ever reads."""
    with path.open("rb") as fh:
        return fh.read(BINARY_PROBE_BYTES)


def _utf16_mostly_printable(head: bytes, bar: float) -> bool:
    """True if the chunk decodes as BOM-less UTF-16 at >= bar printable.

    The text escape both density branches of _looks_binary share: a chunk
    that reads as (mostly) printable UTF-16 in either endianness is a text
    file, not binary soup.
    """
    for enc in ("utf-16-le", "utf-16-be"):
        try:
            text = head.decode(enc)
        except UnicodeDecodeError:
            continue
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
        if printable >= len(text) * bar:
            return True
    return False


def _looks_binary(head: bytes) -> bool:
    """Cheap, deterministic binary sniff on a file's first chunk.

    Two densities, one 1/4 threshold. Control density (C0 minus tab/CR/LF
    plus DEL) at/above the threshold is the classic binary fingerprint,
    with the decode ladder's text escapes kept: a BOM, or a BOM-less
    control-dense chunk that still decodes as mostly-printable (>= 0.8)
    UTF-16, is text. Non-print density (controls + bytes >= 0x80) at the
    same threshold catches real-world binaries — PNG, gzip — whose entropy
    lives in non-control bytes, but only when the chunk also fails a strict
    UTF-8 decode: valid UTF-8 stays text however high its bytes run (unicode
    smuggling must keep getting scanned), and the UTF-16 escape still holds
    at a stricter >= 0.95 printable bar — random bytes luck into ~0.85-0.9
    printable UTF-16 (a gzip head sits at ~0.88), real UTF-16 text is
    essentially all printable. That branch also knows a NUL rule: a
    single-byte legacy encoding (cp1251, koi8-r, latin-1) never encodes a
    real character as NUL, so an undecodable non-print-dense chunk with
    zero NUL bytes is legacy text and stays scannable — real binaries
    carry NULs in their first chunk. Below both densities a file stays
    scannable —
    a bytecode blob with an embedded ASCII payload stays in the scan
    (latin-1 keeps its attack strings visible); only control or
    undecodable non-print soup is skipped.
    """
    if not head or any(head.startswith(bom) for bom, _ in _BOMS):
        return False
    controls = len(head) - len(head.translate(None, _CONTROL_BYTES))
    if controls * 4 >= len(head):
        return not _utf16_mostly_printable(head, 0.8)
    # V8 (review r1): control-sparse is not proof of text. Entropy hiding in
    # high bytes plus a failed strict UTF-8 decode is binary; the stricter
    # 0.95 bar on the UTF-16 escape keeps BOM-less UTF-16 text scannable.
    nonprint = len(head) - len(head.translate(None, _NONPRINT_BYTES))
    if nonprint * 4 >= len(head):
        try:
            head.decode("utf-8")
        except UnicodeDecodeError:
            # V8 (review r2): a single-byte legacy encoding (cp1251, koi8-r,
            # latin-1) can never encode a real character as NUL, so its
            # high-byte-dense prose carries zero NULs, while real binaries
            # all carry NULs in the first chunk. NUL-free soup here is
            # legacy text — keep it scannable instead of skipping a hostile
            # file as "binary" and reporting a false clean.
            if head.count(0) == 0:
                return False
            return not _utf16_mostly_printable(head, 0.95)
    return False


def _decode_scannable(raw: bytes) -> tuple[str, bool]:
    """Decode file bytes into scannable text. Returns (text, decodable).

    BOM first (UTF-8/16/32, both endiannesses), then a NUL-density fallback for
    BOM-less UTF-16 (an ASCII-range payload in UTF-16 is half NUL bytes), then
    UTF-8, then latin-1 as the never-fails last resort so attack strings in
    binaries stay visible. `decodable` is False only for that last resort when
    the result is mostly non-printable — callers report it loudly (D3).
    """
    for bom, enc in _BOMS:
        if raw.startswith(bom):
            try:
                text = raw.decode(enc)
            except UnicodeDecodeError:
                break  # lying BOM: fall through to the generic ladder
            if enc != "utf-8-sig":
                # Sanity-check the claim: text written in UTF-16/32 is nearly
                # always ASCII-range code points per char. A file that merely
                # *starts* with BOM-ish bytes (\xff\xfe\xfa...) decodes to
                # high-codepoint junk — treat that as a lying BOM and fall
                # through so the ASCII payload after it stays scannable.
                body = text[1:]  # skip the U+FEFF the BOM decodes to
                if body and (sum(1 for ch in body if ord(ch) < 0x80)
                             / max(len(body), 1)) < 0.5:
                    break
            return text, True
    if len(raw) >= 4 and raw.count(0) >= len(raw) // 4:
        # BOM-less UTF-16 heuristic: try both endiannesses, keep the one that
        # decodes to mostly-printable text (a real binary fails both checks).
        for enc in ("utf-16-le", "utf-16-be"):
            try:
                text = raw.decode(enc)
            except UnicodeDecodeError:
                continue
            printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
            if printable >= len(text) * 0.8:
                return text, True
    try:
        return raw.decode("utf-8"), True
    except UnicodeDecodeError:
        text = raw.decode("latin-1", errors="replace")
        printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
        return text, printable > 0 and printable >= len(text) * 0.5


def _read_scannable(path: Path) -> tuple[str, bool, bool]:
    """Read a file into scannable text. Returns (text, truncated, decodable).

    Oversize files are windowed (head + tail) instead of skipped: a rug pull
    must not be able to hide behind megabytes of padding. Content that is not
    valid UTF-8 — bytecode, binaries, mixed encodings — is decoded as latin-1
    so the attack strings inside are still visible to the rules; a decode that
    yields mostly non-printable garbage is flagged as not decodable so the
    caller can say so instead of reporting a silent empty scan (D3).
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
    text, decodable = _decode_scannable(raw)
    return text, truncated, decodable


def scan_file(path: Path, rules: list[Rule], root: Path,
              honor_ignores: bool = False, *,
              deadline: float | None = None,
              timeout: float | None = None,
              rel: str | None = None,
              ) -> tuple[list[Finding], int, str, bool, list[Finding], bool]:
    """Scan one file. Returns (candidates, suppressed, text, truncated, final,
    decodable).

    Candidates are unverified: `scan_path` runs them through the verifier
    before they become findings. Correlation rules (`requires_pattern`) are
    resolved in `_scan_text`, because only it has the whole file text.
    `final` carries evidence-backed findings (invisible-unicode marker,
    stage-2 decoded payloads) that skip grading because the evidence is the
    decode itself, not a judgement about the line.

    `rel` overrides the reported path (R1b `link -> target` display); the
    default is the path relative to `root`.

    `deadline` (from `--timeout SEC`) is checked between rules and inside
    match storms, so a single pathological file cannot outlive the budget —
    expiry raises the same InputError `scan_path` raises between files.
    """
    try:
        text, truncated, decodable = _read_scannable(path)
    except OSError as e:
        # unreadable (mode 000), vanished mid-scan: an input problem, not a bug.
        # Raised as UnreadableFileError so `scan_path` can record the file and
        # keep walking instead of discarding the readable files' findings (V5).
        raise UnreadableFileError(f"cannot read {path}: {e.strerror or e}") from None
    if rel is None:
        rel = str(path.relative_to(root)) if path != root else path.name
    candidates, suppressed, final = _scan_text(
        text, rel, rules, honor_ignores, deadline=deadline, timeout=timeout)
    return candidates, suppressed, text, truncated, final, decodable


def _scan_text(text: str, rel: str, rules: list[Rule], honor_ignores: bool, *,
               deadline: float | None = None,
               timeout: float | None = None,
               ) -> tuple[list[Finding], int, list[Finding]]:
    """Match `rules` against in-memory text, reported as `rel`.

    Returns (candidates, suppressed, final). The matcher half of `scan_file`,
    split out so archive members (R3) — which never become files on disk —
    run through the identical rule passes: raw, invisible-normalized, and
    stage-2 decoded payloads.
    """

    def _check_deadline() -> None:
        if deadline is not None and time.monotonic() > deadline:
            raise InputError(f"timed out after {timeout:g} s")

    candidates: list[Finding] = []
    final: list[Finding] = []
    suppressed = 0
    lines = text.splitlines()
    if honor_ignores and NOQA_FILE in "\n".join(lines[:10]):
        return [], len(lines), []  # wholesale suppression, counted as suppressed
    rule_by_id = {r.id: r for r in rules}
    for rule in rules:
        _check_deadline()
        if rule.pattern is None:
            continue
        # file-level correlation: a blob is not evidence unless the file also decodes it
        if rule.requires_pattern is not None and not rule.requires_pattern.search(text):
            continue
        # Line numbers are counted incrementally: finditer yields ascending,
        # non-overlapping matches, so counting "\n" from the previous match
        # start (not from 0) keeps a match-dense megabyte line linear.
        nl_cursor, nl_count = 0, 0
        for i, m in enumerate(rule.pattern.finditer(text)):
            if deadline is not None and not i & 0xFF:
                _check_deadline()  # a match storm must not outlive the budget
            nl_count += text.count("\n", nl_cursor, m.start())
            nl_cursor = m.start()
            line = nl_count + 1
            snippet = _line_snippet(lines[line - 1]) if 0 < line <= len(lines) else m.group(0)[:200]
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
            _check_deadline()
            if rule.pattern is None or rule.id == INVISIBLE_NORM_RULE_ID:
                continue
            if rule.requires_pattern is not None and not rule.requires_pattern.search(text):
                continue
            nl_cursor, nl_count = 0, 0
            for m in rule.pattern.finditer(norm):
                orig = norm_idx[m.start()] if m.start() < len(norm_idx) else len(text) - 1
                nl_count += text.count("\n", nl_cursor, orig)
                nl_cursor = orig
                line = nl_count + 1
                if (rule.id, line) in seen:
                    continue
                seen.add((rule.id, line))
                snippet = _line_snippet(lines[line - 1]) if 0 < line <= len(lines) else m.group(0)[:200]
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
                    snippet=_line_snippet(lines[smuggled - 1]) if smuggled <= len(lines) else "",
                    description=marker.description, kind=marker.kind,
                    verdict="exploitable",
                    reason="invisible characters normalized — this line matched a rule "
                           "only after zero-width/format characters were stripped",
                ))

    # Stage-2 decode (F7): payload blobs that this file also executes.
    for assign_line, exec_line, decoded, var in _stage2_payloads(
            text, deadline=deadline, timeout=timeout):
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
                snippet=_line_snippet(lines[exec_line - 1]) if exec_line <= len(lines) else "",
                description=rule.description, kind=rule.kind, verdict="exploitable",
                reason=f"confirmed from decoded payload of {var} (assigned on line "
                       f"{assign_line}): {m.group(0)[:60]!r} in the decoded text",
                decoded_from=f"{var}@{assign_line}",
            ))
    return candidates, suppressed, final


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


def _archive_kind(name: str) -> str | None:
    """'zip', 'tar', or None. Only containers shipped as skills (R3) count:
    a plain `.gz` blob is not an archive and stays on the binary-skip path."""
    low = name.lower()
    if low.endswith(ARCHIVE_SUFFIXES_TAR):
        return "tar"
    if low.endswith(ARCHIVE_SUFFIXES_ZIP):
        return "zip"
    return None


def _member_escapes(name: str) -> bool:
    """Does this member name try to leave the archive? Absolute paths,
    drive letters, and any `..` that climbs above the root (zip-slip)."""
    pure = PurePosixPath(name)
    if pure.is_absolute():
        return True
    if pure.parts and ":" in pure.parts[0]:  # windows drive/URI prefix
        return True
    depth = 0
    for part in pure.parts:
        if part == "..":
            depth -= 1
            if depth < 0:
                return True
        elif part not in (".", ""):
            depth += 1
    return False


def _read_archive_members(path: Path, rel: str, kind: str, *,
                          max_bytes: int) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Read an archive's members into memory. Returns (members, warnings).

    Members are `(name, data)` pairs — nothing is ever written to disk, so a
    traversal name has nowhere to escape to (R3c) and the read itself bounds
    a bomb (R3b). Every refusal appends a warning the result must carry:
    - entry count over ARCHIVE_MAX_ENTRIES → the whole archive is refused;
    - member over max_bytes, or compressed:uncompressed ratio over
      ARCHIVE_BOMB_RATIO → that member is refused (zip only, where the
      header states both sizes);
    - `_member_escapes(name)` → that member is refused.
    A corrupt container is a warning plus an empty member list, not a crash.
    """
    members: list[tuple[str, bytes]] = []
    warnings: list[str] = []

    def _skip(name: str, why: str) -> None:
        warnings.append(f"warning: skipped archive member {rel}!{name}: {why}")

    try:
        if kind == "zip":
            with zipfile.ZipFile(path) as zf:
                infos = [i for i in zf.infolist() if not i.is_dir()]
                if len(infos) > ARCHIVE_MAX_ENTRIES:
                    warnings.append(
                        f"warning: skipped archive {rel}: {len(infos)} members "
                        f"exceed the {ARCHIVE_MAX_ENTRIES}-entry bound")
                    return members, warnings
                for info in infos:
                    name = info.filename
                    if _member_escapes(name):
                        _skip(name, "member path escapes the archive (traversal)")
                        continue
                    if info.file_size > max_bytes:
                        _skip(name, f"{info.file_size} uncompressed bytes exceed "
                                    f"--archive-max-bytes={max_bytes}")
                        continue
                    if info.compress_size > 0 and (
                            info.file_size / info.compress_size > ARCHIVE_BOMB_RATIO):
                        _skip(name, f"compression ratio over {ARCHIVE_BOMB_RATIO}:1 "
                                    "(zip-bomb guard)")
                        continue
                    with zf.open(info) as fh:
                        members.append((name, fh.read(max_bytes + 1)))
        else:
            with tarfile.open(path, "r:*") as tf:
                infos = [m for m in tf.getmembers() if m.isfile()]
                if len(infos) > ARCHIVE_MAX_ENTRIES:
                    warnings.append(
                        f"warning: skipped archive {rel}: {len(infos)} members "
                        f"exceed the {ARCHIVE_MAX_ENTRIES}-entry bound")
                    return members, warnings
                for m in infos:
                    if _member_escapes(m.name):
                        _skip(m.name, "member path escapes the archive (traversal)")
                        continue
                    if m.size > max_bytes:
                        _skip(m.name, f"{m.size} uncompressed bytes exceed "
                                      f"--archive-max-bytes={max_bytes}")
                        continue
                    fh = tf.extractfile(m)
                    if fh is None:
                        continue
                    members.append((m.name, fh.read(max_bytes + 1)))
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError,
            zlib.error, MemoryError) as e:
        # A truncated or corrupt container is untrusted input, not a bug:
        # warn, keep whatever complete members were read, and move on.
        warnings.append(f"warning: skipped unreadable archive {rel}: {e}")
        return members, warnings
    return members, warnings


# --- Doc-context demotion (card t_3501ae36) -----------------------------------
# A payload that sits in a documentation context is a quoted specimen, not the
# artifact acting — for every rule class except injection prose and
# download-and-exec (see NEVER_DEMOTE_CATEGORIES in rules.py). The contexts are
# detected here, after the verifier has graded, so the pass and the verifier
# share one notion of fence/span/file-context (the verifier's own helpers).

JSONL_SUFFIXES = (".jsonl", ".ndjson")
_HEADING = re.compile(r"^#{1,6}\s")


def _nearest_heading(lines: list[str], line_no: int) -> str:
    """Text of the closest ATX heading at or above `line_no` (1-based), or ''."""
    for i in range(line_no - 1, -1, -1):
        if _HEADING.match(lines[i]):
            return lines[i]
    return ""


def _fence_is_framed(lines: list[str], fenced: list[bool], line_no: int) -> bool:
    """Is the fenced block explicitly presented as documentation? Frame
    evidence: an example/install/usage word in an in-fence `#` comment above
    the payload, on the intro line above the fence, or in the nearest heading
    — never on the payload line itself (the attacker controls it). The live
    corpus documents `curl … | bash` installers exactly this way
    (Installation/Quick Start headings, `# Install …` comments); those are
    specimens, not payloads."""
    evidence: list[str] = []
    open_idx = 0
    for i in range(line_no - 1, -1, -1):
        if not fenced[i]:
            open_idx = i  # the fence marker line carries state False
            break
        if lines[i].lstrip().startswith("#"):  # shell comment inside the fence
            evidence.append(lines[i])
    for i in range(open_idx - 1, -1, -1):  # nearest non-blank line above the fence
        if lines[i].strip():
            evidence.append(lines[i])
            break
    evidence.append(_nearest_heading(lines, line_no))
    return any(DOC_FRAME.search(e) for e in evidence)


def _doc_context(lines: list[str], rel: str, line_no: int, raw: str,
                 ctx: str, fenced_line: bool) -> str:
    """The documentation context owning this match, as a short human phrase
    used verbatim in the demotion reason ('' when none applies). A JSONL log
    record is a log in any file context; the markdown contexts apply only to
    directive/documentation files — in a code file a pipe or `>` is syntax,
    not markup."""
    line = lines[line_no - 1]
    if Path(rel).name.lower().endswith(JSONL_SUFFIXES):
        try:
            if isinstance(json.loads(line), dict):
                return "JSONL log line quoting an earlier command"
        except ValueError:
            pass  # prose smuggled into a .jsonl name is not a log record
    if ctx not in ("documentation", "directive"):
        return ""
    if fenced_line:
        return "fenced code block"
    if _in_code_span(line, raw):
        return "inline code span"
    if line.lstrip().startswith(">"):
        return "blockquote line"
    if line.lstrip().startswith("|"):
        return "markdown table row"
    if DOC_SECTION_HEADING.search(_nearest_heading(lines, line_no)):
        return "example/usage section"
    return ""


def _apply_doc_context_demotion(candidates: list[Finding], sources: dict[str, str],
                                rules_by_id: dict[str, Rule], roots: frozenset[str],
                                cfg) -> None:
    """Settle doc contexts the verifier cannot see (blockquote, table row,
    example section, JSONL record), and re-decide the fence for the classes
    that never take the specimen reading from context alone. Mutates each
    candidate's verdict/reason in place; skipped entirely by `strict`
    (disable_demotions declines every judgement, doc contexts included)."""
    if cfg.disable_demotions:
        return
    fenced_by_file: dict[str, list[bool]] = {}
    ordinal: dict[tuple[str, int, str], int] = {}
    for f in candidates:
        rule = rules_by_id.get(f.rule_id)
        text = sources.get(f.file)
        if rule is None or rule.pattern is None or text is None:
            continue
        lines = text.splitlines()
        if not 0 < f.line <= len(lines):
            continue
        ctx = _ctx_of(f.file, roots)
        fenced = None
        if ctx in ("documentation", "directive"):
            fenced = fenced_by_file.get(f.file)
            if fenced is None:
                fenced = fenced_by_file[f.file] = _fenced_state(lines)
        # The n-th match on the line, exactly as verify_findings graded it.
        key = (f.file, f.line, f.rule_id)
        n = ordinal.get(key, 0)
        ordinal[key] = n + 1
        m = next(islice(rule.pattern.finditer(lines[f.line - 1]), n, None), None)
        raw = m.group(0) if m else f.snippet
        fenced_line = bool(fenced is not None and fenced[f.line - 1])
        phrase = _doc_context(lines, f.file, f.line, raw, ctx, fenced_line)
        if not phrase:
            continue
        if rule.category not in NEVER_DEMOTE_CATEGORIES:
            f.verdict = "low_trust"
            f.reason = (f"match sits in a {phrase} — quoted documentation "
                        "(a specimen the agent reads about), not the artifact acting")
            continue
        # Injection prose and download-and-exec: context alone grants nothing.
        # An unframed fenced block is attacker-controlled framing — the hit
        # stays a finding; a framed one keeps the verifier's specimen verdict.
        if not fenced_line:
            continue  # spans/tables/quotes keep the verifier's own reading
        if rule.category == "rce-download" and not SHELL_PIPE.search(raw):
            continue  # `curl … | python -c` parses output; it does not exec it
        if _fence_is_framed(lines, fenced, f.line):
            continue
        f.verdict = "exploitable"
        f.reason = ("payload in a fenced block with no documentation frame "
                    "(no example/install/usage wording) — the fence is "
                    "attacker-controlled framing, not a specimen; stays a finding")


def scan_path(target: str | Path, rules_path: str | None = None, *,
              honor_ignores: bool = False,
              exclude: list[str] | None = None,
              ignore_patterns: list[str] | None = None,
              profile: str = "balanced",
              timeout: float | None = None,
              max_files: int | None = None,
              follow_symlinks: bool = True,
              archive_max_bytes: int = DEFAULT_ARCHIVE_MAX_BYTES) -> ScanResult:
    """Scan a path. Pattern matches are candidates; the verifier grades them.

    Only `exploitable` findings are reported as findings — everything else is kept in
    `result.verdicts` with a reason, so a dropped hit is auditable rather than
    invisible. `ignore_patterns` (from `.skillsentinelignore`) and inline markers
    both apply only under `honor_ignores`: a scanned artifact must not be able
    to silence its own detection by default.

    `timeout`/`max_files` bound the walk; expiry or hitting the limit is an
    input error for the CLI to report — never a silently partial scan. So are
    the two ways a scan can see nothing: a zero-rule catalog and a walk that
    yielded zero scannable files — a scan that saw nothing proves nothing.
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
    if not rules:
        # An empty catalog matches nothing, so it would "verify" any tree as
        # clean — that verdict is worthless, refuse it as an input error.
        raise InputError(
            f"rules catalog {rules_path or 'the built-in catalog'} has zero rules — "
            "refusing to report an empty scan as clean")
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
    final: list[Finding] = []
    scanned_rels: list[str] = []  # every file actually scanned, findings or not
    deadline = time.monotonic() + timeout if timeout else None
    linked: set[tuple[int, int]] = set()  # (st_dev, st_ino) of resolved symlink targets
    over_limit = 0
    for entry in _iter_target_files(root, follow_symlinks):
        rel, p = entry.rel, entry.path
        if p is None:
            # R1c/R1d: a link the policy declined (loop, broken, or
            # --no-follow-symlinks). A skip the output does not explain is
            # indistinguishable from a clean scan, so it lands in
            # files_skipped WITH its reason.
            result.files_skipped += 1
            result.warnings.append(f"warning: skipped {rel}: {entry.reason}")
            continue
        if p.is_symlink():
            # A file link resolves here: a target inode seen before is a
            # cycle or a second link to an already-scanned file.
            try:
                st = os.stat(p)  # follows the chain; ELOOP on a cycle
            except OSError:
                result.files_skipped += 1
                result.warnings.append(f"warning: skipped {rel}: unresolvable symlink")
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            target = (st.st_dev, st.st_ino)
            if target in linked:
                result.files_skipped += 1
                result.warnings.append(
                    f"warning: skipped {rel}: symlink target already scanned")
                continue
            linked.add(target)
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
        kind = _archive_kind(p.name)
        if kind is not None:
            # R3: the container is opened and its text members matched in
            # memory — never extracted — with findings attributed
            # '<archive>!<inner/path>'. Every guard refusal is a warning
            # counted in files_skipped, not a silent hole.
            member_reports, archive_warnings = _read_archive_members(
                p, rel, kind, max_bytes=archive_max_bytes)
            result.warnings.extend(archive_warnings)
            result.files_skipped += len(archive_warnings)
            for name, data in member_reports:
                if max_files is not None and result.files_scanned >= max_files:
                    over_limit += 1
                    break
                mrel = f"{rel}!{name}"
                if _looks_binary(data[:8192]):
                    result.binary_files_skipped += 1
                    continue
                text, decodable = _decode_scannable(data)
                found, suppressed_members, member_final = _scan_text(
                    text, mrel, rules, honor_ignores,
                    deadline=deadline, timeout=timeout)
                result.files_scanned += 1
                scanned_rels.append(mrel)
                result.suppressed += suppressed_members
                if not decodable:
                    result.undecodable_files.append(mrel)
                if found:
                    candidates.extend(found)
                    sources[found[0].file] = text
                final.extend(member_final)
            continue
        try:
            if _looks_binary(_read_head(p)):
                # V8: a NUL-dense non-text file is reported separately instead
                # of silently counting as a scanned file
                result.binary_files_skipped += 1
                continue
            found, suppressed, text, truncated, file_final, decodable = scan_file(
                p, rules, root, honor_ignores=honor_ignores,
                deadline=deadline, timeout=timeout, rel=rel)
        except (UnreadableFileError, OSError):
            # V5: one unreadable file must not discard the findings already
            # collected from the readable rest — record it, keep walking; the
            # CLI warns and exits 2. (Timeouts raise plain InputError and
            # still propagate.)
            result.unreadable_files.append(rel)
            continue
        result.files_scanned += 1
        scanned_rels.append(rel)
        result.suppressed += suppressed
        if not decodable:
            # D3: a file that could not be decoded is reported loudly, never
            # allowed to quietly shrink the scan to nothing.
            result.undecodable_files.append(rel)
        if truncated:
            result.truncated = True
            result.truncated_files.append(rel)
        if found:
            candidates.extend(found)
            sources[found[0].file] = text
        final.extend(file_final)
    if over_limit:
        result.limit_reached = (max_files, result.files_scanned + over_limit)
    # D2: a manifest file dropped by .skillsentinelignore silences the file
    # every directive lives in — refuse the leftover scan as an input error.
    # Scoped to the scan ROOT's own manifest: a repository self-scan legitimately
    # ignores its fixture corpora, which contain nested SKILL.md files on purpose,
    # and those nested manifests belong to files that stay visible to the scan.
    ignored_manifest = next(
        (rel for rel in result.ignored_files
         if Path(rel).name.lower() in MANIFEST_NAMES and Path(rel).parent == Path(".")),
        None)
    if ignored_manifest is not None:
        raise InputError(
            f".skillsentinelignore excludes skill manifest {ignored_manifest!r} — "
            "refusing to scan a skill without its manifest")
    if result.files_scanned == 0 and not result.limit_reached:
        # Every file was excluded/ignored/skipped/unreadable/binary: the walk
        # saw nothing scannable, so a clean verdict here would prove nothing
        # (same refusal as a whole-skill .skillsentinelignore). limit_reached
        # keeps its own exit-2 report.
        raise InputError(
            f"scanned 0 files in {root} (all excluded, unreadable or skipped) — "
            "refusing to report an empty scan as clean")
    if (deadline is not None and time.monotonic() > deadline) or (
            len(result.undecodable_files) == result.files_scanned):
        # D3: nothing scanned was readable text — a clean verdict would prove
        # nothing. (A timeout spent entirely inside the walk reports the same way.)
        if deadline is not None and time.monotonic() > deadline:
            raise InputError(f"timed out after {timeout:g} s")
        raise InputError(
            f"no file in {root} could be decoded as text "
            f"({', '.join(result.undecodable_files[:3])}"
            f"{'…' if len(result.undecodable_files) > 3 else ''}) — "
            "refusing to report an unreadable scan as clean")

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
    verdicts = verify_findings(candidates, sources, cfg, scanned_paths=scanned_rels)
    for f in candidates:
        if f.file in alias_back:
            f.file = alias_back[f.file]
    for v in verdicts:
        if v.file in alias_back:
            v.file = alias_back[v.file]
    by_key: dict[tuple[str, int, str], tuple[str, str]] = {}
    for v in verdicts:
        by_key.setdefault((v.file, v.line, v.rule_id), (v.verdict, v.reason))
    for f in candidates:
        f.verdict, f.reason = by_key.get((f.file, f.line, f.rule_id),
                                         ("inconclusive", "not graded"))
    # Doc-context demotion (t_3501ae36): quoted specimens in documentation are
    # not the artifact acting — except injection prose and shell pipes, which
    # an unframed fence does not excuse. Runs after grading so the histogram
    # and the findings/demoted split below reflect the final verdicts.
    _apply_doc_context_demotion(candidates, sources, {r.id: r for r in rules},
                                _directive_roots(scanned_rels), cfg)
    result.verdicts = {}
    for f in candidates:
        result.verdicts[f.verdict] = result.verdicts.get(f.verdict, 0) + 1
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
    if deadline is not None and time.monotonic() > deadline:
        # D7: the verification stage must honour the budget like every other.
        raise InputError(f"timed out after {timeout:g} s")
    # stable order: severity desc, then file, then rule, then line
    result.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.rule_id, f.line))
    return result


def to_sarif(result: ScanResult, rules: list[Rule] | None = None) -> dict:
    rules = rules or load_rules()
    return {
        # canonical SARIF 2.1.0 schema (the oasis-tcs GitHub URL this used to
        # carry was a dead Android-workflow schema, 404 since 2019)
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "SkillSentinel",
                "version": __version__,
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
