"""Acceptance tests for the v0.3.3 audit fixes (card t_e6a010ae) — RED phase.

Each criterion V1..V8 below encodes a defect found in the v0.3.2 audit; the
VERSION tests pin the release itself. With only this file committed every
test is expected to FAIL against the current code — that is the point of the
red phase. No network is used: the SARIF schema URL is asserted as a literal
constant, never fetched.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import skillsentinel  # noqa: E402
from skillsentinel import detonate  # noqa: E402
from skillsentinel.scanner import scan_path, to_sarif  # noqa: E402

MAL = REPO / "tests" / "fixtures" / "malicious"

# V3: the SARIF report must declare the canonical schemastore schema — the
# old oasis-tcs GitHub URL is a dead Android-workflow schema, not SARIF 2.1.0.
SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
STALE_SCHEMA_HOST = "raw.githubusercontent.com/oasis-tcs/sarif-spec/master"

# V4: the counts the malicious corpus actually prints today (verified by
# running `python3 -m skillsentinel scan tests/fixtures/malicious`).
EXPECTED_FINDINGS_PREFIX = (
    "Confirmed findings: 43 (critical: 27, high: 15, medium: 1, low: 0)")


def run_cli(*argv, cwd=None):
    env = dict(os.environ)
    extra = env.get("PYTHONPATH")
    env["PYTHONPATH"] = os.pathsep.join([str(REPO), extra]) if extra else str(REPO)
    return subprocess.run(
        [sys.executable, "-m", "skillsentinel", *argv],
        capture_output=True, text=True, cwd=cwd or REPO, timeout=120, env=env,
    )


def make_tmp(case):
    """Temporary directory cleaned up with the test case."""
    d = tempfile.TemporaryDirectory()
    case.addCleanup(d.cleanup)
    return Path(d.name)


class V1WatchInitTests(unittest.TestCase):
    def test_v1_init_nonexistent_path_rejected(self):
        d = make_tmp(self)
        snap = d / "snap.json"
        p = run_cli("watch", "init", str(d / "no" / "such" / "dir"),
                    "--snapshot", str(snap))
        self.assertEqual(p.returncode, 2,
                         f"rc={p.returncode} stdout={p.stdout!r} "
                         f"stderr={p.stderr!r}")
        err = p.stderr.strip()
        self.assertTrue(err, "stderr must carry the error")
        self.assertNotIn("\n", err, "the error must be exactly one line")
        self.assertFalse(snap.exists(),
                         "a failed init must not leave a snapshot behind")


class V2WatchRootTests(unittest.TestCase):
    def test_v2_snapshot_root_resolved_and_diff_mismatch_rejected(self):
        d = make_tmp(self)
        dir_a, dir_b = d / "dirA", d / "dirB"
        for dir_, body in ((dir_a, "content a\n"), (dir_b, "content b\n")):
            dir_.mkdir()
            (dir_ / "SKILL.md").write_text(f"# demo\n{body}", encoding="utf-8")
        snap = d / "snap.json"
        # relative path on purpose: the snapshot must record the resolved
        # absolute root, not the path as typed
        p = run_cli("watch", "init", "dirA", "--snapshot", str(snap), cwd=d)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        data = json.loads(snap.read_text(encoding="utf-8"))
        self.assertEqual(data["root"], str(dir_a.resolve()),
                         f"snapshot root is {data['root']!r}")
        p = run_cli("watch", "diff", str(dir_b), "--snapshot", str(snap))
        combined = p.stdout + p.stderr
        self.assertEqual(p.returncode, 2,
                         f"diffing another tree must be an input error, got "
                         f"rc={p.returncode}: {combined!r}")
        self.assertRegex(combined, r"(?i)root.*mismatch|mismatch.*root")


class V3SarifSchemaTests(unittest.TestCase):
    def test_v3_sarif_schema_is_schemastore_constant(self):
        sarif = to_sarif(scan_path(MAL))
        self.assertEqual(sarif["$schema"], SARIF_SCHEMA_URL,
                         f"$schema is {sarif['$schema']!r}")
        # (c): the expected URL is pinned literally, not derived
        self.assertEqual(
            SARIF_SCHEMA_URL, "https://json.schemastore.org/sarif-2.1.0.json")

    def test_v3_no_stale_oasis_schema_url_in_source(self):
        offenders = [
            str(p.relative_to(REPO))
            for p in sorted((REPO / "skillsentinel").rglob("*.py"))
            if STALE_SCHEMA_HOST in p.read_text(encoding="utf-8")
        ]
        self.assertEqual(offenders, [],
                         f"stale oasis-tcs schema URL still present in: "
                         f"{offenders}")


class V4ReadmeTests(unittest.TestCase):
    def test_v4_readme_findings_line_matches_current_scan(self):
        p = run_cli("scan", str(MAL))
        line = next((l for l in p.stdout.splitlines()
                     if l.startswith("Confirmed findings:")), "")
        self.assertTrue(line, f"no findings line in output: {p.stdout!r}")
        self.assertTrue(line.startswith(EXPECTED_FINDINGS_PREFIX),
                        f"counts drifted: {line!r}")
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        self.assertIn(line, readme,
                      "README must carry the verbatim findings line")
        self.assertNotIn("Confirmed findings: 42", readme)
        self.assertNotIn("42 confirmed findings", readme)


class V5UnreadableFileTests(unittest.TestCase):
    @unittest.skipIf(hasattr(os, "geteuid") and os.geteuid() == 0,
                     "chmod 000 is still readable for root")
    def test_v5_unreadable_file_keeps_readable_findings(self):
        d = make_tmp(self)
        shutil.copy(MAL / "01-prompt-injection" / "SKILL.md", d / "SKILL.md")
        locked = d / "secret.txt"
        locked.write_text("mode 000\n", encoding="utf-8")
        locked.chmod(0o000)
        self.addCleanup(lambda: locked.chmod(0o600))
        p = run_cli("scan", str(d))
        combined = p.stdout + p.stderr
        self.assertEqual(p.returncode, 2,
                         f"unreadable input is an input error, got "
                         f"rc={p.returncode}: {combined!r}")
        self.assertIn("Confirmed findings", p.stdout,
                      "readable files' findings must still be reported")
        warning_lines = [l for l in combined.splitlines()
                         if "secret.txt" in l and re.search(r"(?i)warn", l)]
        self.assertTrue(warning_lines,
                        f"no warning names the unreadable file: "
                        f"stdout={p.stdout!r} stderr={p.stderr!r}")


class V6DetonateSingleFileTests(unittest.TestCase):
    def test_v6_single_file_detonate_no_silent_zero(self):
        d = make_tmp(self)
        script = d / "tool.sh"
        script.write_text("#!/bin/sh\necho probe\n", encoding="utf-8")
        p = run_cli("scan", str(script), "--detonate")
        combined = p.stdout + p.stderr
        self.assertNotIn("(0 scripts)", combined,
                         f"silent no-op detonation: {combined!r}")
        if "single-file detonation is not supported" not in combined:
            m = re.search(r"-- Detonation \((\d+) scripts?\)", p.stdout)
            self.assertIsNotNone(
                m, f"no Detonation section: stdout={p.stdout!r} "
                   f"stderr={p.stderr!r}")
            self.assertGreaterEqual(int(m.group(1)), 1)


class V7FindScriptsTests(unittest.TestCase):
    def test_v7_find_scripts_covers_all_script_suffixes(self):
        d = make_tmp(self)
        wanted = {f"script{s}" for s in
                  (".sh", ".bash", ".py", ".js", ".rb", ".pl", ".ps1")}
        for name in wanted | {"decoy.txt"}:
            (d / name).write_text("# probe\n", encoding="utf-8")
        found = {p.name for p in detonate.find_scripts(d)}
        self.assertTrue(wanted <= found, f"missing suffixes: {wanted - found}")
        self.assertNotIn("decoy.txt", found)


class V8BinaryReportingTests(unittest.TestCase):
    def test_v8_binary_files_reported_separately(self):
        d = make_tmp(self)
        (d / "SKILL.md").write_text("# benign\nhello\n", encoding="utf-8")
        (d / "notes.md").write_text("# notes\n", encoding="utf-8")
        (d / "blob.bin").write_bytes(b"\x00\x01\x02binary")

        p = run_cli("scan", str(d), "--json")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        payload = json.loads(p.stdout)
        self.assertEqual(payload["files_scanned"], 2,
                         f"files_scanned must count text files only: "
                         f"{payload['files_scanned']}")
        binary_fields = [
            f"{path}={val}"
            for path, val in _walk_numbers(payload)
            if "binary" in path[-1].lower() and isinstance(val, int)
            and val >= 1
        ]
        self.assertTrue(binary_fields,
                        "JSON must expose the binary skip count "
                        f"(e.g. binary_files_skipped): {payload!r}")

        p = run_cli("scan", str(d))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertRegex(p.stdout, r"\b2\s+text\b",
                         f"no text count in summary: {p.stdout!r}")
        self.assertRegex(p.stdout, r"\b1\s+binary\b",
                         f"no binary count in summary: {p.stdout!r}")


def _walk_numbers(node, path=()):
    """Yield (key-path, value) for every integer in a JSON payload."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_numbers(v, path + (k,))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_numbers(v, path + (f"[{i}]",))
    elif isinstance(node, int) and not isinstance(node, bool):
        yield path, node


class Version033Tests(unittest.TestCase):
    def test_version_is_033_everywhere(self):
        pyproject = tomllib.loads((REPO / "pyproject.toml")
                                  .read_text(encoding="utf-8"))
        self.assertEqual(pyproject["project"]["version"], "0.3.3")
        self.assertEqual(skillsentinel.__version__, "0.3.3")

    def test_version_changelog_documents_033(self):
        text = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
        m = re.search(r"^## \[?0\.3\.3\]?\s*$", text, re.M)
        self.assertIsNotNone(m, "CHANGELOG.md has no '## 0.3.3' section")
        section = text[m.end():].split("\n## ", 1)[0]
        # one keyword per audited defect V1..V8 the section must name
        required = {
            "V1 watch init on a missing path": r"(?i)watch init|nonexistent"
                                               r"|non-existent|missing path",
            "V2 snapshot root mismatch": r"(?i)mismatch",
            "V3 SARIF schema URL": r"(?i)sarif",
            "V4 README finding counts": r"(?i)readme",
            "V5 unreadable files": r"(?i)unreadable",
            "V6 single-file detonation": r"(?i)single[- ]file",
            "V7 detonate script suffixes": r"(?i)suffix|\.ps1|find_scripts",
            "V8 binary files": r"(?i)binary",
        }
        missing = [label for label, rx in required.items()
                   if not re.search(rx, section)]
        self.assertEqual(missing, [],
                         f"0.3.3 section does not mention: {missing}")


if __name__ == "__main__":
    unittest.main()
