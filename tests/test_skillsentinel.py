"""Unit tests for SkillSentinel — stdlib unittest only, no network."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from skillsentinel.cli import main  # noqa: E402
from skillsentinel.rules import load_rules  # noqa: E402
from skillsentinel.scanner import scan_path, to_sarif  # noqa: E402
from skillsentinel.watch import write_snapshot, snapshot_dir, load_snapshot, diff_snapshots  # noqa: E402
from skillsentinel.detonate import find_scripts, detonate_file  # noqa: E402

MAL = REPO / "tests" / "fixtures" / "malicious"
BEN = REPO / "tests" / "fixtures" / "benign"


class RulesTests(unittest.TestCase):
    def test_at_least_30_rules(self):
        rules = load_rules()
        self.assertGreaterEqual(len(rules), 30, f"only {len(rules)} rules")

    def test_rules_compile_and_have_required_fields(self):
        for r in load_rules():
            self.assertRegex(r.id, r"^SS\d{3}$")
            self.assertIsNotNone(r.pattern)
            self.assertIn(r.severity, ("low", "medium", "high", "critical"))
            self.assertRegex(r.owasp, r"^ASI-\d{2}$")

    def test_required_categories_covered(self):
        cats = {r.category for r in load_rules()}
        required = {
            "prompt-injection", "invisible-unicode", "obfuscation",
            "rce-download", "credential-access", "exfiltration", "miner",
            "persistence", "mcp", "self-modification",
        }
        self.assertTrue(required <= cats, f"missing categories: {required - cats}")


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mal = scan_path(MAL)
        cls.ben = scan_path(BEN)

    def test_malicious_finds_critical(self):
        c = self.mal.counts
        self.assertGreaterEqual(c["critical"], 5, f"counts={c}")
        self.assertGreaterEqual(len(self.mal.findings), 20, f"counts={c}")

    def test_malicious_each_fixture_dir_flagged(self):
        dirs = {f.file.split("/")[0] for f in self.mal.findings}
        expected = {p.name for p in MAL.iterdir() if p.is_dir()}
        self.assertEqual(dirs, expected, f"not flagged: {expected - dirs}")

    def test_key_rules_fire(self):
        ids = {f.rule_id for f in self.mal.findings}
        for expected in ("SS001", "SS004", "SS009", "SS013", "SS016",
                         "SS020", "SS021", "SS024", "SS025", "SS027",
                         "SS029", "SS034", "SS036", "SS037"):
            self.assertIn(expected, ids, f"rule {expected} did not fire")

    def test_benign_is_clean(self):
        self.assertEqual(len(self.ben.findings), 0,
                         f"false positives: {[f.rule_id + ':' + f.file for f in self.ben.findings]}")

    def test_line_numbers_within_file(self):
        for f in self.mal.findings:
            self.assertGreaterEqual(f.line, 1)


class CliTests(unittest.TestCase):
    def _run(self, *argv):
        return subprocess.run(
            [sys.executable, "-m", "skillsentinel", *argv],
            capture_output=True, text=True, cwd=REPO, timeout=120,
        )

    def test_scan_malicious_json_exit_1(self):
        p = self._run("scan", str(MAL), "--json")
        self.assertEqual(p.returncode, 1, p.stderr)
        data = json.loads(p.stdout)
        self.assertGreaterEqual(sum(data["counts"].values()), 20)

    def test_scan_benign_exit_0(self):
        p = self._run("scan", str(BEN))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertIn("No findings", p.stdout)

    def test_scan_severity_threshold_high(self):
        p = self._run("scan", str(MAL), "--json", "--severity", "high")
        self.assertEqual(p.returncode, 1)
        p = self._run("scan", str(BEN), "--severity", "critical")
        self.assertEqual(p.returncode, 0)

    def test_sarif_output(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out.sarif"
            p = self._run("scan", str(MAL), "--sarif", str(out))
            self.assertEqual(p.returncode, 1)
            sarif = json.loads(out.read_text())
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertGreater(len(sarif["runs"][0]["results"]), 0)

    def test_rules_subcommand(self):
        p = self._run("rules")
        self.assertEqual(p.returncode, 0)
        self.assertIn("rules:", p.stdout)

    def test_missing_path_errors(self):
        p = self._run("scan", "/nonexistent-path-xyz")
        self.assertNotEqual(p.returncode, 0)


class WatchTests(unittest.TestCase):
    def test_init_and_diff_drift(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "skills"
            (root / "a").mkdir(parents=True)
            (root / "a" / "SKILL.md").write_text("hello\n")
            snap = Path(d) / "snap.json"
            write_snapshot(root, snap)
            # no drift
            d0 = diff_snapshots(load_snapshot(snap), snapshot_dir(root))
            self.assertTrue(d0["clean"])
            # rug-pull: modify + add + remove
            (root / "a" / "SKILL.md").write_text("evil now\n")
            (root / "b.md").write_text("new\n")
            (root / "a" / "SKILL.md").rename(root / "a" / "RENAMED.md")
            d1 = diff_snapshots(load_snapshot(snap), snapshot_dir(root))
            self.assertFalse(d1["clean"])
            self.assertTrue(set(d1["changed"]) & {"a/RENAMED.md"} or d1["added"] or d1["removed"])

    def test_cli_watch_flow(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "skills"
            root.mkdir()
            (root / "SKILL.md").write_text("v1\n")
            snap = Path(d) / "snap.json"
            p1 = subprocess.run([sys.executable, "-m", "skillsentinel", "watch", "init",
                                 str(root), "--snapshot", str(snap)],
                                capture_output=True, text=True, cwd=REPO)
            self.assertEqual(p1.returncode, 0, p1.stderr)
            (root / "SKILL.md").write_text("v2 — rug pull\n")
            p2 = subprocess.run([sys.executable, "-m", "skillsentinel", "watch", "diff",
                                 str(root), "--snapshot", str(snap)],
                                capture_output=True, text=True, cwd=REPO)
            self.assertEqual(p2.returncode, 1, p2.stdout + p2.stderr)
            self.assertIn("DRIFT", p2.stdout)


class DetonateTests(unittest.TestCase):
    def test_find_scripts(self):
        scripts = find_scripts(MAL)
        names = {s.name for s in scripts}
        self.assertIn("install.sh", names)
        self.assertIn("helper.py", names)

    def test_detonate_runs_or_falls_back(self):
        # bwrap present on CI/dev hosts: must execute and catch the egress shim;
        # absent: must report skipped honestly.
        script = MAL / "05-cred-exfil" / "collect.sh"
        rep = detonate_file(script, timeout=15)
        if shutil.which("bwrap"):
            self.assertTrue(rep.executed)
            self.assertEqual(rep.sandbox, "bwrap")
            self.assertTrue(any("curl" in a for a in rep.network_attempts),
                            f"egress not captured: {rep.network_attempts}")
        else:
            self.assertFalse(rep.executed)
            self.assertIn("bwrap not available", "; ".join(rep.notes))


if __name__ == "__main__":
    unittest.main()
