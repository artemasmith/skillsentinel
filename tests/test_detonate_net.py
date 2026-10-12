"""Acceptance tests for card t_cfe963ad — detonation network isolation.

Expected state while only these tests are committed: criteria 1–4 are RED
(--unshare-net, the capability refusal and --allow-net are not implemented
yet); criterion 5 (bwrap absent → honest skip) is a regression guard for
existing behavior and stays GREEN.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from skillsentinel import detonate  # noqa: E402

EGRESS_PROBE = "import socket; socket.create_connection(('1.1.1.1', 80), 2)\n"

# Fake `bwrap` standing in for a bubblewrap build without --unshare-net
# support: it rejects the flag outright, like a real old bwrap does. If it is
# asked to build a real sandbox WITHOUT the flag, it records a marker — that
# is the forbidden silent fallback to an egress-capable sandbox. Version-style
# queries (no bind options) succeed and mention nothing about the flag.
FAKE_OLD_BWRAP = '''#!/usr/bin/env python3
import os
import sys

argv = sys.argv[1:]
here = os.path.dirname(os.path.abspath(__file__))

if "--unshare-net" in argv:
    sys.stderr.write("bwrap: unrecognized option '--unshare-net'\\n")
    sys.exit(1)

binds = ("--ro-bind", "--ro-bind-try", "--bind", "--bind-try", "--dev-bind")
if any(a in binds for a in argv):
    with open(os.path.join(here, "ran-without-unshare-net"), "w") as f:
        f.write(" ".join(argv) + "\\n")
    sys.exit(0)

sys.stdout.write("bubblewrap (fake, old) 0.4.1\\n")
sys.exit(0)
'''


def run_cli(*argv, env=None):
    return subprocess.run(
        [sys.executable, "-m", "skillsentinel", *argv],
        capture_output=True, text=True, cwd=REPO, timeout=120, env=env,
    )


class BwrapArgvTests(unittest.TestCase):
    """AC1: the built bwrap argv isolates the network. AC4 (unit half):
    detonate_file(allow_net=True) explicitly lifts isolation and says so."""

    def _detonate_capturing_argv(self, **extra_kwargs):
        """Run detonate_file with bwrap lookup and exec patched out.

        Returns (report, argv) where argv is the full command detonate built.
        """
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["argv"] = list(cmd)
            return types.SimpleNamespace(returncode=0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "probe.py"
            script.write_text('print("probe")\n')
            with mock.patch.object(detonate.shutil, "which",
                                   return_value="/usr/bin/bwrap"), \
                 mock.patch.object(detonate.subprocess, "run", side_effect=fake_run):
                report = detonate.detonate_file(script, timeout=5, **extra_kwargs)
        return report, captured.get("argv")

    def test_argv_contains_unshare_net_and_die_with_parent(self):
        _, argv = self._detonate_capturing_argv()
        self.assertIsNotNone(argv, "bwrap was not invoked at all")
        self.assertIn("--die-with-parent", argv,
                      f"argv lost --die-with-parent: {argv}")
        self.assertIn("--unshare-net", argv,
                      f"bwrap argv does not isolate the network: {argv}")

    def test_allow_net_lifts_isolation_and_warns_in_report(self):
        report, argv = self._detonate_capturing_argv(allow_net=True)
        self.assertIsNotNone(argv)
        self.assertNotIn("--unshare-net", argv,
                         "--allow-net must explicitly lift network isolation")
        self.assertTrue(any("network NOT isolated" in n for n in report.notes),
                        f"report must carry the warning, notes={report.notes}")


class SandboxEgressTests(unittest.TestCase):
    """AC2: nothing inside the sandbox can open a network connection."""

    def test_no_egress_from_inside_sandbox(self):
        if not shutil.which("bwrap"):
            self.skipTest("bwrap not available on this host")
        with tempfile.TemporaryDirectory() as d:
            probe = Path(d) / "probe.py"
            probe.write_text(EGRESS_PROBE)
            report = detonate.detonate_file(probe, timeout=20)
        self.assertTrue(report.executed, f"detonation did not run: {report.notes}")
        self.assertEqual(report.sandbox, "bwrap")
        self.assertNotEqual(
            report.exit_code, 0,
            "socket.create_connection(('1.1.1.1', 80)) succeeded from inside "
            f"the sandbox — network is NOT isolated (exit_code={report.exit_code})")


class BwrapCapabilityTests(unittest.TestCase):
    """AC3: bwrap without --unshare-net support → detonation refused, not run."""

    def test_unsupported_unshare_net_refuses_detonation(self):
        with tempfile.TemporaryDirectory() as d:
            fakebin = Path(d) / "bin"
            fakebin.mkdir()
            (fakebin / "bwrap").write_text(FAKE_OLD_BWRAP)
            (fakebin / "bwrap").chmod(0o755)
            skills = Path(d) / "skills"
            skills.mkdir()
            (skills / "probe.py").write_text('print("probe")\n')

            env = dict(os.environ)
            env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
            p = run_cli("scan", str(skills), "--detonate", env=env)

            marker = fakebin / "ran-without-unshare-net"
            self.assertFalse(
                marker.exists(),
                "detonation fell back to a sandbox without --unshare-net "
                f"(real-egress run): {marker.read_text() if marker.exists() else ''}")
            self.assertIn("unshare-net", p.stderr,
                          f"no refusal message on stderr: stderr={p.stderr!r}")
            self.assertEqual(p.returncode, 2,
                             f"refused detonation must exit 2, got {p.returncode}")


class AllowNetCliTests(unittest.TestCase):
    """AC4 (CLI half): --allow-net is documented and prints the warning."""

    def test_help_documents_allow_net(self):
        p = run_cli("scan", "--help")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("--allow-net", p.stdout,
                      "--allow-net must be documented in `scan --help`")

    def test_allow_net_prints_not_isolated_warning(self):
        if not shutil.which("bwrap"):
            self.skipTest("bwrap not available on this host")
        with tempfile.TemporaryDirectory() as d:
            skills = Path(d) / "skills"
            skills.mkdir()
            (skills / "probe.py").write_text('print("probe")\n')
            p = run_cli("scan", str(skills), "--detonate", "--allow-net")
        self.assertIn("network NOT isolated", p.stdout,
                      f"--allow-net must print the explicit warning: "
                      f"stdout={p.stdout!r} stderr={p.stderr!r}")


class NoBwrapTests(unittest.TestCase):
    """AC5 (regression guard): bwrap absent → honest skip, exit 0."""

    def test_bwrap_absent_preserves_skip_behavior(self):
        with tempfile.TemporaryDirectory() as d:
            empty_path = Path(d) / "emptybin"
            empty_path.mkdir()
            skills = Path(d) / "skills"
            skills.mkdir()
            (skills / "probe.py").write_text('print("probe")\n')
            env = dict(os.environ)
            env["PATH"] = str(empty_path)
            p = run_cli("scan", str(skills), "--detonate", "--json", env=env)
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        reports = data.get("detonations", [])
        self.assertEqual(len(reports), 1, f"expected one detonation report: {reports}")
        rep = reports[0]
        self.assertFalse(rep["executed"], "report must be marked not executed")
        self.assertTrue(any("bwrap not available" in n for n in rep["notes"]),
                        f"skip note missing: {rep['notes']}")


if __name__ == "__main__":
    unittest.main()
