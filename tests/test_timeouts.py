"""Acceptance tests (RED phase) for detonation/subprocess timeouts — card t_21dd16a1.

AC1: WHEN a scanned file makes a subprocess exceed its timeout THE SYSTEM SHALL
kill it, record a finding or a warning, and continue; the run SHALL finish.
Negative scenario: a sleeping payload.

Expected state while only these tests are committed: the timeout-warning
assertions are RED — detonate_file() already survives subprocess.TimeoutExpired
(exit_code=None, stderr_tail='detonation timed out') and detonate_tree()
continues to later scripts, but the timeout is nowhere recorded as an explicit
note/finding a user or the JSON consumer can see. The kill/continue halves of
the assertions are contract pins the green phase must keep while adding the note.

AC2/AC3/AC4 of the card are already implemented and pinned green elsewhere —
unshare-net default + exit-2 refusal + skip notes in test_detonate_net.py,
truncated (never silently skipped) oversize files, .git/hooks scanning and the
scanner-level --timeout expiry (exit 2) in test_ci_paths.py — and are not
duplicated here.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from skillsentinel import detonate  # noqa: E402

SLEEPER_PY = "import time\ntime.sleep(30)\n"
SLEEPER_SH = "#!/bin/sh\nsleep 30\n"

# Fake `bwrap` for hermetic CLI runs (unlike test_detonate_net.py's
# FAKE_OLD_BWRAP, this build ACCEPTS --unshare-net so the preflight passes):
# the capability probe succeeds, a sleeping payload runs far past the
# detonation timeout, anything else exits 0 at once.
FAKE_SLEEPY_BWRAP = '''#!/usr/bin/env python3
import sys
import time

argv = sys.argv[1:]
if argv and argv[-1] == "/usr/bin/true":
    sys.exit(0)  # capability preflight: this build honors --unshare-net
if "sleeper" in argv[-1]:
    time.sleep(30)  # negative scenario: the payload outlives the timeout
sys.exit(0)
'''


def run_cli(*argv, env=None, timeout=60):
    return subprocess.run(
        [sys.executable, "-m", "skillsentinel", *argv],
        capture_output=True, text=True, cwd=REPO, timeout=timeout, env=env,
    )


class TimeoutNoteTests(unittest.TestCase):
    """AC1 (unit half): a detonation timeout is recorded as an explicit
    warning note on the report — not only implied by exit_code=None and a
    stderr_tail the caller has to know to look for."""

    def _detonate_with_timeout(self):
        """detonate_file with bwrap lookup patched and subprocess.run faked:
        the preflight probe passes, the real detonation exceeds its timeout.

        Returning at all (instead of propagating TimeoutExpired) is the unit-
        level evidence that the killed run did not take the caller down.
        """
        launched = []

        def fake_run(cmd, **kwargs):
            if cmd[-1] == "/usr/bin/true":  # _bwrap_can_isolate_network probe
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            launched.append(list(cmd))
            raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 10))

        with tempfile.TemporaryDirectory() as d:
            script = Path(d) / "sleeper.py"
            script.write_text(SLEEPER_PY)
            with mock.patch.object(detonate.shutil, "which",
                                   return_value="/usr/bin/bwrap"), \
                 mock.patch.object(detonate.subprocess, "run",
                                   side_effect=fake_run):
                report = detonate.detonate_file(script, timeout=5)
        return report, launched

    def test_timed_out_detonation_carries_explicit_warning_note(self):
        report, launched = self._detonate_with_timeout()
        self.assertEqual(len(launched), 1,
                         "the payload detonation must have been launched once")
        self.assertEqual(Path(report.file).name, "sleeper.py")
        self.assertTrue(
            any("timed out" in n.lower() for n in report.notes),
            f"the timeout must be recorded as an explicit warning note, "
            f"notes={report.notes}")


class TreeContinuesTests(unittest.TestCase):
    """AC1: one timed-out script must not stop detonate_tree — later scripts
    still run, and the timeout is recorded on the offending script alone."""

    def test_detonate_tree_continues_past_a_timed_out_script(self):
        ran = []

        def fake_run(cmd, **kwargs):
            if cmd[-1] == "/usr/bin/true":
                return types.SimpleNamespace(returncode=0, stdout="", stderr="")
            if "aaa_sleeper" in cmd[-1]:  # sorted first by find_scripts
                raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 10))
            ran.append(cmd[-1])
            return types.SimpleNamespace(returncode=0, stdout="fine\n", stderr="")

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "aaa_sleeper.py").write_text(SLEEPER_PY)
            (root / "zzz_normal.sh").write_text("echo fine\n")
            with mock.patch.object(detonate.shutil, "which",
                                   return_value="/usr/bin/bwrap"), \
                 mock.patch.object(detonate.subprocess, "run",
                                   side_effect=fake_run):
                reports = detonate.detonate_tree(root)

        self.assertEqual(len(reports), 2,
                         f"both scripts must be reported: "
                         f"{[r.file for r in reports]}")
        by_name = {Path(r.file).name: r for r in reports}
        self.assertTrue(
            any("timed out" in n.lower() for n in by_name["aaa_sleeper.py"].notes),
            f"the timed-out script must carry the warning note: "
            f"{by_name['aaa_sleeper.py'].notes}")
        normal = by_name["zzz_normal.sh"]
        self.assertTrue(normal.executed,
                        "detonate_tree must continue after a timed-out script")
        self.assertEqual(normal.exit_code, 0)
        self.assertEqual(ran, ["/work/zzz_normal.sh"],
                         "the later script must actually be executed after "
                         "the earlier one timed out")


class SandboxKillTests(unittest.TestCase):
    """AC1 (end to end): a real sleeping payload in a real sandbox is killed
    at the timeout and the timeout is recorded as a warning."""

    def test_sleeping_payload_is_killed_and_reported(self):
        if not shutil.which("bwrap"):
            self.skipTest("bwrap not available on this host")
        with tempfile.TemporaryDirectory() as d:
            sleeper = Path(d) / "sleeper.sh"
            sleeper.write_text(SLEEPER_SH)
            start = time.monotonic()
            report = detonate.detonate_file(sleeper, timeout=2)
            elapsed = time.monotonic() - start
        self.assertLess(
            elapsed, 20,
            f"a sleeping payload must be killed at its timeout, not awaited "
            f"to completion ({elapsed:.1f}s elapsed for a 30 s sleep)")
        self.assertTrue(
            any("timed out" in n.lower() for n in report.notes),
            f"the timeout must be recorded as an explicit warning note: "
            f"notes={report.notes}")


class SandboxSurvivorTests(unittest.TestCase):
    """Round 2 (reviewer finding): a detonation timeout must take down the
    whole sandbox tree, not just the bwrap supervisor.

    detonate.py builds the bwrap argv WITHOUT --unshare-pid, so the payload
    runs in the host PID namespace; subprocess.run(timeout=...) SIGKILLs only
    the direct child (bwrap itself), and the payload is left behind as an
    orphan host process. The payload here is a /bin/sh busy loop (`while true;
    do :; done` — no sleep binary needed): while it runs, the sh cmdline is
    `/bin/sh /work/<marker>.sh`, so `pgrep -f <marker>` detects survivors for
    as long as they live. The marker is unique per run, so strays from earlier
    runs can never be mistaken for this one's survivors.
    """

    def _survivors(self, marker):
        p = subprocess.run(["pgrep", "-f", marker],
                           capture_output=True, text=True)
        return [int(pid) for pid in p.stdout.split()]

    def _terminate(self, pids):
        for pid in pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def test_timed_out_detonation_leaves_no_surviving_payload_process(self):
        if not shutil.which("bwrap"):
            self.skipTest("bwrap not available on this host")

        marker = f"sleeper_{os.getpid()}_{time.monotonic_ns()}.sh"

        # stray guard: the marker is unique per run, so this should be clean;
        # anything matching anyway is terminated and the test skipped
        strays = self._survivors(marker)
        if strays:
            self._terminate(strays)
            self.skipTest(f"stray processes matching {marker} were terminated "
                          f"before the run: {strays}")

        with tempfile.TemporaryDirectory() as d:
            payload = Path(d) / marker
            payload.write_text("#!/bin/sh\nwhile true; do :; done\n")
            report = detonate.detonate_file(payload, timeout=2)

        # signal propagation to the sandbox tree can take a moment
        deadline = time.monotonic() + 3.0
        survivors = self._survivors(marker)
        while survivors and time.monotonic() < deadline:
            time.sleep(0.2)
            survivors = self._survivors(marker)

        # clean up whatever is left so a RED run leaves no spinning orphan;
        # the assertion below judges the captured list, not the post-cleanup
        # state
        self._terminate(survivors)

        self.assertEqual(
            survivors, [],
            f"the payload process survived the detonation timeout: pids "
            f"{survivors} still match '{marker}' after bwrap was killed — "
            f"the whole sandbox tree must die with the timeout, not just the "
            f"bwrap supervisor")
        self.assertTrue(
            any("timed out" in n.lower() for n in report.notes),
            f"the timeout must still be recorded as a warning note: "
            f"notes={report.notes}")


class CliDetonateTimeoutTests(unittest.TestCase):
    """AC1 (CLI half): `scan --detonate` over a tree containing a sleeping
    payload plus a normal script finishes, and its JSON output names the
    timed-out script with the timeout indication."""

    def test_scan_detonate_survives_sleeping_payload(self):
        with tempfile.TemporaryDirectory() as d:
            fakebin = Path(d) / "bin"
            fakebin.mkdir()
            (fakebin / "bwrap").write_text(FAKE_SLEEPY_BWRAP)
            (fakebin / "bwrap").chmod(0o755)
            skills = Path(d) / "skills"
            skills.mkdir()
            (skills / "sleeper.py").write_text(SLEEPER_PY)
            (skills / "normal.sh").write_text("echo fine\n")

            env = dict(os.environ)
            env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
            try:
                p = run_cli("scan", str(skills), "--detonate", "--json",
                            env=env, timeout=90)
            except subprocess.TimeoutExpired:
                self.fail("scan --detonate hung on a sleeping payload — the "
                          "timeout must kill it and the run must finish")

        self.assertNotIn("Traceback", p.stderr)
        self.assertIn(
            p.returncode, (0, 1),
            f"a detonation timeout is a recorded warning, not a refusal or a "
            f"crash: rc={p.returncode}\nstdout={p.stdout}\nstderr={p.stderr}")
        data = json.loads(p.stdout)
        by_name = {Path(r["file"]).name: r for r in data.get("detonations", [])}
        self.assertIn("sleeper.py", by_name,
                      "the timed-out script must be named in the JSON output")
        self.assertIn("normal.sh", by_name,
                      "the run must continue to the normal script")
        self.assertTrue(by_name["normal.sh"]["executed"])
        self.assertTrue(
            any("timed out" in n.lower() for n in by_name["sleeper.py"]["notes"]),
            f"the timed-out script's report must carry the timeout indication: "
            f"{by_name['sleeper.py']['notes']}")


if __name__ == "__main__":
    unittest.main()
