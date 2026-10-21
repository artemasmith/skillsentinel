"""Acceptance tests for card t_ffa25dde (C4: CI/consumption envelope).

The card is about *consumption*: a stranger dropping the Action into their CI
must not get a hanging job, an invisible report, or a stale pin. These tests
lock the envelope files against regression. Parsing is text-based on purpose —
the project is zero-dependency, so no PyYAML at test time; every assertion
targets structural facts (an input key, a flag, a step) that are stable under
benign formatting changes.
"""

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

ACTION = (REPO / "action.yml").read_text(encoding="utf-8")
CI_YML = (REPO / ".github" / "workflows" / "skillsentinel.yml").read_text(encoding="utf-8")
README = (REPO / "README.md").read_text(encoding="utf-8")
CHANGELOG = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
PYPROJECT = (REPO / "pyproject.toml").read_text(encoding="utf-8")


def _matrix_versions():
    """The interpreter versions the test job actually runs (text-parsed: the
    project is zero-dependency, so no PyYAML at test time)."""
    block = re.search(r"python-version:\s*\[([^\]]*)\]", CI_YML)
    assert block, "the test job must run a python-version matrix"
    return [v.strip().strip("\"'") for v in block.group(1).split(",") if v.strip()]


class ActionTimeoutTests(unittest.TestCase):
    """The Action must pass a deadline to the CLI, so scans cannot hang jobs."""

    def test_timeout_input_exists_with_default_600(self):
        self.assertRegex(ACTION, r"(?m)^\s+timeout:\s*$")
        # default must be a quoted string '600' (action inputs are strings)
        self.assertRegex(ACTION, r'(?ms)^\s+timeout:.*?default: "600"')

    def test_run_script_passes_timeout_flag_to_the_cli(self):
        self.assertIn('"--timeout"', ACTION,
                      "action.yml must append --timeout to the scanner args")
        self.assertIn('TIMEOUT="${{ inputs.timeout }}"', ACTION,
                      "the timeout value must come from the timeout input")

    def test_timeout_zero_is_not_passed(self):
        self.assertIn('[ "$TIMEOUT" != "0" ]', ACTION,
                      "timeout: 0 must mean 'no deadline', not --timeout 0 "
                      "re-parsed by the CLI")

    def test_scan_exit_code_passes_through(self):
        self.assertRegex(ACTION, r"RC=\$\?")
        self.assertRegex(ACTION, r"exit \$RC",
                         "the CLI's exit code (1 findings / 2 timeout) must "
                         "become the step's exit code")


class ActionSarifTests(unittest.TestCase):
    """SARIF must reach the Security tab without being able to fail the job."""

    def test_uploads_via_codeql_upload_sarif_with_category(self):
        self.assertIn("github/codeql-action/upload-sarif", ACTION)
        self.assertRegex(ACTION, r"(?m)^\s+category: skillsentinel\s*$")

    def test_upload_is_continue_on_error(self):
        # a missing permission must warn, not fail the consumer's job:
        # continue-on-error belongs to the same step as the upload
        self.assertLess(
            ACTION.index("continue-on-error: true"),
            ACTION.index("github/codeql-action/upload-sarif"),
            "continue-on-error must be on the upload-sarif step")

    def test_upload_failure_produces_a_warning_annotation(self):
        self.assertRegex(ACTION, r"steps\.sarif-upload\.outcome == 'failure'")
        self.assertRegex(ACTION, r"::warning::")


class WorkflowTests(unittest.TestCase):
    """The project's own CI: perf gate present, SARIF upload kept."""

    def test_bench_job_gates_scan_speed(self):
        self.assertRegex(CI_YML, r"(?m)^\s+bench:\s*$",
                         "CI must have a bench job")
        self.assertIn("tools/bench_scan.py --line 800KB --budget 8", CI_YML,
                      "the bench job must run the card's budgeted 800KB gate")
        self.assertIn("--rule-budget 0.5", CI_YML,
                      "no single rule may exceed 0.5 s on the 800KB line")

    def test_sarif_upload_present_with_permissions_and_category(self):
        self.assertIn("github/codeql-action/upload-sarif", CI_YML)
        self.assertIn("security-events: write", CI_YML,
                      "upload-sarif needs the security-events: write permission")
        self.assertRegex(CI_YML, r"(?m)^\s+category: skillsentinel\s*$")

    def test_sarif_stays_an_artifact(self):
        self.assertIn("actions/upload-artifact", CI_YML)

    def test_security_tab_sarif_never_comes_from_the_fixture_scan(self):
        """The uploaded SARIF must be the repo self-scan, not our attack corpus.

        tests/fixtures/malicious exists to make the scanner fire: uploading that
        SARIF as code scanning published ~43 fake critical alerts (all under
        tests/fixtures/malicious/) on the public repo's Security tab, where every
        visitor reads them as real defects.
        """
        producers = {m.group(2): m.group(1)
                     for m in re.finditer(r"skillsentinel scan (\S+)[^\n]*?--sarif (\S+)", CI_YML)}
        uploaded = re.findall(r"(?m)^\s+sarif_file:\s*(\S+)\s*$", CI_YML)
        self.assertTrue(uploaded, "the Security tab upload must name its SARIF file")
        for sarif in uploaded:
            target = producers.get(sarif)
            if target is None:
                self.fail(f"{sarif} is uploaded to code scanning but no scan step writes it")
            self.assertNotIn(
                "fixtures", target,
                f"code scanning must not publish the attack corpus ({target})")

    def test_self_scan_step_writes_the_sarif_that_is_uploaded(self):
        """Without a fresh self-scan SARIF the Security tab keeps stale alerts."""
        uploaded = re.findall(r"(?m)^\s+sarif_file:\s*(\S+)\s*$", CI_YML)
        self.assertTrue(uploaded)
        for sarif in uploaded:
            self.assertRegex(
                CI_YML, rf"skillsentinel scan \. [^\n]*--sarif {re.escape(sarif)}",
                "the repo self-scan must produce the SARIF the Security tab shows")

    def test_ci_scans_use_the_timeout_flag(self):
        self.assertGreaterEqual(
            CI_YML.count("--timeout"), 2,
            "the self-scan steps should dogfood the --timeout flag they document")


class ReadmeTests(unittest.TestCase):
    """README: one true exit-code table, current pins, documented timeout."""

    def test_pins_are_at_least_v0_3_0(self):
        from skillsentinel import __version__
        self.assertNotIn("@v0.2.0", README)
        self.assertNotIn("rev: v0.2.0", README)
        self.assertIn(f"artemasmith/skillsentinel@v{__version__}", README,
                      "the Action snippet must pin the current release tag")
        self.assertIn(f"rev: v{__version__}", README,
                      "the pre-commit snippet must pin the current release tag")

    def test_exactly_one_exit_code_table(self):
        self.assertEqual(README.count("## Exit codes"), 1)
        self.assertNotIn("### Exit codes", README,
                         "the contradictory second table must stay deleted")
        for row, meaning in (("0", "clean"), ("1", "finding"), ("2", "input error"),
                             ("3", "internal error")):
            self.assertRegex(README, rf"\| {row} \|[^|]*{meaning}")

    def test_exit_2_row_covers_timeout_expiry(self):
        self.assertRegex(README, r"\| 2 \|[^|]*`--timeout` expiry")

    def test_action_timeout_documented_with_default(self):
        self.assertIn("timeout: 300", README, "the Action snippet must show the input")
        self.assertIn("default 600", README, "the documented default must match action.yml")

    def test_security_tab_upload_documented(self):
        self.assertIn("upload-sarif", README.lower())
        self.assertIn("security-events: write", README)


class ChangelogReleaseTests(unittest.TestCase):
    """The changelog must carry the notes of the version being released, and
    the release extractor must find them."""

    def test_changelog_carries_a_section_for_the_current_version(self):
        """Either shape is valid: the final `## [0.3.0] - <date>` header, or the
        staging header `## [Unreleased] — 0.3.0` the release workflow also
        accepts. Requiring the staging shape forever would forbid renaming the
        header at release time."""
        import re
        from skillsentinel import __version__
        version = re.escape(__version__)
        self.assertRegex(
            CHANGELOG, rf"(?m)^## .*(?:\[{version}\]|[Uu]nreleased.*\b{version}\b)",
            "the changelog must have a section for the current version")

    def test_release_extractor_finds_the_current_section(self):
        """Replay the release.yml extraction logic against the real CHANGELOG:
        the current version must resolve to its own section and stop at the next
        '## ' header (not swallow an earlier release)."""
        import re
        from skillsentinel import __version__
        version = re.escape(__version__)
        text = CHANGELOG
        headers = [(m.start(), m.group(0)) for m in re.finditer(r"^## .*$", text, re.M)]
        exact = [s for s, h in headers if re.search(rf"\[{version}\]", h)]
        staged = [s for s, h in headers if re.search(rf"\b{version}\b", h)]
        start = (exact or staged or [None])[0]
        assert start is not None, f"no section mentioning {__version__}"
        later = [s for s, _ in headers if s > start]
        section = text[start:later[0] if later else len(text)]
        self.assertIn("###", section,
                      "the release notes for the current version must not be empty")
        self.assertNotIn("watch diff --rescan", section,
                         "the section must end before the 0.2.0 entry begins")


class SarifContractTests(unittest.TestCase):
    """What the Security tab consumes: driver version + rule ids in the report."""

    def test_sarif_carries_driver_version_and_rule_ids(self):
        from skillsentinel.scanner import scan_path, to_sarif
        result = scan_path(REPO / "tests" / "fixtures" / "malicious")
        sarif = to_sarif(result)
        driver = sarif["runs"][0]["tool"]["driver"]
        self.assertRegex(driver["version"], r"^\d+\.\d+\.\d+$")
        rule_ids = [r["id"] for r in driver["rules"]]
        self.assertTrue(rule_ids and all(i.startswith("SS") for i in rule_ids),
                        f"rules must carry SSxxx ids, got {rule_ids[:5]}")


class BenchToolTests(unittest.TestCase):
    """The gate's own tool must be runnable and honest about its verdict."""

    def test_bench_small_line_passes_and_reports(self):
        p = subprocess.run(
            [sys.executable, "tools/bench_scan.py", "--line", "8KB",
             "--budget", "30", "--rule-budget", "5", "--json"],
            capture_output=True, text=True, cwd=REPO, timeout=120)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        data = json.loads(p.stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["line_bytes"], 8 * 1024)

    def test_bench_over_budget_fails(self):
        p = subprocess.run(
            [sys.executable, "tools/bench_scan.py", "--line", "8KB",
             "--budget", "0.000001"],
            capture_output=True, text=True, cwd=REPO, timeout=120)
        self.assertEqual(p.returncode, 1,
                         "an over-budget bench must exit 1 so CI fails")


class WorkflowGateTests(unittest.TestCase):
    """The CI envelope itself: an advertised interpreter or a job that promises
    to consume the shipped artifacts must actually be exercised, otherwise the
    matrix is a claim nobody gates."""

    def test_every_advertised_python_is_in_the_matrix(self):
        advertised = set(re.findall(
            r"Programming Language :: Python :: (\d+\.\d+)", PYPROJECT))
        self.assertTrue(advertised, "pyproject must advertise interpreter versions")
        tested = set(_matrix_versions())
        self.assertEqual(
            advertised - tested, set(),
            f"advertised in classifiers but never tested: {sorted(advertised - tested)}")
        self.assertEqual(
            tested - advertised, set(),
            f"tested but not advertised in classifiers: {sorted(tested - advertised)}")

    def test_matrix_starts_at_the_declared_minimum(self):
        declared = re.search(r'requires-python = ">=(\d+\.\d+)"', PYPROJECT)
        assert declared, "requires-python must declare a minimum"
        floor = min(_matrix_versions(), key=lambda v: tuple(map(int, v.split("."))))
        self.assertEqual(floor, declared.group(1),
                         "the lowest tested interpreter must be the declared minimum")

    def test_pr_runs_cancel_previous_ones(self):
        self.assertRegex(CI_YML, r"(?m)^concurrency:")
        self.assertIn("cancel-in-progress", CI_YML)
        self.assertIn("github.ref", CI_YML,
                      "one run per ref: a push burst must not stack full matrices")

    def test_packaging_job_installs_the_built_wheel_outside_the_checkout(self):
        """The install path is where the S1-S3 defects lived, so the job must
        build the distribution, prove the rule catalog is inside it and then run
        the console script with the checkout off sys.path."""
        parts = CI_YML.split("packaging:", 1)
        self.assertEqual(len(parts), 2, "CI must have a packaging job")
        body = parts[1]
        self.assertIn("python3 -m build", body)
        self.assertIn("pip install --quiet --no-cache-dir dist/*.whl", body)
        self.assertIn("cd /tmp", body,
                      "the installed wheel must be exercised outside the checkout")
        self.assertRegex(body, r"(?m)^\s*unset PYTHONPATH\s*$",
                         "a stray PYTHONPATH makes pip skip the install silently")
        self.assertIn("rules.json", body, "the job must assert the catalog ships in the wheel")
        self.assertIn("twine check", body,
                      "PyPI rejects metadata, not the build: check it in the job that builds")
        self.assertIn("License-Expression: MIT", body,
                      "the shipped METADATA must carry the SPDX expression")
        self.assertIn("$GITHUB_WORKSPACE", body,
                      "scan targets must be absolute after cd /tmp")

    def test_action_gate_job_consumes_the_action_and_checks_its_outputs(self):
        """action.yml is how strangers consume the scanner; the parse of the CLI
        summary line into `findings` must be asserted, or a stale parse becomes
        a false green for every consumer gating on it."""
        parts = CI_YML.split("action-gate:", 1)
        self.assertEqual(len(parts), 2, "CI must have an action-gate job")
        body = parts[1]
        self.assertIn("uses: ./", body, "the gate must consume action.yml like a stranger")
        for step in ("clean", "parse", "attack"):
            self.assertRegex(body, rf"(?m)^\s+id: {step}\s*$")
        self.assertIn("steps.parse.outputs.findings", body,
                      "the reported findings count must be asserted, not just the exit code")
        self.assertIn("steps.clean.outputs.findings", body)
        self.assertIn("action.sarif", body, "the gate must prove the SARIF was written")


class PackagingMetadataTests(unittest.TestCase):
    """PyPI metadata must be PEP 639-clean: the license table is deprecated
    (setuptools drops support 2027-02-18) and a license classifier next to an
    SPDX expression is an error, not a warning."""

    def test_license_is_an_spdx_expression_with_the_license_file(self):
        self.assertRegex(PYPROJECT, r'(?m)^license = "MIT"$')
        self.assertNotIn("license = { text", PYPROJECT,
                         "the license table is deprecated; use an SPDX expression")
        self.assertRegex(PYPROJECT, r'(?m)^license-files = \["LICENSE"\]$',
                         "the text of the license must ship in the distribution")
        self.assertNotIn("License ::", PYPROJECT,
                         "PEP 639 forbids a License classifier next to `license`")

    def test_build_requires_a_pep639_aware_setuptools(self):
        pin = re.search(r"setuptools>=(\d+)", PYPROJECT)
        assert pin, "the build backend must pin a setuptools floor"
        self.assertGreaterEqual(int(pin.group(1)), 77,
                                "SPDX license expressions need setuptools>=77")


if __name__ == "__main__":
    unittest.main()
