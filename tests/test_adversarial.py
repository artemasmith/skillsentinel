"""Acceptance tests for detection-bypass fixes (card t_595efa7f — F1/F5/F6/F7/F10).

Status as written (TDD red step):
- RED today: AC1 (cancel-word in object position), AC3 (invisible-unicode
  smuggling), AC4 (strict profile identical to balanced + missing
  profile_variant), AC5 (--show-inconclusive listing), AC7 (stage-2
  base64/hex decode). They fail on the current scanner — that is the point.
- GREEN today and after the fix: AC2 (detector/doc grammar stays demoted)
  and AC6 (latin-1 read still yields a normal verdict) — regression guards.

All fixtures live in tests/fixtures/adversarial/ (committed, never /tmp).
"""

import io
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from skillsentinel.cli import build_parser  # noqa: E402
from skillsentinel.scanner import scan_path  # noqa: E402

ADV = REPO / "tests" / "fixtures" / "adversarial"
A01 = ADV / "a01_object"
A02 = ADV / "a02_decode"
A03 = ADV / "a03_docmention"
A04 = ADV / "a04_wrapper"
A05 = ADV / "a05_unicode"
A06 = ADV / "a06_encoding"

MEDIUM_OR_WORSE = ("medium", "high", "critical")


class ObjectPositionMaskingTests(unittest.TestCase):
    """AC1 — a defensive-lexicon word as the OBJECT of the attack must not cancel it.

    `Ignore all previous instructions about malware detection` — `detection` is
    what the instructions are *about*, not a claim that the line detects anything.
    Same for `to the attacker` / `that mention the scanner`. The naive cancel-word
    check demotes all of these today (F1 self-masking).
    """

    def test_ignore_line_with_object_position_cancel_word_is_confirmed(self):
        result = scan_path(A01)
        hits = [f for f in result.confirmed()
                if f.rule_id == "SS001" and f.file == "SKILL.md" and f.line == 3]
        self.assertTrue(hits, "SS001 on the ignore-line was demoted by an "
                        "object-position defensive word: "
                        f"{[(f.rule_id, f.line, f.verdict) for f in result.demoted]}")

    def test_ssh_and_exfil_lines_yield_confirmed_critical(self):
        result = scan_path(A01)
        attack_lines = {4, 5, 6}  # send ~/.ssh/id_rsa / exfiltrate / ignore prior prompts
        hits = [f for f in result.confirmed()
                if f.file == "SKILL.md" and f.line in attack_lines
                and f.severity == "critical"
                and f.rule_id in ("SS020", "SS026", "SS001")]
        self.assertTrue(hits, "no confirmed critical on the ssh/exfil/ignore lines: "
                        f"{[(f.rule_id, f.line, f.verdict) for f in result.demoted]}")


class DocMentionGuardTests(unittest.TestCase):
    """AC2 — guard: the same strings in detector/documentation grammar stay demoted.

    Must pass BEFORE and AFTER the fix: `detects the phrase "ignore all previous
    instructions"`, `pattern: disregard your instructions`, `matches: reveal your
    system prompt` and the regex literal are descriptions, not directives.

    D11 keeps this guard honest by requiring the marking: the quoted phrase with a
    citation frame ("detects the phrase ...") and the `pattern:`/`matches:` lines as
    inline code. Unmarked detector prose in a doc is indistinguishable from a
    payload and is reported as one — see tests/test_doc_surface.py.
    """

    def test_doc_lines_produce_no_confirmed_findings(self):
        result = scan_path(A03)
        confirmed = [(f.rule_id, f.file, f.line) for f in result.confirmed()]
        self.assertEqual(confirmed, [],
                         "documentation mentions must stay demoted (AC2 guard broken)")


class UnicodeSmugglingTests(unittest.TestCase):
    """AC3 — invisible characters must be stripped and NFKC-normalized before matching.

    a05_unicode/SKILL.md smuggles directives with U+200B (line 3), U+00AD (line 4),
    U+034F (line 5) inside words, plus a fullwidth variant of the whole phrase
    (line 6). Today only SS008 fires on line 3; the smuggled intent itself
    (SS001) never matches — F5.
    """

    SMUGGLED_LINES = {3, 4, 5, 6}
    INVISIBLE_LINES = {3, 4, 5}  # fullwidth is width, not an invisible character

    @classmethod
    def setUpClass(cls):
        cls.result = scan_path(A05)

    def test_smuggled_directive_confirmed_after_normalization(self):
        hits = [f for f in self.result.confirmed()
                if f.rule_id == "SS001" and f.file == "SKILL.md"
                and f.line in self.SMUGGLED_LINES]
        self.assertTrue(hits, "SS001 must match the normalized smuggled text; "
                        f"confirmed={[ (f.rule_id, f.line) for f in self.result.confirmed()]}")

    def test_invisible_normalization_finding_is_reported(self):
        hits = [f for f in self.result.findings
                if "invisible characters normalized" in (f.title + " " + f.reason).lower()
                and f.severity in MEDIUM_OR_WORSE]
        self.assertTrue(hits, "no 'invisible characters normalized' finding (>= medium)")
        self.assertTrue(any(h.file == "SKILL.md" and h.line in self.INVISIBLE_LINES
                            for h in hits),
                        f"marker must point at the smuggled file:line, got "
                        f"{[(h.file, h.line) for h in hits]}")


class StrictProfileTests(unittest.TestCase):
    """AC4 — strict disables verifier demotions and must differ from balanced.

    Strict confirms ALL candidates (demoted is empty — no verdict class is
    exempt), a strict superset of balanced; ScanResult.to_dict carries
    `profile_variant`.
    """

    def test_strict_confirms_more_than_balanced(self):
        strict = scan_path(ADV, profile="strict")
        balanced = scan_path(ADV, profile="balanced")
        self.assertEqual(strict.demoted, [],
                         "strict must not demote anything: "
                         f"{[(f.rule_id, f.file, f.line, f.verdict) for f in strict.demoted]}")
        ks = {(f.file, f.line, f.rule_id) for f in strict.confirmed()}
        kb = {(f.file, f.line, f.rule_id) for f in balanced.confirmed()}
        self.assertNotEqual(ks, kb, "strict and balanced confirm the same set")
        self.assertGreater(len(ks), len(kb), "strict must confirm a strict superset")

    def test_scan_result_carries_profile_variant(self):
        for profile in ("strict", "balanced"):
            with self.subTest(profile=profile):
                d = scan_path(ADV, profile=profile).to_dict()
                self.assertEqual(d.get("profile_variant"), profile,
                                 f"to_dict() must carry profile_variant={profile!r}")


class InconclusiveListingTests(unittest.TestCase):
    """AC5 — inconclusive candidates must be listable from the CLI.

    a02_decode/config.env holds a pastebin URL in a non-directive/non-code file:
    its SS024 candidate is graded `inconclusive` (unknown context) today.
    """

    def test_show_inconclusive_flag_parses(self):
        args = build_parser().parse_args(["scan", str(A02), "--show-inconclusive"])
        self.assertTrue(args.show_inconclusive)

    def test_text_output_lists_inconclusive_candidates(self):
        args = build_parser().parse_args(["scan", str(A02), "--show-inconclusive"])
        buf = io.StringIO()
        with redirect_stdout(buf):
            args.func(args)
        out = buf.getvalue()
        self.assertIn("inconclusive candidate(s)", out)
        self.assertRegex(out, r"config\.env:\d+",
                         "listing must carry a file:line reference")


class Latin1ReadTests(unittest.TestCase):
    """AC6 — guard: a latin-1 file (bytes not valid utf-8) gets a normal verdict.

    The scanner reads with errors='replace', so the ASCII directive line survives
    and SS001 is confirmed (not skipped as inconclusive). Passes today; keeps the
    encoding path honest while F11 hardening lands elsewhere.
    """

    def test_latin1_skill_gets_confirmed_ss001(self):
        result = scan_path(A06)
        hits = [f for f in result.confirmed()
                if f.rule_id == "SS001" and f.file == "SKILL.md"]
        self.assertTrue(hits, "latin-1 read must not turn the verdict inconclusive: "
                        f"{[(f.rule_id, f.verdict, f.reason) for f in result.demoted]}")


class Stage2DecodeTests(unittest.TestCase):
    """AC7 — stage-2 obfuscation: a blob in a variable on one line, executed from
    the next. The scanner must decode the blob and run the decoded text through
    the rules (SS016 fires on the decoded curl|bash pipeline) — F7.

    a02_decode/run.py: base64 blob (>= 16 chars) + exec(base64.b64decode(P)).
    a04_wrapper/wrap.sh: hex blob (>= 16 chars) + eval "$P".
    Neither produces a single candidate today: the payload only exists decoded.
    """

    def _decoded_confirmed(self, result, filename):
        return [f for f in result.confirmed()
                if f.file == filename
                and ("decoded" in f.reason.lower()
                     or "decoded_from" in f.to_dict())]

    def test_base64_blob_exec_is_confirmed_via_decoded_text(self):
        result = scan_path(A02)
        hits = self._decoded_confirmed(result, "run.py")
        self.assertTrue(hits, "no confirmed finding marked as decoded for run.py: "
                        f"{[(f.rule_id, f.verdict) for f in result.demoted]}")
        self.assertIn("SS016", {f.rule_id for f in hits},
                      "the rule firing on the decoded text is SS016 (curl|bash)")

    def test_hex_blob_eval_is_confirmed_via_decoded_text(self):
        result = scan_path(A04)
        hits = self._decoded_confirmed(result, "wrap.sh")
        self.assertTrue(hits, "no confirmed finding marked as decoded for wrap.sh: "
                        f"{[(f.rule_id, f.verdict) for f in result.demoted]}")
        self.assertIn("SS016", {f.rule_id for f in hits},
                      "the rule firing on the decoded text is SS016 (curl|bash)")


if __name__ == "__main__":
    unittest.main()
