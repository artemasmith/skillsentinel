# Contributing

Bug reports, rule ideas and PRs are welcome. Small and focused beats large and sprawling.

## Setup

```bash
git clone https://github.com/artemasmith/skillsentinel && cd skillsentinel
python3 -m unittest discover -s tests -v   # must pass: 32 tests
```

Python ≥ 3.10, stdlib only — a PR that adds a runtime dependency will be declined.

## How to add a rule

1. Add the rule to [`rules/rules.json`](rules/rules.json): `id` (next `SSnnn`), `title`,
   `severity` (`critical|high|medium|low`), `category`, `owasp` (Agentic Top 10 ID, see
   the README table), `description`, and the regex `pattern`.
2. Add a **malicious fixture** under `tests/fixtures/malicious/<nn-name>/` that the rule
   catches — inert payload, real attack structure (example.com hosts, no live secrets).
3. Add a **benign look-alike** under `tests/fixtures/benign/` or `benign-hard/` that the
   rule (or its verifier path) must *not* flag — this is the part that keeps the scanner
   installed on people's machines.
4. Extend `tests/test_skillsentinel.py` to assert both directions.
5. If the raw pattern over-fires, extend the verifier (`skillsentinel/verifier.py`)
   instead of weakening the pattern — recall belongs to the rules, precision to the verifier.
6. Run the full suite; all three fixture corpora must keep their expected outcome
   (malicious → findings, benign and benign-hard → exit 0).

## How to report a false positive / false negative

Use the issue templates (`.github/ISSUE_TEMPLATE/`). The definitions this project uses:

- **False positive** — the scanner reports a confirmed finding (`exploitable` or a
  confirmed candidate) on a file whose legitimate purpose is clear from its context,
  and a careful human reviewer would not flag it. "The rule matched" is *not* a false
  positive — only the final verdict counts.
- **False negative** — a genuinely malicious file or line produces no confirmed finding:
  either no rule matched, or the verifier demoted the candidate.

Both reports should include the exact command, the verbatim `verdict:` line, and a
minimized (and neutralized) copy of the file.

## Style

- Keep the CLI output stable — people parse it in CI.
- Every demotion must keep a written reason; never drop a candidate silently.
- No telemetry, no network calls, ever.

## License

By contributing you agree your contributions are licensed under the [MIT license](LICENSE).
