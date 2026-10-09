# Security Policy

## Supported versions

The latest `main` branch and the most recent release.

## Reporting a vulnerability

If you found a security issue **in SkillSentinel itself** (a bypass of the scanner,
a sandbox escape in `--detonate`, a crash on malformed input):

1. Do **not** open a public issue.
2. Use [GitHub private vulnerability reporting](https://github.com/artemasmith/skillsentinel/security/advisories/new)
   for this repository, or email the maintainer at the address on the commits.
3. Include the exact command, the input that triggers it, and the observed vs. expected behavior.

You will get an acknowledgement within a few days. Coordinated disclosure: please wait
for a fix (or 90 days) before publishing.

## What is NOT a vulnerability in SkillSentinel

- A malicious skill that SkillSentinel fails to detect → open a
  **false-negative** issue (it improves the rule set, but it is expected behavior of a
  heuristic scanner).
- A malicious skill that *is* detected → working as intended.
- Detonation caveats (raw sockets not intercepted) → already documented under
  Limitations in the README; `--detonate` is evidence collection, not a containment boundary.

## Detonation safety notes

`--detonate` executes skill scripts under bubblewrap with shimmed network tools.
It is designed for inert test fixtures and triage of suspicious-but-unexecuted skills.
Do not detonate a skill you already have strong reasons to consider hostile on a machine
you care about — use a disposable VM instead.
