# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-09

### Added

- `scan` command: scan a skill file or directory for prompt injection, invisible
  unicode (zero-width, tag characters, bidi overrides, variation selectors, ANSI
  escapes), base64/hex obfuscation, `curl | bash` remote-code-execution downloads,
  credential access (SSH keys, `.env`, API tokens, browser/OS credential stores),
  exfiltration (paste services, webhooks/ngrok, bulk upload), crypto miners
  (stratum protocol, known pool domains), persistence (crontab, systemd/launchd,
  shell rc, git hooks, `authorized_keys`), MCP backdoors (command injection in
  `mcp.json`, `npx` from URL, tool-description override) and agent
  self-modification — 38 rules in `rules/rules.json`.
- Two-stage pipeline: a rule match is only a *candidate*; a file-local verifier
  (`verifier.py`) confirms or demotes it. Every demotion carries a written reason
  in the scan output (`verdict:` line). Verified on the fixtures: 42 confirmed
  findings on `tests/fixtures/malicious`, 0 on `tests/fixtures/benign` (32 tests).
- `--profile` flag (`strict` / `balanced` / `loose` / `paranoid`) controlling how
  many candidates survive verification to findings.
- `--detonate` flag: run discovered scripts inside a disposable bubblewrap sandbox
  and record attempted network egress (skipped with a notice when bwrap is absent).
- `--sarif OUT.sarif` flag: write a SARIF 2.1.0 report alongside the human output.
- `--json` machine-readable output, `--severity` exit-code threshold,
  `--honor-ignores` (OFF by default — a scanned file must not be able to silence
  its own detection), `--exclude` globs plus `.skillsentinelignore` support,
  `--rules` for an alternative rule catalog.
- `watch` command with `init` / `diff` / `show` subcommands: record a hash
  snapshot of an **installed** skill tree and detect post-install drift
  (rug-pulls) on later runs.
- `rules` command: list the loaded detection rules.
- Composite GitHub Action (`action.yml`) to scan skills in CI.
- Zero runtime dependencies — Python 3.10+ stdlib only.

[0.1.0]: https://github.com/artemasmith/skillsentinel/releases/tag/v0.1.0
