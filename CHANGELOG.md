# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-12

### Added

- `watch diff --rescan`: re-scan the changed/added files of a drift and print
  their confirmed findings (`skillsentinel.watch.rescan_changes(root, diff)`) —
  drift output now explains WHAT changed, not only that something did. Exit
  codes unchanged: any drift is still exit 1, a clean tree 0.
- Version identity in machine output: `scan --json` carries top-level
  `version` (scanner) and `rules_version` (the catalog's `_version`); SARIF
  `tool.driver.version` names the exact scanner build.
- Release pipeline (`.github/workflows/release.yml`), triggered only by `v*`
  tags: builds sdist + wheel, attaches them to a GitHub Release, and publishes
  to PyPI only when the `PYPI_API_TOKEN` secret is set — without the token the
  workflow still succeeds, printing that publish was skipped.
- CI now uploads `scan.sarif` to the GitHub Security tab via
  `github/codeql-action/upload-sarif@v3` (`if: always()`, so findings are
  reported even when the fail-closed scan step fails); the RC==1 check on the
  malicious fixtures is unchanged.
- pre-commit integration: `.pre-commit-hooks.yaml` defines the `skillsentinel`
  hook (repo-root scan, non-zero exit on confirmed findings).
- README: Install section (`pipx install skillsentinel` /
  `pip install git+https://…`), an exit-code table (0/1/2/3), a pre-commit
  usage section, and the GitHub Action usage pinned to a version tag instead
  of `@main`.
- `[project.urls]`: Changelog and Issues.

### Changed

- One version everywhere: `skillsentinel.__version__`, `rules.json`
  `_version` and `pyproject.toml` all read 0.2.0. Zero runtime dependencies
  unchanged (`dependencies = []`).

### Fixed

- CI self-scan gate: the "Scan repo itself (expect clean)" step now passes
  `--honor-ignores`, so the repo's own `.skillsentinelignore` (rule catalog,
  malicious fixtures) applies. The gate had been red since the hardening merge —
  the tree was never dirty, the flag was missing.
- `.worktrees/` added to `.gitignore` and `.skillsentinelignore`: agent
  worktrees are full checkouts and were reported as a second copy of the repo.
- Release notes for a tag now come from that version's `CHANGELOG.md` section
  (`body_path`) instead of GitHub's auto-generated commit list.

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
