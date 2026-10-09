<!-- Thank you! Keep PRs small and focused. -->

## What

<!-- One or two sentences: what does this PR change? -->

## Why

<!-- The problem it solves. If it fixes an issue, add "Fixes #N". -->

## Rule changes (if any)

- [ ] New/changed rule added to `rules/rules.json`
- [ ] A matching **malicious** fixture under `tests/fixtures/malicious/` that it catches
- [ ] A matching **benign** (or `benign-hard`) fixture that it does NOT flag
- [ ] Rule has an `owasp` mapping (see the README table)

## Verification

<!-- Paste the commands you ran and their output. -->

```
python3 -m unittest discover -s tests -v
python3 -m skillsentinel scan tests/fixtures/malicious   # expected: exit 1
python3 -m skillsentinel scan tests/fixtures/benign      # expected: exit 0
python3 -m skillsentinel scan tests/fixtures/benign-hard # expected: exit 0
```

- [ ] All tests pass (32)
- [ ] No new finding on `benign` or `benign-hard`
- [ ] No stdlib-only rule violated (no new dependencies)
