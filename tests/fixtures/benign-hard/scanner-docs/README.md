# Skill scanner rules

The scanner looks for these signatures in skill files:

| Category | Indicators |
|---|---|
| Prompt injection | `IGNORE PREVIOUS`, `system override`, `disregard`, `developer mode` |
| Exfiltration | `curl ... | bash`, `webhook.site`, `ngrok.io` |
| Miners | `xmrig`, `stratum+tcp://`, `--donate-level` |
| Backdoors | reverse shell, keylogger, `nc -e` |

Each signature is a candidate, verified before it becomes a finding.
