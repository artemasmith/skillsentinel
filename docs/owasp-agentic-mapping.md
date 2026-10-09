# OWASP Top 10 for Agentic Applications (2026) — mapping

Bidirectional mapping between SkillSentinel rules ([rules/rules.json](../rules/rules.json))
and the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
(Agentic Security Initiative, December 2025).

Risk names are quoted from the official 2026 list: ASI01 Agent Goal Hijack,
ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse,
ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution (RCE),
ASI06 Memory & Context Poisoning, ASI07 Insecure Inter-Agent Communication,
ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents.

## Rule → OWASP risk

| Rule | Category | OWASP risk |
|---|---|---|
| SS001, SS002, SS003, SS005, SS007 | prompt-injection | ASI01 Agent Goal Hijack |
| SS004 | prompt-injection | ASI02 Tool Misuse and Exploitation |
| SS006 | prompt-injection | ASI08 Cascading Failures |
| SS008, SS009, SS010, SS011, SS012 | invisible-unicode | ASI01 Agent Goal Hijack |
| SS013, SS014, SS015 | obfuscation | ASI01 Agent Goal Hijack |
| SS016, SS017, SS018, SS019 | rce-download | ASI06 Memory & Context Poisoning |
| SS020, SS021, SS022, SS023 | credential-access | ASI04 Agentic Supply Chain Vulnerabilities |
| SS024, SS025, SS026 | exfiltration | ASI09 Human-Agent Trust Exploitation |
| SS027, SS028 | miner | ASI06 Memory & Context Poisoning |
| SS029, SS030, SS031, SS032, SS033 | persistence | ASI06 Memory & Context Poisoning |
| SS034, SS036 | mcp | ASI01 Agent Goal Hijack |
| SS035 | mcp | ASI06 Memory & Context Poisoning |
| SS037, SS038 | self-modification | ASI08 Cascading Failures |

## OWASP risk → rules (reverse direction)

| OWASP risk (2026) | SkillSentinel rules | Coverage |
|---|---|---|
| ASI01 Agent Goal Hijack | SS001–SS003, SS005, SS007–SS015, SS034, SS036 | **15 rules** — prompt injection, unicode smuggling, obfuscation, MCP injection |
| ASI02 Tool Misuse and Exploitation | SS004 | **1 rule** — system-prompt exfiltration via tooling |
| ASI03 Identity and Privilege Abuse | — | **no coverage** |
| ASI04 Agentic Supply Chain Vulnerabilities | SS020–SS023 | **4 rules** — credential access within the skill supply chain |
| ASI05 Unexpected Code Execution (RCE) | — | **no rule-level tag**; partially covered behaviourally by `--detonate` (sandboxed script execution) and the rce-download category (tagged ASI06) |
| ASI06 Memory & Context Poisoning | SS016–SS019, SS027, SS028, SS029–SS033, SS035 | **12 rules** — RCE downloads, miners, persistence, MCP npx-from-URL |
| ASI07 Insecure Inter-Agent Communication | — | **no coverage** |
| ASI08 Cascading Failures | SS006, SS037, SS038 | **3 rules** — hide-from-user instructions, agent self-modification |
| ASI09 Human-Agent Trust Exploitation | SS024, SS025, SS026 | **3 rules** — exfiltration to paste/webhook/ngrok |
| ASI10 Rogue Agents | — | **no coverage** |

## Explicitly uncovered risks

SkillSentinel is a *file* scanner; the following 2026 risks are inherently
out of scope for static rule scanning and have **no rule coverage**:

- **ASI03 Identity and Privilege Abuse** — runtime identity/privilege misuse,
  invisible in skill file contents.
- **ASI05 Unexpected Code Execution (RCE)** — no rule carries the ASI05 tag;
  the closest mitigation is behavioural: `scan --detonate` runs scripts in a
  bubblewrap sandbox and records egress attempts.
- **ASI07 Insecure Inter-Agent Communication** — network protocol level,
  not present in skill files.
- **ASI10 Rogue Agents** — runtime agent lifecycle concern, out of scanner scope.
