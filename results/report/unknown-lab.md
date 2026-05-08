# Unknown-Lab: Blind comparison on real released packages

Generated: 2026-05-08T03:44:40.093237+00:00

This stage scans unmodified upstream releases. There are no `expected_findings` — the value is in (a) what each scanner uniquely surfaces, (b) deltas between adjacent version pairs (e.g. before vs after a security fix).

**Two scan modes covered**: (i) *source* — scan the actual shipped source tree; (ii) *config* — scan two categories of MCP configs: docs-recommended honest baselines (FP-rate probes) and CVE-2026-40933 / CVE-2026-30625 sanitizer-bypass patterns from the [OX research blog](https://www.ox.security/blog/flowise-cve-2026-40933-upsonic-cve-2026-30625-what-to-do-when-best-practice-isnt-enough/). The bypass pattern is `<allowed_cmd> <innocent-looking-arg> <attacker-controlled-payload>` (e.g. `npx -c curl ...`, `python -c "import os; ..."`, `git -c core.pager=...`) — the Flowise/Upsonic input sanitizer accepts it because the leading binary is in the allowlist and the argument string contains no `&|>` shell metacharacters, but the binary itself interprets the next argument and runs arbitrary code.

Live-launch is intentionally not run here: Flowise (MCP *host/client*) and Upsonic (MCP *client* SDK) do not expose their own tools as MCP servers, so there's no SSE/stdio endpoint to probe. A higher-fidelity reproduction would stand up Flowise/Upsonic instances and submit each bypass config through their MCP-server-add UI/API — that's a separate lab tier we can build out next.

## Per-package findings

| Package | mcp-guard verdict | mcp-guard findings | MCPScan rules (count × unique) |
|---|---|---|---|
| flowise-3.0.13 | BLOCK | command_exec, unrestricted_file_read | — |
| flowise-3.1.0 | BLOCK | command_exec, unrestricted_file_read | — |
| upsonic-0.71.6 | BLOCK | allowlist_bypass, command_exec_via_args, conditional_command_exec, config_to_execution, excessive_permissions, runtime_only_danger, unrestricted_file_write | 60 hits across 2 rules: detect-command-execution, detect-hardcoded-secrets-py |
| upsonic-0.72.0 | BLOCK | allowlist_bypass, command_exec_via_args, conditional_command_exec, config_to_execution, excessive_permissions, runtime_only_danger, unrestricted_file_write | 64 hits across 2 rules: detect-command-execution, detect-hardcoded-secrets-py |

## Version-pair deltas (fix-before → fix-after)

| Pair | Scanner | Before-only | After-only | Common |
|---|---|---|---|---|
| flowise-3.0.13 → flowise-3.1.0 | mcp-guard | — | — | command_exec, unrestricted_file_read |
| flowise-3.0.13 → flowise-3.1.0 | mcpscan | — | — | — |
| upsonic-0.71.6 → upsonic-0.72.0 | mcp-guard | — | — | allowlist_bypass, command_exec_via_args, conditional_command_exec, config_to_execution, excessive_permissions, runtime_only_danger, unrestricted_file_write |
| upsonic-0.71.6 → upsonic-0.72.0 | mcpscan | — | — | detect-command-execution, detect-hardcoded-secrets-py |

## Scanner overlap (per package)

| Package | mcp-guard only | MCPScan only | Both |
|---|---|---|---|
| flowise-3.0.13 | command_exec, unrestricted_file_read | — | — |
| flowise-3.1.0 | command_exec, unrestricted_file_read | — | — |
| upsonic-0.71.6 | allowlist_bypass, command_exec_via_args, conditional_command_exec, config_to_execution, excessive_permissions, runtime_only_danger, unrestricted_file_write | detect-command-execution, detect-hardcoded-secrets-py | — |
| upsonic-0.72.0 | allowlist_bypass, command_exec_via_args, conditional_command_exec, config_to_execution, excessive_permissions, runtime_only_danger, unrestricted_file_write | detect-command-execution, detect-hardcoded-secrets-py | — |

## Config-mode fixture scans

Two fixture categories: **sanitizer_bypass** are CVE-2026-40933 / CVE-2026-30625 patterns from the OX research blog — the canonical Flowise/Upsonic command-input sanitizer treats them as safe (allowed command + no blocked special character) but the runtime interprets a subsequent argument and executes arbitrary code. A scanner that misses these is letting a known supply-chain RCE through. **honest_baseline** are non-malicious configs straight from the Flowise / Upsonic docs — flags here are scanner false positives against real-world paste targets.

### sanitizer_bypass — CVE-grade exploit configs

| Config fixture | CVE | mcp-guard | Cisco config | Invariant/Snyk config |
|---|---|---|---|---|
| flowise-bypass-docker-mount | CVE-2026-40933 | BLOCK: allowlist_bypass, config_to_execution | — | — |
| flowise-bypass-npx-c | CVE-2026-40933 | BLOCK: allowlist_bypass, config_to_execution | — | — |
| flowise-bypass-npx-p | CVE-2026-40933 | BLOCK: allowlist_bypass, config_to_execution | — | — |
| flowise-bypass-python-m | CVE-2026-40933 | BLOCK: allowlist_bypass, config_to_execution | — | — |
| upsonic-bypass-git-pager | CVE-2026-30625 | BLOCK: allowlist_bypass, config_to_execution | — | — |
| upsonic-bypass-uvx-from | CVE-2026-30625 | BLOCK: allowlist_bypass, config_to_execution | — | — |

### honest_baseline — docs-recommended configs (FP-rate probe)

| Config fixture | mcp-guard | Cisco config | Invariant/Snyk config |
|---|---|---|---|
| flowise-stdio-docker | BLOCK: allowlist_bypass, config_to_execution | — | — |
| flowise-stdio-sequential-thinking | BLOCK: allowlist_bypass, config_to_execution | — | — |
| flowise-streamable-http-github | ALLOW: — | — | command_exec, env_exposure, tool_poisoning |
| upsonic-multi-sqlite | BLOCK: allowlist_bypass, config_to_execution | — | unrestricted_file_read |
| upsonic-uvx-sqlite | BLOCK: allowlist_bypass, config_to_execution | — | unrestricted_file_read |
