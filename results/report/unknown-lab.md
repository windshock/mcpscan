# Unknown-Lab: Blind comparison on real released packages

Generated: 2026-05-08T01:34:52.517163+00:00

This stage scans unmodified upstream releases. There are no `expected_findings` — the value is in (a) what each scanner uniquely surfaces, (b) deltas between adjacent version pairs (e.g. before vs after a security fix).

**Why source-mode only**: the chosen packages (Flowise 3.0.13/3.1.0, Upsonic 0.71.6/0.72.0) do not expose a native "run as an MCP server" CLI in these releases — Flowise is an AI workflow platform and Upsonic is an MCP *client* SDK that consumes external MCP servers. There is therefore no live SSE/stdio endpoint to point cisco-remote / invariant-scan / mcp-guard --endpoint at, and no honest mcpServers config to feed cisco-config / invariant-config / mcp-guard --config. The OX research corpus's `flowise_attack` and `upsonic_attack` cases (in `cisco-config` / `invariant-config` reports) cover the config-to-execution supply-chain *attack* pattern against these names; this section covers the orthogonal axis — **what does each scanner detect when looking at the actual shipped source code?**

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
