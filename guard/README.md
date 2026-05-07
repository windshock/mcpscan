# mcp-guard

Policy-based security guardrail for MCP (Model Context Protocol) integrations. Detects capability-based vulnerabilities (authless endpoints, unrestricted file/env access, allowlist bypass, hidden admin endpoints, runtime-only triggers) in MCP server source, configs, and live endpoints.

Optionally fuses with [cisco-ai-mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) for malicious-intent / supply-chain detection.

## Install

```bash
# Wheel from latest GitHub release
pip install https://github.com/windshock/mcpscan/releases/download/v0.2.4/mcp_guard-0.2.4-py3-none-any.whl

# With cisco supply-chain detection
pip install 'https://github.com/windshock/mcpscan/releases/download/v0.2.4/mcp_guard-0.2.4-py3-none-any.whl[cisco]'
```

## Quickstart

```bash
# Audit local MCP server source
mcp-guard scan --path ./my-mcp-server

# Audit an MCP config (supply-chain check)
mcp-guard scan --config ./mcp.json

# Probe a running MCP endpoint
mcp-guard scan --endpoint http://localhost:3000/sse

# Combine with cisco for both threat models
mcp-guard scan --config ./mcp.json --with-cisco

# Auto-discover and scan a single best candidate (highest-ranked)
mcp-guard scan --auto

# Auto-discover and scan ALL candidates (one report per target)
mcp-guard scan --auto-all
```

`--auto-all` walks every listening port + known MCP project marker, scans each, and emits one section per target. Exit code is 1 if any target evaluates to BLOCK. Wall-clock cost grows with the number of listening services on your host (each non-MCP port costs roughly 8–15 s in connection timeouts), so prefer `--auto` or an explicit `--endpoint` for tight CI loops.

JSON output (`--output json`) tags each finding with `source` (`mcp-guard`, `cisco-yara`, `cisco-behavioral`, `cisco-llm`) and emits a `provenance` map keyed by pattern id.

Verbose logging:

```bash
mcp-guard -v scan --path .          # INFO: scan progress + verdict summary
mcp-guard -vv scan --path .         # DEBUG: per-file reads + suppression decisions
mcp-guard -q scan --path .          # ERROR only
```

Logs go to stderr so `--output json` on stdout stays pipeable.

Each scan also emits a `Target details` block in both text and JSON output that identifies *what* was scanned:

- `--endpoint`: listening process (PID + command via `lsof`) and Docker container info (name, image, compose project/service/working_dir) when the target is a Docker-mapped port.
- `--path`: resolved absolute path, file count by extension, total bytes, git remote + commit + dirty flag.
- `--config`: file path or `inline_json` marker, plus a preview of declared `mcpServers` (name, command, transport).

All collectors are best-effort: missing `lsof` / `docker` / `git` quietly skip without breaking the scan.

## Threat models

`mcp-guard` and `cisco-ai-mcp-scanner` are complementary, not redundant:

- **mcp-guard**: capability gaps in MCPs you author or operate (auth, allowlists, runtime triggers).
- **cisco-mcp-scanner**: malicious-intent payloads in third-party MCPs you're about to install.

See [`docs/threat-models.md`](https://github.com/windshock/mcpscan/blob/main/docs/threat-models.md) for the decision tree.

## Lab benchmark

The repo also contains an 11-server docker-compose lab that benchmarks `mcp-guard`, `cisco-mcp-scanner`, and `mcpscan` side by side. Latest combined recall: **24/24 (100 %)** with **100 % precision**. See [`results/report/comparison.md`](https://github.com/windshock/mcpscan/blob/main/results/report/comparison.md).

## License

MIT
