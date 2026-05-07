# mcp-guard

Policy-based security guardrail for MCP (Model Context Protocol) integrations. Detects capability-based vulnerabilities (authless endpoints, unrestricted file/env access, allowlist bypass, hidden admin endpoints, runtime-only triggers) in MCP server source, configs, and live endpoints.

Optionally fuses with [cisco-ai-mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner) for malicious-intent / supply-chain detection.

## Install

```bash
# Wheel from latest GitHub release
pip install https://github.com/windshock/mcpscan/releases/download/v0.1.0/mcp_guard-0.1.0-py3-none-any.whl

# With cisco supply-chain detection
pip install 'https://github.com/windshock/mcpscan/releases/download/v0.1.0/mcp_guard-0.1.0-py3-none-any.whl[cisco]'
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
```

JSON output (`--output json`) tags each finding with `source` (`mcp-guard`, `cisco-yara`, `cisco-behavioral`, `cisco-llm`) and emits a `provenance` map keyed by pattern id.

## Threat models

`mcp-guard` and `cisco-ai-mcp-scanner` are complementary, not redundant:

- **mcp-guard**: capability gaps in MCPs you author or operate (auth, allowlists, runtime triggers).
- **cisco-mcp-scanner**: malicious-intent payloads in third-party MCPs you're about to install.

See [`docs/threat-models.md`](https://github.com/windshock/mcpscan/blob/main/docs/threat-models.md) for the decision tree.

## Lab benchmark

The repo also contains an 11-server docker-compose lab that benchmarks `mcp-guard`, `cisco-mcp-scanner`, and `mcpscan` side by side. Latest combined recall: **24/24 (100 %)** with **100 % precision**. See [`results/report/comparison.md`](https://github.com/windshock/mcpscan/blob/main/results/report/comparison.md).

## License

MIT
