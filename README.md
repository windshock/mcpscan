# MCP Security Lab & Guardrail Tool

Docker-based evaluation lab for MCP security scanners, plus a policy-based guardrail tool (`mcp-guard`).

## Background

MCP security is not just about prompt injection.

It is about trust boundaries between configuration and execution.

- https://windshock.github.io/en/post/2026-05-07-mcp-is-repeating-rpc-security-history/

## Status

The five work items from [docs/COMPLETION_PLAN.md](docs/COMPLETION_PLAN.md) are complete. Latest live benchmark numbers below; full per-server details live in [results/report/comparison.md](results/report/comparison.md) and [results/report/ox-live.md](results/report/ox-live.md).

## Benchmark Results

11 lab servers, 24 expected findings. Source-only and live-endpoint stages run in the same `docker compose run --rm runner` invocation; the combined view shows what `mcp-guard` catches when both stages contribute.

| Scanner | TP | FP | FN | Recall | Precision |
|---|---:|---:|---:|---:|---:|
| MCPScan (semgrep taint) | 0 | 4 | 24 | 0.0% | 0.0% |
| Cisco mcp-scanner (yara analyzer, no API keys) | 1 | 1 | 23 | 4.2% | 50.0% |
| mcp-guard (source path) | 23 | 0 | 1 | 95.8% | 100% |
| mcp-guard-endpoint (live SSE + HTTP probe) | 15 | 0 | 9 | 62.5% | 100% |
| **mcp-guard combined (source ∪ endpoint)** | **24** | **0** | **0** | **100%** | **100%** |

The single source-only FN is `authless_endpoint` on `vuln-authless` — a runtime property no static scan can reach. The live endpoint stage closes it. `expected_false_positives` are documented per-server in [`runner/expected-findings.json`](runner/expected-findings.json) (e.g., FastMCP's unenforced auth defaults are tolerated for normal servers).

The TypeScript lab servers (`vuln-network`, `vuln-allowlist-bypass`) ship an older `SSEServerTransport` that the current MCP Python client and Cisco scanner cannot list tools from. The endpoint stage falls back to HTTP probes for them; vuln-hidden-transport is fully covered that way.

## Threat Models

`mcp-guard` and `cisco-mcp-scanner` are complementary, not redundant — see [docs/threat-models.md](docs/threat-models.md) for the full discussion.

| | **mcp-guard** | **cisco-mcp-scanner (yara)** |
|---|---|---|
| Looks for | Capability gaps (authless, unrestricted file/env, allowlist bypass, hidden admin, runtime-only) | Malicious-intent payloads in tool descriptions/code |
| Use case | Audit your own MCP before deploy | Vet a third-party MCP before install |
| Lab recall | 100 % combined | 4.2 % (capability lab is outside cisco-yara's scope) |

## Integrated Usage

`mcp-guard scan` has a `--with-cisco` flag that runs the cisco mcp-scanner alongside our detectors and merges findings with a `source` tag. Cisco needs to be on `PATH` (`pip install cisco-ai-mcp-scanner`) — when missing, mcp-guard prints a warning and continues alone.

```bash
# Developer pre-commit (path mode)
mcp-guard scan --path ./servers/vuln-exec --with-cisco

# Supply-chain audit (config mode, cisco's natural fit)
mcp-guard scan --config /path/to/mcp.json --with-cisco

# Live endpoint monitoring
mcp-guard scan --endpoint http://localhost:3102/sse --with-cisco --output json
```

Cisco analyzer selection:

- `yara` (default) is offline.
- `behavioral` and `llm` need an LLM API key in `MCP_SCANNER_LLM_API_KEY` (auto-enabled when present).
- Override explicitly: `--cisco-analyzers yara,behavioral,llm`.
- Subprocess time cap: `--cisco-timeout 60`.

Each finding in the JSON output carries a `source` field (`mcp-guard`, `cisco-yara`, `cisco-behavioral`, `cisco-llm`) plus a per-pattern `provenance` map. The PolicyEngine escalates any `HIGH`/`CRITICAL` cisco finding to `BLOCK` regardless of `--env`.

Verbose mode (`-v` INFO, `-vv` DEBUG) emits scan progress, hidden-probe URLs+statuses, cisco subprocess invocations, and suppression decisions (e.g. `suppressing command_exec/env_exposure: runtime-only family fired`). Logs go to stderr so `--output json` stays pipeable.

Each scan also emits a `Target details` block identifying *what* was scanned: for `--endpoint`, the listening process (PID + command via `lsof`) and Docker container (name, image, compose service, working_dir) when applicable; for `--path`, the resolved absolute path, file count by extension, and git remote+commit; for `--config`, the file path or inline-JSON marker plus a preview of declared `mcpServers`.

Bulk modes:

- `--auto` runs `discover` and scans the highest-ranked candidate.
- `--auto-all` scans **every** discovered candidate (one section per target). Exit code is 1 if any target evaluates to BLOCK.

## Public Tunnel Detection

Discovery recognises three free no-signup tunnel paths and the legacy ngrok flow, both as host processes and as docker compose sidecars:

| Tunnel | Detected via | Public URL pattern |
|---|---|---|
| cloudflared (quick tunnel) | host process or container logs | `https://*.trycloudflare.com` |
| localtunnel | host `lt`/npx process or container logs | `https://*.loca.lt` |
| bore | host `bore local` process or container logs | `tcp://bore.pub:<port>` |
| ngrok | host process + local API (`/api/endpoints`) | `https://*.ngrok-free.app` (token required) |

When a tunnel forwards to a local MCP, `mcp-guard discover` and `mcp-guard scan` attach the public URL to the same candidate / target metadata so vulnerability findings and supply-chain exposure show up together:

```
Target details:
  docker:
    container: mcp-lab-vuln-authless-1
    compose_service: vuln-authless
  public_tunnels:
    - provider=cloudflared,
      public_url=https://abc.trycloudflare.com,
      container=mcp-lab-cloudflared-tunnel-1
```

... (rest unchanged)