# MCP Security Lab & Guardrail Tool

Docker-based evaluation lab for MCP security scanners, plus a policy-based guardrail tool (`mcp-guard`).

<p align="center">
  <img src="demo/mcp-guard-4x5.gif" alt="mcp-guard scan demo: capability audit on a running Docker MCP, then a supply-chain config check" width="540"/>
</p>

The clip walks through `mcp-guard scan --endpoint <local-mcp>` (capability audit including the Docker container that's behind the port) and `mcp-guard scan --config <attack.json>` (supply-chain check). Source `.tape` and longer cuts live in [`demo/`](demo/).

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
| Invariant/Snyk mcp-scan (live SSE, requires `SNYK_TOKEN`) | 4 | 8 | 20 | 16.7% | 33.3% |
| mcp-guard (source path) | 23 | 0 | 1 | 95.8% | 100% |
| mcp-guard-endpoint (live SSE + HTTP probe) | 15 | 0 | 9 | 62.5% | 100% |
| **mcp-guard combined (source ∪ endpoint)** | **24** | **0** | **0** | **100%** | **100%** |

The single source-only FN is `authless_endpoint` on `vuln-authless` — a runtime property no static scan can reach. The live endpoint stage closes it. `expected_false_positives` are documented per-server in [`runner/expected-findings.json`](runner/expected-findings.json) (e.g., FastMCP's unenforced auth defaults are tolerated for normal servers).

The TypeScript lab servers (`vuln-network`, `vuln-allowlist-bypass`) ship an older `SSEServerTransport` that the current MCP Python client and Cisco scanner cannot list tools from. The endpoint stage falls back to HTTP probes for them; vuln-hidden-transport is fully covered that way.

## Unknown-Lab (blind test on real releases)

A second corpus that scans unmodified upstream releases without pre-labelled expected findings — Flowise 3.1.0 / 3.0.13 (npm) and Upsonic 0.72.0 / 0.71.6 (PyPI). It has two modes: source scans of the shipped packages, and config-mode scans of honest MCP configs rendered from the Flowise Custom MCP docs and Upsonic MCPHandler/MultiMCPHandler docs. Live endpoint scanning is not applicable because Flowise is an MCP host/client and Upsonic is an MCP client SDK in these releases. Bring up the source fixtures with `bash lab/unknown/fetch.sh` before invoking the runner.

| Package | mcp-guard verdict | mcp-guard findings | MCPScan rules |
|---|---|---|---|
| flowise-3.0.13 | BLOCK | command_exec, unrestricted_file_read | — (Python rules don't fire on JS) |
| flowise-3.1.0 | BLOCK | command_exec, unrestricted_file_read | — |
| upsonic-0.71.6 | BLOCK | 7 patterns | 60 hits across 2 rules |
| upsonic-0.72.0 | BLOCK | 7 patterns | 64 hits across 2 rules |

Config-mode fixtures cover two categories: **sanitizer_bypass** (5 patterns from CVE-2026-40933 / CVE-2026-30625 — `npx -c curl`, `python -c "import os; ..."`, `node -e "require('child_process')..."`, `git -c core.pager=...`, `uvx --from <evil>`) and **honest_baseline** (5 docs-recommended configs).

| Category | mcp-guard | Cisco config (yara) | Invariant/Snyk config |
|---|---|---|---|
| sanitizer_bypass (5) | 5/5 BLOCK ✅ | 0/5 — | 0/5 — |
| honest_baseline (5) | 4/5 BLOCK (FP) | 0/5 — | 1–2/5 (FP) |

mcp-guard is the only scanner that catches the CVE-grade sanitizer bypasses, but its config-mode policy is too coarse — it also flags 4 of 5 honest baselines (any local stdio command in mcp.json gets `allowlist_bypass`/`config_to_execution`). cisco-yara and Invariant/Snyk both let the bypass patterns through.

Two observations from the blind run:

1. **Zero version-pair delta.** Both scanners produce identical output for the older and newer release of each package. Whatever security fix landed between 3.0.13→3.1.0 / 0.71.6→0.72.0, neither tool's coarse pattern-set surfaces it.
2. **Zero scanner overlap.** mcp-guard and MCPScan have completely disjoint taxonomies (`command_exec` / `unrestricted_file_read` vs `detect-command-execution` / `detect-hardcoded-secrets-py`) — they're complementary rather than redundant.

Full source/config tables + version-pair deltas + scanner overlap matrix in [`results/report/unknown-lab.md`](results/report/unknown-lab.md).

## Threat Models

`mcp-guard`, `cisco-mcp-scanner`, and Invariant/Snyk `mcp-scan` are complementary, not redundant — see [docs/threat-models.md](docs/threat-models.md) for the full discussion.

| | **mcp-guard** | **cisco-mcp-scanner (yara)** | **Invariant/Snyk mcp-scan** |
|---|---|---|---|
| Looks for | Capability gaps (authless, unrestricted file/env, allowlist bypass, hidden admin, runtime-only) | Malicious-intent payloads in tool descriptions/code | Manipulative tool descriptions (LLM-classified) |
| Operational model | Local CLI, fully offline | Local CLI, offline yara | Local CLI → `api.snyk.io` (requires `SNYK_TOKEN`) |
| Use case | Audit your own MCP before deploy | Vet a third-party MCP before install | Same — supply-chain check, cloud LLM analyser |
| Lab recall | 100 % combined | 4.2 % (capability lab is outside cisco-yara's scope) | 16.7 % (description-only signal) |

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


## Install

There are three ways to use this repo, in increasing order of involvement:

### 1. Pip wheel (fastest, recommended for the CLI)

```bash
# Latest tagged release wheel
pip install https://github.com/windshock/mcpscan/releases/latest/download/mcp_guard-0.2.4-py3-none-any.whl

# With cisco supply-chain detection (yara offline; behavioral/llm need MCP_SCANNER_LLM_API_KEY)
pip install 'https://github.com/windshock/mcpscan/releases/latest/download/mcp_guard-0.2.4-py3-none-any.whl[cisco]'

mcp-guard scan --path ./your-mcp-server
mcp-guard scan --config ./mcp.json --with-cisco
mcp-guard scan --endpoint http://localhost:3000/sse
```

Requires Python ≥ 3.10.

### 2. Distribution Docker image (zero Python setup)

```bash
docker run --rm -v "$PWD:/scan" \
  ghcr.io/windshock/mcp-guard:latest \
  scan --path /scan/your-mcp-server
```

The image at `ghcr.io/windshock/mcp-guard` ships with cisco-mcp-scanner preinstalled (~360 MiB). Set `MCP_SCANNER_LLM_API_KEY` to enable cisco's behavioral/llm analyzers.

### 3. Full lab benchmark (this repo)

For evaluating multiple scanners side by side on the 11-server vulnerability lab — the workflow this repo was built around.

```bash
# Start the lab in the background
docker compose up --build -d

# Run the lab benchmark and generate results/report
docker compose run --rm runner

# Run OX live validation from the host
python3 runner/run_ox_live.py

# Or run OX live validation from the isolated Docker profile
docker compose --profile ox-live run --rm ox-live-runner

# Run mcp-guard standalone (lab image, editable install)
docker compose run --rm mcp-guard scan --path /servers/vuln-exec

# Open MCP Inspector
open http://localhost:6274

# View results
ls results/report/

# Stop the lab when finished
docker compose down
```

`runner/run-scans.sh` is a container-internal entrypoint. Do not run it directly from the host shell; use `docker compose run --rm runner`.

## Recommended Workflow

```bash
# 1) Bring up the local MCP lab
docker compose up --build -d

# 2) (Optional) fetch unknown-lab fixtures (Flowise + Upsonic real releases)
bash lab/unknown/fetch.sh

# 3) Produce raw + normalized benchmark results
docker compose run --rm runner

# 4) Produce OX live validation results
python3 runner/run_ox_live.py

# 5) Review the generated reports
ls results/report/
```

## Local Unit Tests

```bash
PYTHONPATH=guard:. python3 -m unittest \
  guard.tests.test_discovery \
  guard.tests.test_scanner \
  guard.tests.test_cli \
  guard.tests.test_endpoint_integration \
  runner.tests.test_reporting \
  runner.tests.test_ox_live
```

`test_endpoint_integration` stands up a local HTTP server and a real FastMCP server in subprocesses to exercise probe / scan / CLI paths end-to-end without docker.

## Docker Disk Recovery

If Docker stops mid-run with `no space left on device`, check and reclaim space before retrying:

```bash
docker system df
docker builder prune -f
docker system prune -f
```

If image/volume pressure is still high, stop the lab first:

```bash
docker compose down
docker volume prune -f
```

## Architecture

### Normal Servers (FP Baseline)
| Server | Port | Description |
|--------|------|-------------|
| normal-strict | 3001 | Cleanest possible — auth ✓, allowlist ✓, no dangerous tools |
| normal-realistic | 3002 | Business tools with strict limits — file read restricted to /data/ |
| normal-tricky | 3003 | FP trap — looks dangerous but is actually safe |

### Vulnerable Servers
| Server | Port | Pattern |
|--------|------|---------|
| vuln-exec | 3101 | Direct command execution + tool poisoning |
| vuln-authless | 3102 | No authentication + tool poisoning |
| vuln-filesystem | 3103 | Unrestricted file read/write + env exposure |
| vuln-config-exec | 3104 | Config-to-execution escalation |
| vuln-runtime-only | 3105 | Static-safe, runtime-dangerous |
| vuln-network | 3201 | SSRF + CORS * + debug info |
| vuln-allowlist-bypass | 3202 | Allowlist on name, args unvalidated |
| vuln-hidden-transport | 3203 | Clean UI, hidden transport endpoints |

### Exposure Simulation
| Component | Port | Description |
|-----------|------|-------------|
| proxy-public | 8080 | Public MCP endpoint (no auth, CORS *) |
| proxy-internal | 8081 | Internal MCP endpoint (auth, strict CORS) |
| config-elevator | 3301 | AI-mediated config injection simulation |

## mcp-guard CLI

```bash
# Scan a local server directory
mcp-guard scan --path ./servers/vuln-exec

# Scan an MCP config JSON
mcp-guard scan --config ./mcp.json

# Scan for development environment
mcp-guard scan --path ./servers/vuln-exec --env development

# JSON output
mcp-guard scan --path ./servers/vuln-exec --output json

# View pattern catalog
mcp-guard catalog

# View policy rules
mcp-guard policy --show
```

### Policy Verdicts
- **ALLOW**: No security concerns
- **CONDITIONAL**: Acceptable with restrictions (sandbox, masking, internal-only)
- **BLOCK**: Dangerous — must not be used without remediation

## Deliverables
1. **MCP Security Pattern Catalog** — 13 vulnerability patterns with indicators and recommendations
2. **MCP Scanner Benchmark** — Compare MCPScan, Cisco mcp-scanner, Invariant/Snyk mcp-scan, and mcp-guard (TP/FP/FN/TN)
3. **mcp-guard** — Policy-based guardrail CLI for developers
4. **OX Live Validation** — Launch official products where possible, record blockers where not, and store normalized live results

## Project Structure
```
mcpscan/
├── docker-compose.yml
├── .env
├── integrations/ox/  # OX product manifests for live validation
├── servers/          # 11 MCP servers (3 normal + 8 vulnerable)
├── exposure/         # 3 exposure simulations
├── scanners/         # 4 scanner containers (mcpscan, cisco, invariant, inspector)
├── lab/unknown/      # Blind-test fixture (Flowise / Upsonic real releases)
├── guard/            # mcp-guard tool
├── runner/           # Scan runners + report generators
└── results/          # Raw + normalized + report output
```
