# MCP Security Lab & Guardrail Tool

Docker-based evaluation lab for MCP security scanners, plus a policy-based guardrail tool (`mcp-guard`).

## Next Agent Handoff

This project is not complete yet. Continue from [docs/COMPLETION_PLAN.md](docs/COMPLETION_PLAN.md) before implementing changes.

## Quick Start

```bash
# Start the lab in the background
docker compose up --build -d

# Run the lab benchmark and generate results/report
docker compose run --rm runner

# Run OX live validation from the host
python3 runner/run_ox_live.py

# Or run OX live validation from the isolated Docker profile
docker compose --profile ox-live run --rm ox-live-runner

# Run mcp-guard standalone
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

# 2) Produce raw + normalized benchmark results
docker compose run --rm runner

# 3) Produce OX live validation results
python3 runner/run_ox_live.py

# 4) Review the generated reports
ls results/report/
```

## Local Unit Tests

```bash
PYTHONPATH=guard:. python3 -m unittest \
  guard.tests.test_discovery \
  guard.tests.test_scanner \
  guard.tests.test_cli \
  runner.tests.test_reporting \
  runner.tests.test_ox_live
```

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
2. **MCP Scanner Benchmark** — Compare MCPScan, Cisco mcp-scanner, and mcp-guard (TP/FP/FN/TN)
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
├── scanners/         # 3 scanner containers
├── guard/            # mcp-guard tool
├── runner/           # Scan runners + report generators
└── results/          # Raw + normalized + report output
```
