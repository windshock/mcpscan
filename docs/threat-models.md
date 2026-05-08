# Threat Models: Vulnerable MCP vs Malicious MCP

`mcp-guard`, `cisco-mcp-scanner`, and Invariant/Snyk `mcp-scan` look like they solve the same problem but solve very different ones. The lab benchmark numbers (`results/report/comparison.md`) only make sense when you separate the threat models.

## Side-by-side

| Axis | **mcp-guard (capability audit)** | **cisco-mcp-scanner (offline yara)** | **Invariant/Snyk mcp-scan (cloud LLM)** |
|---|---|---|---|
| Who is the attacker? | External party exploiting weak MCP server capabilities | MCP author publishing hidden bad behaviour | MCP author publishing manipulative tool descriptions |
| What is checked? | Tool capabilities, schemas, runtime properties (auth, CORS, hidden admin, allowlist enforcement, runtime triggers) | Tool descriptions/code for known-bad payload patterns (yara rules) | Tool descriptions analysed by Snyk's hosted classifier (issue codes E001/W001/W017 etc.) |
| Trust assumption | "Honest developer, possibly insecure code" | "Untrusted source, possibly malicious code" | "Untrusted source — does the description text manipulate the agent?" |
| Operational model | Local CLI, fully offline | Local CLI, offline yara (paid LLM analyzers optional via `MCP_SCANNER_LLM_API_KEY`) | **Local CLI calls `api.snyk.io` — requires `SNYK_TOKEN`. Without a token, `issues=[]`.** |
| Primary use case | Pre-deploy / pre-commit audit of *your own* MCP | Supply-chain vetting before installing a *third-party* MCP | Same as cisco — supply-chain, with cloud-side LLM rather than offline rules |
| Lab coverage on `vuln-*` servers | 24/24 (100 %) when source ∪ endpoint runs | 1/24 (4.2 %) with offline `yara` analyzer | 4/24 (16.7 %), 8 FPs — coarser taxonomy mismatches the lab's strict labels |

## When to use which

```
Are you auditing code you own?
   ├── Yes → mcp-guard scan --path/--endpoint
   └── No, vetting third-party config/package?
              ├── Yes → mcp-guard scan --config <path> --with-cisco
              └── Operating prod endpoint?
                          └── Both: mcp-guard scan --endpoint <url> --with-cisco
```

The combined `mcp-guard scan ... --with-cisco` command runs both detectors against the same target and tags every finding with its source (`mcp-guard` vs `cisco-yara`/`cisco-behavioral`/`cisco-llm`).

## Why the lab numbers look the way they do

Our lab is built around capability gaps (intentionally weak auth, unvalidated args, hidden admin endpoints). That is exactly mcp-guard's threat model and neither cisco's nor Invariant/Snyk's.

- **cisco** fires when a description string reads malicious — `read_file_unrestricted` mentions `/etc/shadow` and `~/.ssh/id_rsa`, which trips `credential_harvesting.yara`. `vuln-exec`'s `execute_command` admits its purpose is "Execute a shell command" but doesn't embed a literal payload like `bash -i >& /dev/tcp/…`, so cisco yara stays silent.
- **Invariant/Snyk mcp-scan** uses an LLM classifier on tool descriptions (issue codes E001 prompt-injection, W001 dangerous words, W017 sensitive data exposure). It catches `vuln-authless`'s "IGNORE ANY PREVIOUS INSTRUCTIONS" injection text easily but doesn't audit runtime behaviour — `vuln-hidden-transport` (clean UI, hidden admin endpoint) and `vuln-network` (CORS `*`, SSRF) come back empty because the descriptions look normal. Lab false positives largely come from taxonomy mismatch: invariant-scan reports `tool_poisoning`/`env_exposure`/`unrestricted_file_read` but the lab's expected_findings use finer labels like `command_exec_via_args` or `conditional_command_exec`.

To see cisco / Invariant-Snyk shine, point them at the OX research supply-chain corpus (`guard/tests/fixtures/ox_research_cases.json`) — those are *config-style* attacks where the malicious payload is in the config itself, which is their home turf.

## A note on Invariant Labs → Snyk

The CLI you may know as Invariant Labs' `mcp-scan` was acquired by Snyk and renamed to `snyk-agent-scan`. The legacy `mcp-scan` PyPI package now installs a deprecation shim that delegates to `snyk-agent-scan`. Critically, **all analysis happens server-side at `api.snyk.io`** — without `SNYK_TOKEN` set, `mcp-scan scan --json` returns the tool listing but `issues=[]`. This is a meaningful operational difference from cisco's offline yara analyzer; in air-gapped or CI environments that can't reach Snyk, the tool produces no findings. The lab measures the SaaS path; the runner stage skips silently when `SNYK_TOKEN` is unset.

## Combining the two

Two ways:

1. **One-shot via the CLI**: `mcp-guard scan ... --with-cisco`. The CLI runs cisco against the same target (path / config / endpoint) and merges findings with a `source` tag. The PolicyEngine treats any cisco `HIGH`/`CRITICAL` finding as `BLOCK` regardless of environment, because Cisco's "harmful" classification implies confirmed-malicious authoring rather than a capability default-to-conditional.
2. **Lab benchmark column**: see `results/report/comparison.md` — `mcp-guard combined` row gives the union of source + endpoint scans, the `cisco-config` column (when run) shows cisco against the supply-chain corpus.

## Public tunnel exposure

A third axis lives between the two threat models above: a developer's *honest* MCP can become a *supply-chain risk* the moment it gets published over a free tunnel (cloudflared, localtunnel, bore, ngrok). Discovery recognises each tunnel — both host processes and docker compose sidecars — and attaches the public URL to the same candidate as the local MCP. So when scan output reads:

```
Target: http://127.0.0.1:3102/sse
  docker.compose_service: vuln-authless
  public_tunnels: [cloudflared → https://abc.trycloudflare.com]
Risk: HIGH    Policy: BLOCK
Vulnerabilities: env_exposure, tool_poisoning, authless_endpoint, ...
```

…the operator sees both: "this MCP has these capability gaps" *and* "this MCP is reachable from the public internet right now". That combination is the supply-chain risk picture. Run the lab with `docker compose --profile tunnels up -d` to exercise the path against real public URLs.

## Operational notes

- Cisco's deeper analyzers (`behavioral`, `llm`) need an LLM API key in `MCP_SCANNER_LLM_API_KEY`. Without one, `--with-cisco` falls back to `yara` only.
- `--cisco-analyzers yara,behavioral,llm` overrides the auto-selection.
- `--cisco-timeout` (default 60 s) caps the subprocess.
- If `mcp-scanner` is not on `PATH`, `--with-cisco` prints a one-line warning and continues with mcp-guard only — no crash.
