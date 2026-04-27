# MCP-Based AI Supply Chain Risks and `mcp-guard` Operator Guide

This document is written to answer four practical questions.

- Why do MCP-based AI tools create supply chain risk instead of just ordinary app risk?
- How do real-world exposure and execution paths form in practice?
- What can this repository and `mcp-guard` actually validate?
- What should an engineer or security reviewer do first?

## 1. Executive Summary

MCP (Model Context Protocol) is useful as an integration layer between AI systems and external tools, but from a security perspective it should be treated as an execution path, not just as an API.

The core risk is:

`untrusted input -> MCP config or tool invocation -> local or server-side execution`

Once that path exists, the blast radius can include:

- command execution
- local file read/write
- internal service access
- secret exposure
- zero-click or near-zero-click execution through AI-suggested configuration changes

## 2. Why This Is Different From Traditional Vulnerabilities

| Category | Traditional bug class | MCP / AI execution-path risk |
| --- | --- | --- |
| Root cause | code defect | design and operating path |
| Security boundary | input validation failure | input promoted into executable configuration |
| User expectation | clearly sees "run command" | often sees "add integration" or "update config" |
| Operational scope | one app | IDE, agent, tunnel, connector, localhost, and server runtime |

MCP is not just a feature extension layer. If it is wired incorrectly, the connection path itself becomes the attack surface.

## 3. Common Attack Paths

### 3.1 Configuration-to-execution

This is the most common pattern.

- a malicious README or blog post provides an MCP snippet
- a UI accepts `command`, `args`, or `transport` directly
- an agent proposes a config change and a user approves it

Configuration data is then interpreted as a subprocess launch instruction.

### 3.2 Hidden backend paths

A tool list may look harmless while the server still exposes hidden management routes such as:

- `/api/transport`
- `/api/config`
- `/api/connectors`
- hidden stdio registration or backend transport paths

That means a visible UI alone is not enough to establish safety.

### 3.3 Exposure expansion

Even a local development server becomes externally relevant once it is combined with:

- ngrok
- Cloudflare Tunnel
- reverse proxies
- Docker published ports

Convenience exposure turns into a reachable attack surface.

### 3.4 AI-mediated change approval

This is where prompt injection and MCP risk intersect.

- an AI agent reads untrusted remote content
- the agent proposes MCP configuration changes
- the user treats the suggestion as trusted automation
- the result is a local execution-capable configuration

The attacker no longer needs to type the command directly.

## 4. High-Risk Environments To Review First

Prioritize environments such as:

- AI IDEs like Cursor, Windsurf, Claude, and Copilot
- orchestration stacks such as LangChain, LiteLLM, Flowise, and LangFlow
- internal agent platforms and connector UIs
- local MCP development servers
- Dockerized MCP servers
- test servers exposed through tunnels

## 5. What This Repository Does

This repository has two main roles.

### 5.1 MCP security lab

It keeps intentionally vulnerable and intentionally safe MCP servers side by side so scanners can be compared on true positives, false positives, and false negatives.

Representative patterns include:

- direct command execution
- authless endpoint
- unrestricted file read/write
- secret exposure
- SSRF
- allowlist bypass
- hidden transport
- config-to-execution
- AI-mediated config injection

### 5.2 `mcp-guard`

`mcp-guard` is a guardrail CLI that inspects MCP source trees, MCP config files, and live endpoints, then maps findings to a policy verdict.

The built-in verdicts are:

- `ALLOW`
- `CONDITIONAL`
- `BLOCK`

## 6. Scan Modes Supported By `mcp-guard`

### 6.1 Explicit scans

The user specifies the target directly.

```bash
mcp-guard scan --path ./servers/vuln-exec
mcp-guard scan --config ./mcp.json
mcp-guard scan --endpoint http://127.0.0.1:3101/sse
```

### 6.2 Auto-discovery scans

On macOS, the tool can discover likely candidates instead of requiring the user to type a path or port manually.

```bash
mcp-guard discover
mcp-guard discover --output json
mcp-guard scan
mcp-guard scan --auto
```

Discovery combines:

- host process and open-port inspection via `lsof` and `ps`
- Docker container, published-port, bind-mount, and Compose metadata inspection
- localhost endpoint probing
- ngrok public URL discovery
- cloudflared public URL discovery

### 6.3 Current auto-selection rule

`scan --auto` does not blindly choose the highest-scoring service anymore.

Automatic selection is limited to candidates with strong MCP evidence, for example:

- successful MCP tool listing
- code markers such as `fastmcp`, `modelcontextprotocol`, or `mcp.tool`
- `mcp.json`-style configuration files
- explicit MCP metadata in process or container context

This means a generic web service can still appear in discovery output, but it is excluded from automatic scanning unless it looks like a real MCP target.

## 7. What Changed For Docker and Tunnel Environments

Previously, the user had to enter ports or folders manually. The current workflow adds:

### 7.1 Docker support

- published ports become endpoint candidates
- bind mounts and Compose build contexts become host path candidates
- container name, service name, image, and derived host path are shown together

### 7.2 ngrok and Cloudflare Tunnel support

- the tool finds public tunnel URLs on the local machine
- it maps those URLs back to their localhost upstreams
- public URLs are shown as metadata, while the scanner prefers the local upstream whenever possible

This makes it easier to see both the exposed public surface and the underlying local execution target.

## 8. How Validation Was Strengthened

Validation in this repository now has two layers.

### 8.1 Lab-server regression coverage

The built-in safe and vulnerable lab servers continue to serve as regression targets.

### 8.2 Public-research fixture coverage

`guard/tests/fixtures/ox_research_cases.json` contains regression cases derived from the attack payload shapes discussed in public OX Security research.

Important clarification:

- this fixture corpus does not vendor the original third-party products
- it is intended to lock in recurring attack structures
- it specifically protects against regressions in patterns such as config-to-execution and allowlist bypass

## 9. How To Use The Tool As A Reader Or Operator

Recommended order of operations:

1. Run `mcp-guard discover` to inspect likely candidates on your Mac.
2. If Docker, ngrok, or cloudflared entries appear, compare the public URL and the local upstream.
3. If auto-selection is available, run `mcp-guard scan --auto`.
4. If auto-selection is unavailable, use discovery output to choose `--path`, `--config`, or `--endpoint` explicitly.
5. If the result is `BLOCK`, inspect the matched pattern and recommendation immediately.

## 10. Immediate Review Checklist

- Is there any externally reachable MCP endpoint?
- Is a Docker-published port exposing an MCP server?
- Is ngrok or Cloudflare Tunnel exposing a localhost MCP service?
- Does any `mcp.json` or MCP config use dangerous `command`, `args`, or `env` values?
- Do tool descriptions contain hidden instructions or poisoning text?
- Do localhost services perform sensitive actions without authentication?
- Is configuration change approval delegated to an AI suggestion flow?

## 11. What This Tool Does Not Guarantee

The tool is useful, but it is not magical.

- runtime-only backdoors can still evade static scanning
- private endpoints that require authentication may only yield partial analysis
- discovery output still benefits from human review in mixed localhost environments
- the public-research fixture corpus is a regression suite for attack structure, not a real-time statement about every upstream product today

## 12. Conclusion

The central question in MCP security is not "which AI tool are we using?" but "how much do we allow external input to become executable state?"

The discovery, Docker, and tunnel tracing features in `mcp-guard` exist to make that path visible earlier.

The operational decision rule is simple:

> Can external input become internal execution through configuration or tool invocation?

If the answer is `YES`, you are already in a high-risk zone.
