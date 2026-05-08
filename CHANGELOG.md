# Changelog

All notable user-facing changes to `mcp-guard`. Earlier versions only had a single bootstrapping commit; semantic-version history starts at v0.1.0.

## v0.2.5 — 2026-05-08

- Lab: added Invariant/Snyk `mcp-scan` (legacy `mcp-scan` PyPI package now redirects to `snyk-agent-scan`) as a third external scanner. Two new stages in `runner/run-scans.sh` — live SSE mode against the 11 lab servers, and config mode against the OX research supply-chain corpus. Both stages require `SNYK_TOKEN` (loaded from `.env`); without it the runner records `skipped` results so the report shows the dependency explicitly instead of silent zeros.
- `runner/reporting.py`: new `INVARIANT_ISSUE_MAP` (E001/W001/W017/etc. → lab vuln_type), `normalize_invariant`, `generate_invariant_config_outputs`, and `invariant-supply-chain.md` aggregate report. Comparison table now lists invariant-scan alongside cisco/mcp-guard.
- Docs: `docs/threat-models.md` rewritten as a 3-column table (mcp-guard / cisco / invariant-snyk) with an explicit note about `api.snyk.io` dependency and air-gapped behaviour. Snapshot benchmark numbers in README: invariant-scan = 4 TP / 8 FP / 20 FN against the lab's 24 expected findings (recall 16.7 %, precision 33.3 %).
- New unknown-lab corpus: `lab/unknown/fetch.sh` downloads Flowise 3.1.0/3.0.13 (npm) and Upsonic 0.72.0/0.71.6 (PyPI) — real production releases without pre-labelled expected_findings, mounted at `/unknown` in the runner. Source stage (`unknown-mcp-guard`, `unknown-mcpscan`) feeds `results/report/unknown-lab.md` with per-package findings, version-pair deltas, and scanner overlap. Two observations from the source pass: (a) zero version-pair delta — `diff -u upsonic-0.71.6/src/upsonic/tools/mcp.py upsonic-0.72.0/src/upsonic/tools/mcp.py` shows only a new `_emit_mcp_security_warning()` console print, `prepare_command()` body is byte-identical, so zero scanner delta is the correct ground truth, not a scanner-resolution problem; (b) zero scanner overlap — mcp-guard and MCPScan have completely disjoint taxonomies. `lab/unknown/CVE-NOTES.md` documents the verified attack surface, including the `shutil.which()` short-circuit at line 129 that makes Upsonic's `ALLOWED_COMMANDS` allowlist mostly decorative for any binary on PATH.
- Unknown-lab also runs config-mode (`unknown-mcp-guard-config`, `unknown-cisco-config`, `unknown-invariant-config`) over 10 fixtures in `lab/unknown/configs/` split into two categories: `sanitizer_bypass` (5 patterns from CVE-2026-40933 / CVE-2026-30625 — `npx -c`, `python -c`, `node -e`, `git -c core.pager=`, `uvx --from`) and `honest_baseline` (5 docs-recommended configs from upstream Flowise/Upsonic docs). Result: mcp-guard catches 5/5 sanitizer_bypass but flags 4/5 honest baselines as well (config-mode policy too coarse to distinguish runtime-arg-interpretation patterns from honest stdio configs). cisco-yara and Invariant/Snyk catch 0/5 bypass. Live-launch is left for a future tier — Flowise/Upsonic are MCP host/client only, no SSE endpoint to probe; the bypass would need a running Flowise canvas instance accepting submitted MCP configs.

## v0.2.4 — 2026-05-07

- `mcp-guard scan --endpoint <local>` now surfaces `public_tunnels` in the target metadata when a docker tunnel container forwards to that local port. Direct endpoint scans are now consistent with `discover` / `--auto-all` for tunnel exposure.

## v0.2.3 — 2026-05-07

- Discovery: detect `localtunnel` (`*.loca.lt`) and `bore` (`tcp://bore.pub:<port>`) as host processes.
- Discovery: detect cloudflared / localtunnel / bore tunnel containers via `docker logs`; rewrite the container's internal upstream (e.g. `http://vuln-authless:8000`) to the host-mapped form (`http://127.0.0.1:3102`) so the tunnel link attaches to the existing docker MCP candidate.
- Lab: `docker compose --profile tunnels up -d` brings up cloudflared, localtunnel, and bore sidecars. ngrok intentionally omitted (now requires authtoken).

## v0.2.2 — 2026-05-07

- Lab: TS server `POST /messages` handlers were empty, so the SSE handshake never completed and `mcp-guard scan --endpoint` against vuln-network / vuln-allowlist-bypass / vuln-hidden-transport reported `Connection closed` and (incorrectly) ALLOW. Each handler now tracks transports by sessionId and routes via `transport.handlePostMessage`.
- Scanner: `_list_tools_via_mcp` falls back to streamable-http transport (`<base>/mcp`, `<base>`) when SSE listing fails. The probe summary records the transport actually used (`sse` vs `streamable_http`).

## v0.2.1 — 2026-05-07

- Discovery now excludes `/opt`, `/Applications`, `/Library/{Frameworks,Caches,Application Support}`, `/Volumes`, `.windsurf`, `.cursor`, `.vscode`, `node_modules`, `site-packages`, `dist-info`, `__pycache__`, `.venv`, build/, dist/. Also requires an MCP-specific marker (`mcp.json` / FastMCP / modelcontextprotocol import) — bare `package.json` / `Dockerfile` no longer qualifies. End result: `/opt/homebrew`, `/Applications/Windsurf.app`, IDE plugin ports, etc. are no longer reported as candidates.
- `hidden_transport` only fires when the response body actually contains MCP keywords (`stdio`, `transport`, `connector`, `applied`). 403 CSRF / generic HTML on `/api/*` no longer trips the finding.
- Endpoint findings that fire purely from a tool's JSON schema (e.g. "this tool has a `path` parameter") emit `confidence: low` and the PolicyEngine demotes BLOCK → CONDITIONAL. Server-side validation isn't visible from an endpoint, so these stay as "operator should verify" instead of "must remediate".
- New pattern `unrestricted_directory_listing` (PAT-022, MEDIUM) for `list_*`/`dir_*`/`scan_*` tools — no longer misclassified as `unrestricted_file_read`.
- Per-tool `(pattern_id, tool_name)` dedupe drops noise when one tool fires the same pattern via name AND parameter.

## v0.2.0 — 2026-05-04

- `-v` / `-vv` / `-q` log levels on the scan subcommand; logs go to stderr so JSON output stays pipeable.
- New `Target details` block in both text and JSON: for `--endpoint`, the listening process (PID + command via `lsof`) and Docker container info (name, image, compose project/service/working_dir); for `--path`, resolved abs path + file count by extension + git remote+commit; for `--config`, file path or inline-JSON marker plus `mcpServers` preview.
- New `--auto-all` flag scans every discovered candidate (one section per target). Exit 1 if any target evaluates to BLOCK.

## v0.1.0 — 2026-05-03

- Initial release. Core CLI (`scan --path/--config/--endpoint/--auto`), pattern catalog, PolicyEngine, lab benchmark.
- Optional `--with-cisco` flag fuses cisco-mcp-scanner findings under the same source-tagged result; PolicyEngine escalates HIGH/CRITICAL cisco findings to BLOCK.
- Distribution via wheel attached to GitHub Release + GHCR docker image (`ghcr.io/windshock/mcp-guard`).
