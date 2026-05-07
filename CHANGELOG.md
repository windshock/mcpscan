# Changelog

All notable user-facing changes to `mcp-guard`. Earlier versions only had a single bootstrapping commit; semantic-version history starts at v0.1.0.

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
