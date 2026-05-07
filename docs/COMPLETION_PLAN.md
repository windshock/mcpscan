# Completion Plan for Next Agent

Last inspected: 2026-04-27

This project is usable as a lab/demo, but it is not complete as a benchmark deliverable yet. Continue from this file before changing code.

## Current State

- Unit tests passed with:
  `PYTHONPATH=guard:. python3 -m unittest guard.tests.test_discovery guard.tests.test_scanner guard.tests.test_cli runner.tests.test_reporting runner.tests.test_ox_live`
- `docker compose config --quiet` passed.
- Existing reports are present:
  - `results/report/comparison.md`
  - `results/report/ox-live.md`
- Latest observed benchmark gaps:
  - `mcp-guard`: TP 13, FP 6, FN 11, recall 54.2%, precision 68.4%
  - `cisco-scanner`: 11/11 lab scans skipped
  - `mcpscan`: TP 0, FP 4, FN 24
  - OX live: 14 products scanned, 3 launch successes, 11 launch failures/blockers

## Completion Criteria

The project can be considered complete when:

- `mcp-guard` detects the expected lab patterns with no false positives on `normal-strict`, `normal-realistic`, and `normal-tricky`.
- The benchmark includes a real Cisco scanner run path instead of placeholder skipped results.
- Runtime and endpoint checks are included for patterns that source scanning cannot reliably detect, especially authless endpoints, CORS, runtime-only behavior, and hidden transport endpoints.
- OX live validation separates expected manual blockers from fixable launch failures, and manifests are pinned to currently valid images/tags/refs.
- Generated artifacts, caches, logs, `.env`, and large temporary workdirs are excluded from the repo handoff.

## Work Plan

1. Improve `mcp-guard` detection alignment.
   - Compare `runner/expected-findings.json` against `results/normalized/*_mcp-guard.json`.
   - Add or refine pattern detection for:
     - `runtime_only_danger`
     - `conditional_command_exec`
     - `static_analysis_bypass`
     - `remote_config_loading`
     - `internal_metadata_exposure`
     - `connector_metadata_exposure`
     - `config_injection`
     - `excessive_permissions`
     - `command_exec_via_args`
   - Reduce false positives currently observed on:
     - `normal-realistic`: `unrestricted_file_read`
     - `vuln-network`: `env_exposure`
     - `vuln-runtime-only`: `command_exec`, `env_exposure`

2. Add runtime and endpoint benchmark coverage.
   - Extend the runner so source scan results and endpoint scan results can both be normalized.
   - Use the lab ports defined in `docker-compose.yml`.
   - Cover at minimum:
     - authless endpoint detection
     - CORS wildcard detection
     - hidden transport/config endpoints
     - runtime-only trigger behavior
   - Preserve raw evidence under `results/evidence/lab/`.

3. Replace Cisco scanner placeholders with real scans.
   - Stop treating Cisco as a source-path scanner.
   - Use whichever supported mode fits the lab best: remote endpoint, stdio, config, or static tool dump.
   - Keep skipped output only for targets that are genuinely impossible to scan, and include a precise reason.

4. Fix OX live validation quality.
   - Update invalid git refs/tags in product manifests.
   - Re-run after Docker disk cleanup if `no_space_left` appears.
   - Mark products without official self-hosted launch paths as expected manual blockers.
   - Keep scan fixture results separate from real launch/health success so the report does not imply a product launched when only static fixture scanning succeeded.

5. Clean repository handoff hygiene.
   - Add `.gitignore` for generated files and local artifacts.
   - Exclude at least:
     - `__pycache__/`
     - `*.pyc`
     - `*.log`
     - `results/workdir/`
     - `guard/mcp_guard.egg-info/`
     - `.env`
   - Add `.env.example` if environment variables are needed for reproducible runs.
   - Note that the current git root was observed as `/Users/1004276/Downloads`, not the `mcpscan` folder; fix repo boundaries before committing.

## Verification Commands

Run these before calling the work complete:

```bash
PYTHONPATH=guard:. python3 -m unittest \
  guard.tests.test_discovery \
  guard.tests.test_scanner \
  guard.tests.test_cli \
  guard.tests.test_cisco_bridge \
  guard.tests.test_endpoint_integration \
  guard.tests.test_target_info \
  runner.tests.test_reporting \
  runner.tests.test_ox_live

docker compose config --quiet
docker compose up --build -d
docker compose run --rm runner
python3 runner/run_ox_live.py
```

Then review:

```bash
sed -n '1,240p' results/report/comparison.md
sed -n '1,260p' results/report/ox-live.md
```

## Notes for the Next LLM Agent

- Do not start by refactoring. First make the benchmark results honest and reproducible.
- Keep raw scanner output and normalized result shape stable unless the report generator is updated in the same change.
- Treat `results/workdir/ox-live/` as generated state, not source.
- The most valuable first implementation task is closing the `mcp-guard` FP/FN gap because it is local, testable, and blocks credible reporting.
