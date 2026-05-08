# Unknown-lab runtime tests

Static scanners look at the JSON in `lab/unknown/configs/` and pattern-
match on suspicious command/arg shapes. **Runtime tests do something
different**: they import the target package's actual sanitizer / launcher
and feed each fixture into it, recording whether the function `ACCEPTED`
or `REJECTED` the payload. That's the only way to confirm a static-pattern
hit corresponds to a real sanitizer bypass — and to discover the inverse
case where the static scan flagged a payload that the sanitizer would have
caught.

## Why per-CVE PoC projects, not a runner stage

Runtime testing of MCP clients is **per-package work**: every framework
(Upsonic Python, Flowise TS, the next one) has its own sanitizer location,
language, import semantics, and sandbox needs. Bolting another bespoke
stage onto `runner/run-scans.sh` for each new CVE would balloon the
scanner core. So each runtime PoC lives in a self-contained subdirectory
following the [`oh-my-secuaudit / security-testing-as-code`](https://github.com/windshock/oh-my-secuaudit/tree/main/skills/methodology/security-testing-as-code)
skill structure: `exploit.*`, `README.md`, `Dockerfile`, `evidence/`,
`finding.json`. PoCs are runnable directly without invoking the runner.

## Current PoCs

| Directory | CVE | Target | Verdict |
|---|---|---|---|
| [`upsonic-cve-2026-30625/`](upsonic-cve-2026-30625/) | CVE-2026-30625 | `upsonic.tools.mcp.prepare_command` | 6/6 sanitizer_bypass fixtures ACCEPTED |

To add Flowise CVE-2026-40933, port the sanitizer extraction to a Node
harness against the Flowise canvas's MCP-add validator (TypeScript). Same
project structure, different language toolchain.

## Running a PoC

Each subdirectory's `README.md` documents reproduction. Quick local form
for the Upsonic PoC:

```bash
bash lab/unknown/fetch.sh
python3 lab/unknown/runtime/upsonic-cve-2026-30625/exploit.py
```

JSON output for diff-friendly capture:

```bash
python3 lab/unknown/runtime/upsonic-cve-2026-30625/exploit.py --json
```

Sandbox via the included Dockerfile:

```bash
docker build -t upsonic-cve-2026-30625 lab/unknown/runtime/upsonic-cve-2026-30625
docker run --rm --network=none \
    -v "$PWD/lab/unknown:/lab/unknown:ro" \
    upsonic-cve-2026-30625
```

## Relationship to the static scan results

| Layer | What it produces | Where |
|---|---|---|
| Static config scan (mcp-guard --config + cisco config + invariant) | "Did each scanner flag the suspicious-looking JSON?" | `results/report/unknown-lab.md` |
| Runtime PoC (here) | "Does the actual package sanitizer let the payload through?" | `lab/unknown/runtime/<cve>/evidence/run.txt` |

The two answers are independent. mcp-guard's BLOCK on `flowise-bypass-npx-c.json`
plus this PoC's ACCEPTED on the same fixture together establish: the JSON
*is* dangerous, mcp-guard catches it, and Upsonic's sanitizer does not.
