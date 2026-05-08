"""Generate normalized reports from raw lab and OX live outputs."""
from __future__ import annotations

import os
from pathlib import Path

from reporting import (
    generate_cisco_config_outputs,
    generate_invariant_config_outputs,
    generate_lab_outputs,
    generate_ox_live_outputs,
    generate_unknown_lab_outputs,
)


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RESULTS_DIR = SCRIPT_DIR.parent / "results" if (SCRIPT_DIR.parent / "results").exists() else Path("/results")
RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", str(DEFAULT_RESULTS_DIR)))
LAB_EXPECTED_FILE = Path(os.environ.get("LAB_EXPECTED_FILE", str(SCRIPT_DIR / "expected-findings.json")))
OX_EXPECTED_FILE = Path(os.environ.get("OX_EXPECTED_FILE", str(SCRIPT_DIR / "ox-live-expected.json")))


def _resolve_ox_research_fixture() -> Path:
    env_override = os.environ.get("OX_RESEARCH_FIXTURE", "").strip()
    candidates = [
        Path(env_override) if env_override else None,
        SCRIPT_DIR / "ox_research_cases.json",
        Path("/app/ox_research_cases.json"),
        SCRIPT_DIR.parent / "guard" / "tests" / "fixtures" / "ox_research_cases.json",
    ]
    for path in candidates:
        if path and path.is_file():
            return path
    return SCRIPT_DIR / "ox_research_cases.json"


def main() -> None:
    lab_results = generate_lab_outputs(RESULTS_DIR, LAB_EXPECTED_FILE)
    ox_results = generate_ox_live_outputs(RESULTS_DIR, OX_EXPECTED_FILE)
    fixture_file = _resolve_ox_research_fixture()
    cisco_config_results = generate_cisco_config_outputs(RESULTS_DIR, fixture_file)
    invariant_config_results = generate_invariant_config_outputs(RESULTS_DIR, fixture_file)
    unknown_lab_results = generate_unknown_lab_outputs(RESULTS_DIR)

    print(f"Generated {len(lab_results)} lab normalized results")
    if ox_results:
        print(f"Generated {len(ox_results)} OX live normalized results")
    if cisco_config_results:
        print(f"Generated {len(cisco_config_results)} cisco supply-chain results")
    if invariant_config_results:
        print(f"Generated {len(invariant_config_results)} invariant supply-chain results")
    if unknown_lab_results:
        print(f"Generated {len(unknown_lab_results)} unknown-lab normalized results")
    print(f"Reports saved to {RESULTS_DIR / 'report'}")


if __name__ == "__main__":
    main()
