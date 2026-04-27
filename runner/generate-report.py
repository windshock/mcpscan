"""Generate normalized reports from raw lab and OX live outputs."""
from __future__ import annotations

import os
from pathlib import Path

from reporting import generate_lab_outputs, generate_ox_live_outputs


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_RESULTS_DIR = SCRIPT_DIR.parent / "results" if (SCRIPT_DIR.parent / "results").exists() else Path("/results")
RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", str(DEFAULT_RESULTS_DIR)))
LAB_EXPECTED_FILE = Path(os.environ.get("LAB_EXPECTED_FILE", str(SCRIPT_DIR / "expected-findings.json")))
OX_EXPECTED_FILE = Path(os.environ.get("OX_EXPECTED_FILE", str(SCRIPT_DIR / "ox-live-expected.json")))


def main() -> None:
    lab_results = generate_lab_outputs(RESULTS_DIR, LAB_EXPECTED_FILE)
    ox_results = generate_ox_live_outputs(RESULTS_DIR, OX_EXPECTED_FILE)

    print(f"Generated {len(lab_results)} lab normalized results")
    if ox_results:
        print(f"Generated {len(ox_results)} OX live normalized results")
    print(f"Reports saved to {RESULTS_DIR / 'report'}")


if __name__ == "__main__":
    main()
