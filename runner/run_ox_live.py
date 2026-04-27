#!/usr/bin/env python3
"""Run OX product live validation and generate reports."""
from __future__ import annotations

import argparse
from pathlib import Path

from ox_live import (
    DEFAULT_FIXTURE_FILE,
    DEFAULT_PRODUCTS_DIR,
    DEFAULT_RESULTS_DIR,
    filter_manifests,
    load_fixture_cases,
    load_product_manifests,
    run_product,
)
from reporting import generate_ox_live_outputs


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OX live validation against official products.")
    parser.add_argument("--products-dir", default=str(DEFAULT_PRODUCTS_DIR), help="Directory containing product manifests")
    parser.add_argument("--fixture-file", default=str(DEFAULT_FIXTURE_FILE), help="OX fixture corpus JSON path")
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR), help="Results output directory")
    parser.add_argument("--expected-file", default="runner/ox-live-expected.json", help="OX live expected findings JSON path")
    parser.add_argument(
        "--product",
        action="append",
        dest="products",
        help="Specific product id to run. Can be provided multiple times.",
    )
    parser.add_argument("--keep-workdirs", action="store_true", help="Keep cloned repo work directories for debugging")
    args = parser.parse_args()

    products_dir = Path(args.products_dir)
    fixture_file = Path(args.fixture_file)
    results_dir = Path(args.results_dir)
    expected_file = Path(args.expected_file)

    manifests = load_product_manifests(products_dir)
    selected = set(args.products or [])
    manifests = filter_manifests(manifests, selected)
    fixture_cases = load_fixture_cases(fixture_file)

    for manifest in manifests:
        print(f">>> Running OX live validation for {manifest['id']}")
        run_product(
            manifest,
            fixture_cases=fixture_cases,
            results_dir=results_dir,
            keep_workdir=args.keep_workdirs,
        )

    normalized = generate_ox_live_outputs(results_dir, expected_file)
    print(f"Generated {len(normalized)} normalized OX live results")
    print(f"Report saved to {results_dir / 'report' / 'ox-live.md'}")


if __name__ == "__main__":
    main()
