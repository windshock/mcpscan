"""Shared report generation helpers for lab and OX live validation."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LAB_SCANNERS = ("mcpscan", "cisco-scanner", "mcp-guard")


def load_json(path: Path, default: Any = None) -> Any:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def load_json_payload(path: Path) -> tuple[Any | None, str | None]:
    try:
        raw_text = path.read_text()
    except FileNotFoundError:
        return None, f"missing raw result: {path.name}"
    except OSError as exc:
        return None, f"failed to read raw result {path.name}: {exc}"

    if not raw_text.strip():
        return None, f"empty raw result: {path.name}"

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return None, f"invalid JSON in {path.name}: {exc.msg}"

    return payload, None


def build_normalized(
    scanner: str,
    server_name: str,
    expected: dict,
    detected: list[str],
    policy_verdict: str | None = None,
    *,
    status: str = "success",
    error: str | None = None,
    notes: list[str] | None = None,
    evidence: dict[str, Any] | None = None,
    source_file: str | None = None,
    source_target: str | None = None,
    exit_code: int | None = None,
) -> dict[str, Any]:
    expected_findings = expected.get("expected_findings", [])
    expected_fp = expected.get("expected_false_positives", [])

    detected_set = set(detected)
    expected_set = set(expected_findings)

    true_positives = sorted(detected_set & expected_set)
    missed = sorted(expected_set - detected_set)
    false_positives = sorted(detected_set - expected_set - set(expected_fp))

    return {
        "target": server_name,
        "scanner_name": scanner,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "error": error,
        "expected_findings": expected_findings,
        "detected_findings": detected,
        "true_positives": true_positives,
        "missed_findings": missed,
        "false_positives": false_positives,
        "policy_verdict": policy_verdict,
        "notes": notes or [],
        "evidence": evidence or {},
        "source_file": source_file,
        "source_target": source_target,
        "exit_code": exit_code,
    }


def normalize_lab_result(
    scanner: str,
    raw: dict[str, Any],
    server_name: str,
    expected: dict,
    detected: list[str],
    policy_verdict: str | None = None,
) -> dict[str, Any]:
    raw_notes = raw.get("notes", [])
    if isinstance(raw_notes, str):
        notes = [raw_notes]
    elif isinstance(raw_notes, list):
        notes = [note for note in raw_notes if isinstance(note, str)]
    else:
        notes = [str(raw_notes)] if raw_notes else []

    evidence = raw.get("evidence", {})
    if not isinstance(evidence, dict):
        evidence = {}

    exit_code = raw.get("exit_code")
    if not isinstance(exit_code, int):
        exit_code = None

    return build_normalized(
        scanner,
        server_name,
        expected,
        detected,
        policy_verdict,
        status=str(raw.get("status", "success")),
        error=raw.get("error") or raw.get("reason"),
        notes=notes,
        evidence=evidence,
        source_file=str(raw.get("source_file")) if raw.get("source_file") else None,
        source_target=str(raw.get("target")) if raw.get("target") else None,
        exit_code=exit_code,
    )


def build_failed_lab_result(scanner: str, server_name: str, expected: dict, error: str, source_file: Path) -> dict[str, Any]:
    return build_normalized(
        scanner,
        server_name,
        expected,
        [],
        status="failed",
        error=error,
        notes=[error],
        evidence={},
        source_file=str(source_file),
    )


def normalize_mcpscan(raw: Any, server_name: str, expected: dict) -> dict[str, Any]:
    if isinstance(raw, list):
        findings = [
            result.get("rule_id", result.get("pattern", "unknown"))
            for result in raw
            if isinstance(result, dict)
        ]
        return build_normalized("mcpscan", server_name, expected, findings)

    if not isinstance(raw, dict):
        error = f"unexpected JSON type in mcpscan payload: {type(raw).__name__}"
        return build_normalized(
            "mcpscan",
            server_name,
            expected,
            [],
            status="failed",
            error=error,
            notes=[error],
        )

    findings = []
    for result in raw.get("taint_results") or []:
        findings.append(result.get("rule_id", result.get("pattern", "unknown")))
    return normalize_lab_result("mcpscan", raw, server_name, expected, findings)


def normalize_cisco(raw: dict, server_name: str, expected: dict) -> dict[str, Any]:
    findings = []
    for result in raw.get("findings") or []:
        findings.append(result.get("type", result.get("rule", "unknown")))
    return normalize_lab_result("cisco-scanner", raw, server_name, expected, findings)


def normalize_guard(raw: dict, server_name: str, expected: dict) -> dict[str, Any]:
    findings = [finding for finding in raw.get("findings", []) if isinstance(finding, str)]
    return normalize_lab_result("mcp-guard", raw, server_name, expected, findings, raw.get("policy_verdict"))


def build_failed_ox_result(product_id: str, expected: dict[str, Any], error: str, source_file: Path) -> dict[str, Any]:
    launch_expected = expected.get("expected_launch_success")
    health_expected = expected.get("expected_health_status")
    scan_expected = expected.get("expected_scan_status")

    return {
        "target": product_id,
        "target_type": "ox_live",
        "product_name": expected.get("product_name", product_id),
        "scanner_name": "mcp-guard-live",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_url": expected.get("source_url") or "-",
        "launch_kind": expected.get("launch_kind") or "unknown",
        "launch_status": "failed",
        "health_status": "unreachable",
        "scan_status": "failed",
        "failure_reason": "raw_result_unavailable",
        "expected_findings": expected.get("expected_findings", []),
        "optional_findings": expected.get("optional_findings", []),
        "detected_findings": [],
        "true_positives": [],
        "missed_findings": expected.get("expected_findings", []),
        "false_positives": [],
        "expected_launch_success": launch_expected,
        "launch_matches_expectation": None if launch_expected is None else False,
        "expected_health_status": health_expected,
        "health_matches_expectation": None if health_expected is None else False,
        "expected_scan_status": scan_expected,
        "scan_matches_expectation": None if scan_expected is None else False,
        "notes": [error],
        "evidence": {"source_file": str(source_file)},
    }


def normalize_ox_live(raw: dict, expected: dict) -> dict[str, Any]:
    detected = raw.get("scan_result", {}).get("findings", []) if raw.get("scan_status") == "success" else []
    expected_findings = expected.get("expected_findings", [])
    optional_findings = expected.get("optional_findings", [])

    detected_set = set(detected)
    expected_set = set(expected_findings)
    optional_set = set(optional_findings)

    launch_expected = expected.get("expected_launch_success")
    health_expected = expected.get("expected_health_status")
    scan_expected = expected.get("expected_scan_status")

    actual_health = raw.get("health_status")
    actual_launch_success = raw.get("launch_status") == "success"

    return {
        "target": raw["product_id"],
        "target_type": "ox_live",
        "product_name": raw["product_name"],
        "scanner_name": "mcp-guard-live",
        "timestamp": raw.get("timestamp"),
        "source_url": raw.get("source_url"),
        "launch_kind": raw.get("launch_kind"),
        "launch_status": raw.get("launch_status"),
        "health_status": actual_health,
        "scan_status": raw.get("scan_status"),
        "failure_reason": raw.get("failure_reason"),
        "expected_findings": expected_findings,
        "optional_findings": optional_findings,
        "detected_findings": detected,
        "true_positives": sorted(detected_set & expected_set),
        "missed_findings": sorted(expected_set - detected_set),
        "false_positives": sorted(detected_set - expected_set - optional_set),
        "expected_launch_success": launch_expected,
        "launch_matches_expectation": None if launch_expected is None else actual_launch_success == launch_expected,
        "expected_health_status": health_expected,
        "health_matches_expectation": None if health_expected is None else actual_health == health_expected,
        "expected_scan_status": scan_expected,
        "scan_matches_expectation": None if scan_expected is None else raw.get("scan_status") == scan_expected,
        "notes": raw.get("notes", []),
        "evidence": raw.get("evidence", {}),
    }


def lab_status_label(result: dict[str, Any]) -> str:
    status = result.get("status", "success")
    if status == "failed":
        return "FAIL"
    if status == "skipped":
        return "SKIP"
    if result["missed_findings"] or result["false_positives"]:
        return "WARN"
    return "OK"


def generate_comparison_report(all_normalized: list[dict[str, Any]]) -> str:
    lines = ["# MCP Scanner Benchmark Report\n"]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")

    scanners: dict[str, list[dict[str, Any]]] = {}
    for normalized in all_normalized:
        scanners.setdefault(normalized["scanner_name"], []).append(normalized)

    for scanner_name, results in scanners.items():
        lines.append(f"\n## {scanner_name}\n")
        tp = sum(len(result["true_positives"]) for result in results)
        fp = sum(len(result["false_positives"]) for result in results)
        fn = sum(len(result["missed_findings"]) for result in results)
        total_expected = sum(len(result["expected_findings"]) for result in results)
        success_count = sum(1 for result in results if result.get("status") == "success")
        skipped_count = sum(1 for result in results if result.get("status") == "skipped")
        failed_count = sum(1 for result in results if result.get("status") == "failed")

        lines.append(f"- **True Positives**: {tp}")
        lines.append(f"- **False Positives**: {fp}")
        lines.append(f"- **False Negatives (Missed)**: {fn}")
        lines.append(f"- **Total Expected Findings**: {total_expected}")
        lines.append(f"- **Successful Scans**: {success_count}")
        lines.append(f"- **Skipped Scans**: {skipped_count}")
        lines.append(f"- **Failed Scans**: {failed_count}")
        if total_expected > 0:
            lines.append(f"- **Recall**: {tp/total_expected:.1%}")
        if tp + fp > 0:
            lines.append(f"- **Precision**: {tp/(tp+fp):.1%}")
        lines.append("")

        for result in results:
            status = lab_status_label(result)
            suffix = f" Error={result['error']}" if result.get("error") else ""
            lines.append(
                f"  {status} **{result['target']}**: "
                f"TP={len(result['true_positives'])} "
                f"FP={len(result['false_positives'])} "
                f"FN={len(result['missed_findings'])}{suffix}"
            )

    lines.append("\n## Cross-Scanner Comparison\n")
    lines.append("| Server | mcpscan | cisco-scanner | mcp-guard |")
    lines.append("|--------|---------|---------------|-----------|")

    server_names = sorted({normalized["target"] for normalized in all_normalized})
    for server in server_names:
        row = [server]
        for scanner in LAB_SCANNERS:
            matches = [n for n in all_normalized if n["target"] == server and n["scanner_name"] == scanner]
            if matches:
                match = matches[0]
                row.append(
                    f"{lab_status_label(match)} "
                    f"TP:{len(match['true_positives'])} "
                    f"FP:{len(match['false_positives'])} "
                    f"FN:{len(match['missed_findings'])}"
                )
            else:
                row.append("N/A")
        lines.append("| " + " | ".join(row) + " |")

    return "\n".join(lines)


def generate_ox_live_report(all_normalized: list[dict[str, Any]]) -> str:
    lines = ["# OX Live Validation Report\n"]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")

    if not all_normalized:
        lines.append("No OX live results were found.")
        return "\n".join(lines)

    launch_success = sum(1 for result in all_normalized if result["launch_status"] == "success")
    scan_success = sum(1 for result in all_normalized if result["scan_status"] == "success")
    reachable = sum(1 for result in all_normalized if result["health_status"] == "reachable")
    blocked = sum(1 for result in all_normalized if result["failure_reason"])

    lines.append(f"- **Products**: {len(all_normalized)}")
    lines.append(f"- **Launch Success**: {launch_success}")
    lines.append(f"- **Health Reachable**: {reachable}")
    lines.append(f"- **Scan Success**: {scan_success}")
    lines.append(f"- **Failures / Blockers Recorded**: {blocked}")
    lines.append("")

    lines.append("| Product | Launch | Health | Scan | Findings | Reason |")
    lines.append("|---------|--------|--------|------|----------|--------|")

    for result in sorted(all_normalized, key=lambda item: item["target"]):
        findings = (
            f"TP:{len(result['true_positives'])}/"
            f"FP:{len(result['false_positives'])}/"
            f"FN:{len(result['missed_findings'])}"
        )
        reason = result["failure_reason"] or "-"
        lines.append(
            "| "
            + " | ".join(
                [
                    result["target"],
                    result["launch_status"],
                    result["health_status"],
                    result["scan_status"],
                    findings,
                    reason,
                ]
            )
            + " |"
        )

    lines.append("\n## Details\n")
    for result in sorted(all_normalized, key=lambda item: item["target"]):
        lines.append(f"### {result['product_name']} ({result['target']})")
        lines.append(f"- Source: {result['source_url']}")
        lines.append(f"- Launch: {result['launch_status']} via `{result['launch_kind']}`")
        lines.append(f"- Health: {result['health_status']}")
        lines.append(f"- Scan: {result['scan_status']}")
        if result["failure_reason"]:
            lines.append(f"- Failure Reason: `{result['failure_reason']}`")
        lines.append(f"- Expected Findings: {', '.join(result['expected_findings']) or 'none'}")
        lines.append(f"- Detected Findings: {', '.join(result['detected_findings']) or 'none'}")
        evidence = result.get("evidence", {})
        if evidence:
            lines.append(f"- Evidence: `{json.dumps(evidence, sort_keys=True)}`")
        notes = result.get("notes") or []
        if notes:
            lines.append(f"- Notes: {' | '.join(notes)}")
        lines.append("")

    return "\n".join(lines)


def generate_lab_outputs(results_dir: Path, expected_file: Path) -> list[dict[str, Any]]:
    raw_dir = results_dir / "raw"
    norm_dir = results_dir / "normalized"
    report_dir = results_dir / "report"
    norm_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    expected_data = load_json(expected_file, default={}) or {}
    expected_servers = expected_data.get("servers", {})
    all_normalized: list[dict[str, Any]] = []

    for scanner_name in LAB_SCANNERS:
        scanner_dir = raw_dir / scanner_name
        discovered_servers = {raw_file.stem for raw_file in scanner_dir.glob("*.json")} if scanner_dir.exists() else set()
        server_names = sorted(set(expected_servers) | discovered_servers)

        for server_name in server_names:
            raw_file = scanner_dir / f"{server_name}.json"
            raw, raw_error = load_json_payload(raw_file)
            server_expected = expected_servers.get(server_name, {})

            if raw_error:
                normalized = build_failed_lab_result(scanner_name, server_name, server_expected, raw_error, raw_file)
            elif scanner_name == "mcpscan":
                normalized = normalize_mcpscan(raw, server_name, server_expected)
            elif not isinstance(raw, dict):
                normalized = build_failed_lab_result(
                    scanner_name,
                    server_name,
                    server_expected,
                    f"unexpected JSON type in {raw_file.name}: {type(raw).__name__}",
                    raw_file,
                )
            elif scanner_name == "cisco-scanner":
                normalized = normalize_cisco(raw, server_name, server_expected)
            else:
                normalized = normalize_guard(raw, server_name, server_expected)

            with open(norm_dir / f"{server_name}_{scanner_name}.json", "w") as f:
                json.dump(normalized, f, indent=2)
                f.write("\n")
            all_normalized.append(normalized)

    if all_normalized:
        report = generate_comparison_report(all_normalized)
        with open(report_dir / "comparison.md", "w") as f:
            f.write(report)

    return all_normalized


def generate_ox_live_outputs(results_dir: Path, expected_file: Path) -> list[dict[str, Any]]:
    raw_dir = results_dir / "raw" / "ox-live"
    norm_dir = results_dir / "normalized" / "ox-live"
    report_dir = results_dir / "report"
    norm_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    expected_data = load_json(expected_file, default={"products": {}}) or {"products": {}}
    products_expected = expected_data.get("products", {})
    normalized_results: list[dict[str, Any]] = []

    discovered_products = {raw_file.stem for raw_file in raw_dir.glob("*.json")} if raw_dir.exists() else set()
    product_ids = sorted(set(products_expected) | discovered_products)

    for product_id in product_ids:
        raw_file = raw_dir / f"{product_id}.json"
        raw, raw_error = load_json_payload(raw_file)
        expected = products_expected.get(product_id, {})

        if raw_error:
            normalized = build_failed_ox_result(product_id, expected, raw_error, raw_file)
        elif not isinstance(raw, dict):
            normalized = build_failed_ox_result(
                product_id,
                expected,
                f"unexpected JSON type in {raw_file.name}: {type(raw).__name__}",
                raw_file,
            )
        else:
            normalized = normalize_ox_live(raw, expected)

        normalized_results.append(normalized)
        with open(norm_dir / f"{product_id}_mcp-guard-live.json", "w") as f:
            json.dump(normalized, f, indent=2)
            f.write("\n")

    if normalized_results:
        report = generate_ox_live_report(normalized_results)
        with open(report_dir / "ox-live.md", "w") as f:
            f.write(report)

    return normalized_results
