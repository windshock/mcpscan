"""Shared report generation helpers for lab and OX live validation."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


LAB_SCANNERS = ("mcpscan", "cisco-scanner", "invariant-scan", "mcp-guard", "mcp-guard-endpoint")
OPTIONAL_LAB_SCANNERS = frozenset({"mcp-guard-endpoint", "invariant-scan"})


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
        "expected_false_positives": expected_fp,
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


try:
    from mcp_guard.cisco_bridge import CISCO_THREAT_MAP, map_cisco_threat as _map_cisco_threat
except ImportError:  # mcp-guard package not on PYTHONPATH (e.g. some CI subsets)
    CISCO_THREAT_MAP = {
        "PROMPT INJECTION": "tool_poisoning",
        "TOOL POISONING": "tool_poisoning",
        "TOOL SHADOWING": "tool_poisoning",
        "GOAL MANIPULATION": "tool_poisoning",
        "COERCIVE INJECTION": "tool_poisoning",
        "CODE EXECUTION": "command_exec",
        "INJECTION ATTACK": "command_exec",
        "INJECTION ATTACKS": "command_exec",
        "COMMAND INJECTION": "command_exec",
        "SCRIPT INJECTION": "command_exec",
        "SQL INJECTION": "command_exec",
        "TEMPLATE INJECTION": "command_exec",
        "SYSTEM MANIPULATION": "command_exec",
        "CREDENTIAL HARVESTING": "env_exposure",
        "DATA EXFILTRATION": "ssrf",
    }

    def _map_cisco_threat(name: str) -> str:
        if not name:
            return "unknown"
        return CISCO_THREAT_MAP.get(name.upper(), name.lower().replace(" ", "_"))


def normalize_cisco(raw: dict, server_name: str, expected: dict) -> dict[str, Any]:
    findings: list[str] = []

    scan_results = raw.get("scan_results") if isinstance(raw, dict) else None
    if isinstance(scan_results, list):
        for tool_result in scan_results:
            if not isinstance(tool_result, dict) or tool_result.get("is_safe", True):
                continue
            for analyzer_data in (tool_result.get("findings") or {}).values():
                if not isinstance(analyzer_data, dict):
                    continue
                severity = str(analyzer_data.get("severity", "")).upper()
                if severity in ("", "SAFE"):
                    continue
                for threat in analyzer_data.get("threat_names") or []:
                    findings.append(_map_cisco_threat(str(threat)))
    elif isinstance(raw.get("findings"), list):
        for result in raw["findings"]:
            if isinstance(result, dict):
                findings.append(result.get("type", result.get("rule", "unknown")))

    return normalize_lab_result("cisco-scanner", raw, server_name, expected, findings)


def normalize_guard(raw: dict, server_name: str, expected: dict) -> dict[str, Any]:
    findings = [finding for finding in raw.get("findings", []) if isinstance(finding, str)]
    return normalize_lab_result("mcp-guard", raw, server_name, expected, findings, raw.get("policy_verdict"))


# Invariant/Snyk mcp-scan issue codes → lab vuln_type. Codes documented at
# https://docs.snyk.io/scan-with-snyk/snyk-agent-scan/issue-types and observed
# from live runs against the lab corpus.
INVARIANT_ISSUE_MAP = {
    "E001": "tool_poisoning",   # Prompt injection found
    "E002": "tool_poisoning",   # Tool shadowing / hijack
    "E003": "tool_poisoning",   # Goal manipulation
    "W001": "tool_poisoning",   # Dangerous words (lower confidence)
    "W002": "tool_poisoning",   # Manipulative formatting
    "W015": "command_exec",     # Code execution capability
    "W017": "env_exposure",     # Sensitive Data Exposure (env / file paths)
    "W018": "unrestricted_file_read",
}


def _map_invariant_issue(code: str, evidence: str) -> str | None:
    if not code:
        return None
    mapped = INVARIANT_ISSUE_MAP.get(code.upper())
    if mapped:
        # W017 fires for both env-var leakage and unrestricted file read; use
        # evidence text to disambiguate the two when possible.
        if code.upper() == "W017" and evidence:
            ev = evidence.lower()
            if "environment" in ev or "env var" in ev:
                return "env_exposure"
            if any(token in ev for token in ("/etc/", "ssh", "id_rsa", "/root/", "any file")):
                return "unrestricted_file_read"
        return mapped
    return None


def normalize_invariant(raw: dict, server_name: str, expected: dict) -> dict[str, Any]:
    """Normalise a `mcp-scan scan --json` payload.

    The CLI emits a dict keyed by the input config-file path. Each value carries
    `servers` (tool listings) and `issues` (analysis results from api.snyk.io).
    """
    findings: list[str] = []

    if isinstance(raw, dict):
        for key, payload in raw.items():
            if key.startswith("scan_") or not isinstance(payload, dict):
                continue
            for issue in payload.get("issues") or []:
                if not isinstance(issue, dict):
                    continue
                code = str(issue.get("code", ""))
                evidence = str((issue.get("extra_data") or {}).get("evidence", ""))
                mapped = _map_invariant_issue(code, evidence)
                if mapped:
                    findings.append(mapped)

    return normalize_lab_result("invariant-scan", raw, server_name, expected, findings)


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
        "scan_mode": expected.get("scan_mode"),
        "expected_manual_blocker": launch_expected is False,
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

    scan_mode = raw.get("scan_mode")
    launch_kind = raw.get("launch_kind")
    is_manual_blocked = launch_kind == "manual_blocked" or launch_expected is False

    return {
        "target": raw["product_id"],
        "target_type": "ox_live",
        "product_name": raw["product_name"],
        "scanner_name": "mcp-guard-live",
        "timestamp": raw.get("timestamp"),
        "source_url": raw.get("source_url"),
        "launch_kind": launch_kind,
        "launch_status": raw.get("launch_status"),
        "health_status": actual_health,
        "scan_status": raw.get("scan_status"),
        "scan_mode": scan_mode,
        "expected_manual_blocker": is_manual_blocked,
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
    present_scanners = [scanner for scanner in LAB_SCANNERS if scanner in scanners]
    header_cells = ["Server"] + present_scanners
    lines.append("| " + " | ".join(header_cells) + " |")
    lines.append("|" + "|".join("-" * max(3, len(cell) + 2) for cell in header_cells) + "|")

    server_names = sorted({normalized["target"] for normalized in all_normalized})
    for server in server_names:
        row = [server]
        for scanner in present_scanners:
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

    if "mcp-guard" in scanners and "mcp-guard-endpoint" in scanners:
        lines.append("\n## mcp-guard combined (source ∪ endpoint)\n")
        combined: list[dict[str, Any]] = []
        for server in server_names:
            source = next(
                (n for n in all_normalized if n["target"] == server and n["scanner_name"] == "mcp-guard"),
                None,
            )
            endpoint = next(
                (n for n in all_normalized if n["target"] == server and n["scanner_name"] == "mcp-guard-endpoint"),
                None,
            )
            if not (source or endpoint):
                continue
            base = source or endpoint
            expected = set(base.get("expected_findings", []))
            expected_fp = set(base.get("expected_false_positives", []))
            detected: set[str] = set()
            if source:
                detected |= set(source.get("detected_findings", []))
            if endpoint:
                detected |= set(endpoint.get("detected_findings", []))
            tp = sorted(detected & expected)
            fn = sorted(expected - detected)
            fp = sorted(detected - expected - expected_fp)
            combined.append({
                "target": server,
                "scanner_name": "mcp-guard-combined",
                "expected_findings": sorted(expected),
                "true_positives": tp,
                "missed_findings": fn,
                "false_positives": fp,
                "status": "success",
            })

        if combined:
            tp_total = sum(len(c["true_positives"]) for c in combined)
            fp_total = sum(len(c["false_positives"]) for c in combined)
            fn_total = sum(len(c["missed_findings"]) for c in combined)
            expected_total = sum(len(c["expected_findings"]) for c in combined)
            lines.append(f"- **True Positives**: {tp_total}")
            lines.append(f"- **False Positives**: {fp_total}")
            lines.append(f"- **False Negatives (Missed)**: {fn_total}")
            lines.append(f"- **Total Expected Findings**: {expected_total}")
            if expected_total:
                lines.append(f"- **Recall**: {tp_total/expected_total:.1%}")
            if tp_total + fp_total:
                lines.append(f"- **Precision**: {tp_total/(tp_total+fp_total):.1%}")
            lines.append("")
            for c in combined:
                lines.append(
                    f"  {lab_status_label(c)} **{c['target']}**: "
                    f"TP={len(c['true_positives'])} "
                    f"FP={len(c['false_positives'])} "
                    f"FN={len(c['missed_findings'])}"
                )

    return "\n".join(lines)


def generate_ox_live_report(all_normalized: list[dict[str, Any]]) -> str:
    lines = ["# OX Live Validation Report\n"]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")

    if not all_normalized:
        lines.append("No OX live results were found.")
        return "\n".join(lines)

    launchable = [r for r in all_normalized if not r.get("expected_manual_blocker")]
    expected_manual = [r for r in all_normalized if r.get("expected_manual_blocker")]
    launch_success = sum(1 for result in launchable if result["launch_status"] == "success")
    reachable = sum(1 for result in launchable if result["health_status"] == "reachable")
    fixture_scans = sum(1 for result in all_normalized if result.get("scan_mode") == "config_fixture" and result["scan_status"] == "success")
    live_scans = sum(1 for result in all_normalized if result.get("scan_mode") == "endpoint" and result["scan_status"] == "success")
    unexpected_failures = sum(
        1
        for result in launchable
        if result["launch_status"] != "success" and result.get("launch_matches_expectation") is False
    )

    lines.append(f"- **Products**: {len(all_normalized)}")
    lines.append(f"- **Launch-expected products**: {len(launchable)} (success: {launch_success}, reachable: {reachable})")
    lines.append(f"- **Expected manual blockers**: {len(expected_manual)} (no self-hosted launch path)")
    lines.append(f"- **Fixture-only scans (config_fixture)**: {fixture_scans}")
    lines.append(f"- **Live endpoint scans**: {live_scans}")
    lines.append(f"- **Unexpected launch failures**: {unexpected_failures}")
    lines.append("")
    lines.append(
        "> Note: scan results from `config_fixture` mode validate that mcp-guard detects the OX research configuration; they do **not** scan a running product. Live endpoint scans are only counted when `scan_mode == endpoint`."
    )
    lines.append("")

    lines.append("| Product | Launch | Health | Scan (mode) | Findings | Expected Block | Reason |")
    lines.append("|---------|--------|--------|-------------|----------|----------------|--------|")

    for result in sorted(all_normalized, key=lambda item: item["target"]):
        findings = (
            f"TP:{len(result['true_positives'])}/"
            f"FP:{len(result['false_positives'])}/"
            f"FN:{len(result['missed_findings'])}"
        )
        scan_cell = result["scan_status"]
        if result.get("scan_mode"):
            scan_cell = f"{scan_cell} ({result['scan_mode']})"
        reason = result["failure_reason"] or "-"
        manual_blocker = "yes" if result.get("expected_manual_blocker") else "no"
        lines.append(
            "| "
            + " | ".join(
                [
                    result["target"],
                    result["launch_status"],
                    result["health_status"],
                    scan_cell,
                    findings,
                    manual_blocker,
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
        scan_line = f"- Scan: {result['scan_status']}"
        if result.get("scan_mode"):
            scan_line += f" (mode: `{result['scan_mode']}`)"
        lines.append(scan_line)
        if result.get("expected_manual_blocker"):
            lines.append("- Expected Manual Blocker: yes (no official self-hosted launch path)")
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
        if not scanner_dir.exists() and scanner_name in OPTIONAL_LAB_SCANNERS:
            continue
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
            elif scanner_name == "invariant-scan":
                normalized = normalize_invariant(raw, server_name, server_expected)
            elif scanner_name == "mcp-guard-endpoint":
                normalized = normalize_guard(raw, server_name, server_expected)
                normalized["scanner_name"] = "mcp-guard-endpoint"
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


def generate_cisco_config_outputs(results_dir: Path, fixture_file: Path) -> list[dict[str, Any]]:
    """Normalize cisco config-mode scans against the OX research corpus.

    The fixture file contains entries with ``name``, ``expected_findings`` and
    a JSON ``payload``. The runner writes one cisco scan result per case at
    ``results/raw/cisco-config/<case>.json``. Output: per-case normalized JSON
    plus an aggregated ``cisco-supply-chain.md`` report. Skipped silently if
    the raw directory is empty.
    """
    raw_dir = results_dir / "raw" / "cisco-config"
    norm_dir = results_dir / "normalized" / "cisco-config"
    report_dir = results_dir / "report"

    if not raw_dir.exists() or not any(raw_dir.glob("*.json")):
        return []

    norm_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    cases_data = load_json(fixture_file, default=[]) or []
    expected_by_key = {}
    for case in cases_data:
        if not isinstance(case, dict):
            continue
        name = case.get("name")
        if not name:
            continue
        normalized_key = name.replace(" ", "_").replace("/", "_")
        expected_by_key[normalized_key] = {
            "name": name,
            "source": case.get("source", ""),
            "expected_findings": case.get("expected_findings", []) or [],
            "expected_false_positives": case.get("expected_false_positives", []) or [],
        }

    normalized: list[dict[str, Any]] = []
    for raw_file in sorted(raw_dir.glob("*.json")):
        key = raw_file.stem
        case = expected_by_key.get(key, {})
        raw, raw_error = load_json_payload(raw_file)
        expected = {
            "expected_findings": case.get("expected_findings", []),
            "expected_false_positives": case.get("expected_false_positives", []),
        }

        if raw_error:
            entry = build_failed_lab_result("cisco-config", key, expected, raw_error, raw_file)
        elif not isinstance(raw, dict):
            entry = build_failed_lab_result(
                "cisco-config",
                key,
                expected,
                f"unexpected JSON type in {raw_file.name}: {type(raw).__name__}",
                raw_file,
            )
        else:
            entry = normalize_cisco(raw, key, expected)
            entry["scanner_name"] = "cisco-config"

        entry["case_name"] = case.get("name") or key
        entry["case_source"] = case.get("source", "")
        normalized.append(entry)

        with open(norm_dir / f"{key}.json", "w") as f:
            json.dump(entry, f, indent=2)
            f.write("\n")

    if normalized:
        report = _generate_cisco_config_report(normalized)
        with open(report_dir / "cisco-supply-chain.md", "w") as f:
            f.write(report)

    return normalized


def generate_invariant_config_outputs(results_dir: Path, fixture_file: Path) -> list[dict[str, Any]]:
    """Normalize Invariant/Snyk mcp-scan config-mode runs against the OX corpus."""
    raw_dir = results_dir / "raw" / "invariant-config"
    norm_dir = results_dir / "normalized" / "invariant-config"
    report_dir = results_dir / "report"

    if not raw_dir.exists() or not any(raw_dir.glob("*.json")):
        return []

    norm_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    cases_data = load_json(fixture_file, default=[]) or []
    expected_by_key: dict[str, dict[str, Any]] = {}
    for case in cases_data:
        if not isinstance(case, dict):
            continue
        name = case.get("name")
        if not name:
            continue
        normalized_key = name.replace(" ", "_").replace("/", "_")
        expected_by_key[normalized_key] = {
            "name": name,
            "source": case.get("source", ""),
            "expected_findings": case.get("expected_findings", []) or [],
            "expected_false_positives": case.get("expected_false_positives", []) or [],
        }

    normalized: list[dict[str, Any]] = []
    for raw_file in sorted(raw_dir.glob("*.json")):
        key = raw_file.stem
        case = expected_by_key.get(key, {})
        raw, raw_error = load_json_payload(raw_file)
        expected = {
            "expected_findings": case.get("expected_findings", []),
            "expected_false_positives": case.get("expected_false_positives", []),
        }

        if raw_error:
            entry = build_failed_lab_result("invariant-config", key, expected, raw_error, raw_file)
        elif not isinstance(raw, dict):
            entry = build_failed_lab_result(
                "invariant-config",
                key,
                expected,
                f"unexpected JSON type in {raw_file.name}: {type(raw).__name__}",
                raw_file,
            )
        else:
            entry = normalize_invariant(raw, key, expected)
            entry["scanner_name"] = "invariant-config"

        entry["case_name"] = case.get("name") or key
        entry["case_source"] = case.get("source", "")
        normalized.append(entry)

        with open(norm_dir / f"{key}.json", "w") as f:
            json.dump(entry, f, indent=2)
            f.write("\n")

    if normalized:
        report = _generate_invariant_config_report(normalized)
        with open(report_dir / "invariant-supply-chain.md", "w") as f:
            f.write(report)

    return normalized


def _generate_invariant_config_report(results: list[dict[str, Any]]) -> str:
    lines = ["# Invariant/Snyk Supply-Chain Coverage (mcp-scan config mode against OX research corpus)\n"]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")

    total_tp = sum(len(r["true_positives"]) for r in results)
    total_fp = sum(len(r["false_positives"]) for r in results)
    total_fn = sum(len(r["missed_findings"]) for r in results)
    total_expected = sum(len(r["expected_findings"]) for r in results)
    successes = sum(1 for r in results if r.get("status", "success") == "success")

    lines.append(f"- **Cases scanned**: {len(results)} ({successes} succeeded)")
    lines.append(f"- **True Positives**: {total_tp}")
    lines.append(f"- **False Positives**: {total_fp}")
    lines.append(f"- **False Negatives**: {total_fn}")
    lines.append(f"- **Total Expected Findings**: {total_expected}")
    if total_expected:
        lines.append(f"- **Recall**: {total_tp/total_expected:.1%}")
    if total_tp + total_fp:
        lines.append(f"- **Precision**: {total_tp/(total_tp+total_fp):.1%}")
    lines.append("")
    lines.append("> This stage runs `mcp-scan scan --json --dangerously-run-mcp-servers` against the OX research supply-chain corpus. Requires `SNYK_TOKEN`; mcp-scan delegates analysis to api.snyk.io.")
    lines.append("")

    lines.append("| Case | Status | Detected | TP | FP | FN |")
    lines.append("|---|---|---|---:|---:|---:|")
    for r in sorted(results, key=lambda item: item.get("case_name", item["target"])):
        detected = ", ".join(r["detected_findings"]) or "—"
        lines.append(
            "| {name} | {status} | {detected} | {tp} | {fp} | {fn} |".format(
                name=r.get("case_name", r["target"]),
                status=r.get("status", "success"),
                detected=detected,
                tp=len(r["true_positives"]),
                fp=len(r["false_positives"]),
                fn=len(r["missed_findings"]),
            )
        )

    return "\n".join(lines)


def _generate_cisco_config_report(results: list[dict[str, Any]]) -> str:
    lines = ["# Cisco Supply-Chain Coverage (config mode against OX research corpus)\n"]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")

    total_tp = sum(len(r["true_positives"]) for r in results)
    total_fp = sum(len(r["false_positives"]) for r in results)
    total_fn = sum(len(r["missed_findings"]) for r in results)
    total_expected = sum(len(r["expected_findings"]) for r in results)
    successes = sum(1 for r in results if r.get("status", "success") == "success")

    lines.append(f"- **Cases scanned**: {len(results)} ({successes} succeeded)")
    lines.append(f"- **True Positives**: {total_tp}")
    lines.append(f"- **False Positives**: {total_fp}")
    lines.append(f"- **False Negatives**: {total_fn}")
    lines.append(f"- **Total Expected Findings**: {total_expected}")
    if total_expected:
        lines.append(f"- **Recall**: {total_tp/total_expected:.1%}")
    if total_tp + total_fp:
        lines.append(f"- **Precision**: {total_tp/(total_tp+total_fp):.1%}")
    lines.append("")
    lines.append("> This stage runs `mcp-scanner config --config-path <case>` against the OX research supply-chain corpus. It measures Cisco's *malicious-MCP* detection (its native threat model), not the capability lab.")
    lines.append("")

    lines.append("| Case | Status | Detected | TP | FP | FN |")
    lines.append("|---|---|---|---:|---:|---:|")
    for r in sorted(results, key=lambda item: item.get("case_name", item["target"])):
        detected = ", ".join(r["detected_findings"]) or "—"
        lines.append(
            "| {name} | {status} | {detected} | {tp} | {fp} | {fn} |".format(
                name=r.get("case_name", r["target"]),
                status=r.get("status", "success"),
                detected=detected,
                tp=len(r["true_positives"]),
                fp=len(r["false_positives"]),
                fn=len(r["missed_findings"]),
            )
        )

    return "\n".join(lines)


def generate_unknown_lab_config_outputs(results_dir: Path) -> list[dict[str, Any]]:
    """Normalize unknown-lab config-mode scans (Flowise/Upsonic docs configs).

    Each fixture is a canonical, honest mcp.json straight from upstream docs.
    We record what each scanner says about it so the report can distinguish
    malicious-config detections from friction on real-world paste targets.
    """
    raw_root = results_dir / "raw"
    norm_dir = results_dir / "normalized" / "unknown-config"
    report_dir = results_dir / "report"

    scanners = [
        ("unknown-mcp-guard-config", "mcp-guard"),
        ("unknown-cisco-config", "cisco"),
        ("unknown-invariant-config", "invariant"),
    ]

    discovered: dict[str, dict[str, Any]] = {}
    for raw_subdir, label in scanners:
        scanner_dir = raw_root / raw_subdir
        if not scanner_dir.exists():
            continue
        for raw_file in sorted(scanner_dir.glob("*.json")):
            cfg_name = raw_file.stem
            raw, raw_error = load_json_payload(raw_file)
            entry = discovered.setdefault(cfg_name, {})

            if raw_error:
                entry[label] = {"status": "failed", "error": raw_error, "findings": []}
                continue

            if label == "mcp-guard":
                if isinstance(raw, dict):
                    findings = [f for f in (raw.get("findings") or []) if isinstance(f, str)]
                    entry[label] = {
                        "status": str(raw.get("status", "success")),
                        "findings": findings,
                        "policy_verdict": raw.get("policy_verdict"),
                    }
                elif isinstance(raw, dict) and raw.get("status") == "skipped":
                    entry[label] = {"status": "skipped", "findings": []}
                else:
                    entry[label] = {"status": "failed", "findings": []}
            elif label == "cisco":
                findings = []
                if isinstance(raw, dict):
                    status = str(raw.get("status", "success"))
                    if status == "failed":
                        entry[label] = {
                            "status": "failed",
                            "findings": [],
                            "error": raw.get("error") or raw.get("reason"),
                        }
                        continue
                    if raw.get("status") == "skipped":
                        entry[label] = {
                            "status": "skipped",
                            "findings": [],
                            "reason": raw.get("reason") or raw.get("error"),
                        }
                        continue
                    for tool_result in raw.get("scan_results") or []:
                        if not isinstance(tool_result, dict) or tool_result.get("is_safe", True):
                            continue
                        for analyzer_data in (tool_result.get("findings") or {}).values():
                            if not isinstance(analyzer_data, dict):
                                continue
                            for threat in analyzer_data.get("threat_names") or []:
                                findings.append(_map_cisco_threat(str(threat)))
                entry[label] = {"status": "success", "findings": findings}
            elif label == "invariant":
                findings = []
                if isinstance(raw, dict):
                    status = str(raw.get("status", "success"))
                    if status == "failed":
                        entry[label] = {
                            "status": "failed",
                            "findings": [],
                            "error": raw.get("error") or raw.get("reason"),
                        }
                        continue
                    if raw.get("status") == "skipped":
                        entry[label] = {
                            "status": "skipped",
                            "findings": [],
                            "reason": raw.get("reason") or raw.get("error"),
                        }
                        continue
                    for key, payload in raw.items():
                        if not isinstance(payload, dict) or key.startswith("scan_"):
                            continue
                        for issue in payload.get("issues") or []:
                            if not isinstance(issue, dict):
                                continue
                            code = str(issue.get("code", ""))
                            evidence = str((issue.get("extra_data") or {}).get("evidence", ""))
                            mapped = _map_invariant_issue(code, evidence)
                            if mapped:
                                findings.append(mapped)
                entry[label] = {"status": "success", "findings": findings}

    if not discovered:
        return []

    norm_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    # Tag each fixture by category so the report can split the table:
    #   - sanitizer_bypass: CVE-2026-40933 / CVE-2026-30625 patterns (npx -c,
    #     python -c, node -e, git -c core.pager=, uvx --from). A scanner that
    #     misses these is letting a known supply-chain RCE through.
    #   - honest_baseline: docs-recommended configs. A scanner firing here is
    #     flagging a config users will paste straight from upstream docs.
    config_dir = Path("/unknown-configs")
    if not config_dir.exists():
        config_dir = results_dir.parent / "lab" / "unknown" / "configs"

    def _category_for(cfg_name: str) -> str:
        fixture = config_dir / f"{cfg_name}.json"
        if fixture.is_file():
            try:
                payload = json.loads(fixture.read_text())
            except json.JSONDecodeError:
                payload = {}
            if payload.get("_cve"):
                return "sanitizer_bypass"
        return "honest_baseline"

    normalized: list[dict[str, Any]] = []
    for cfg_name in sorted(discovered):
        category = _category_for(cfg_name)
        entry = {"config": cfg_name, "category": category, "scanners": discovered[cfg_name]}

        # Surface the CVE id so the report can cite it.
        fixture = config_dir / f"{cfg_name}.json"
        if fixture.is_file():
            try:
                payload = json.loads(fixture.read_text())
                if payload.get("_cve"):
                    entry["cve"] = payload["_cve"]
            except json.JSONDecodeError:
                pass

        normalized.append(entry)
        with open(norm_dir / f"{cfg_name}.json", "w") as f:
            json.dump(entry, f, indent=2)
            f.write("\n")

    return normalized


def generate_unknown_lab_outputs(results_dir: Path) -> list[dict[str, Any]]:
    """Normalize unknown-lab source scans (blind comparison on real releases).

    No expected_findings — we record what each scanner detected per package
    version, then surface deltas (between scanners and between fix-before vs
    fix-after versions) in `results/report/unknown-lab.md`.
    """
    raw_root = results_dir / "raw"
    norm_dir = results_dir / "normalized" / "unknown-lab"
    report_dir = results_dir / "report"

    scanners = [
        ("unknown-mcp-guard", "mcp-guard"),
        ("unknown-mcpscan", "mcpscan"),
    ]

    discovered: dict[str, dict[str, Any]] = {}
    for raw_subdir, scanner_label in scanners:
        scanner_dir = raw_root / raw_subdir
        if not scanner_dir.exists():
            continue
        for raw_file in sorted(scanner_dir.glob("*.json")):
            pkg = raw_file.stem
            raw, raw_error = load_json_payload(raw_file)
            entry = discovered.setdefault(pkg, {})

            if raw_error:
                entry[scanner_label] = {
                    "status": "failed",
                    "error": raw_error,
                    "findings": [],
                }
                continue

            if scanner_label == "mcp-guard":
                if isinstance(raw, dict):
                    findings = [f for f in (raw.get("findings") or []) if isinstance(f, str)]
                    entry[scanner_label] = {
                        "status": str(raw.get("status", "success")),
                        "findings": findings,
                        "policy_verdict": raw.get("policy_verdict"),
                        "risk_level": raw.get("risk_level"),
                    }
                else:
                    entry[scanner_label] = {
                        "status": "failed",
                        "error": "unexpected JSON shape (expected dict)",
                        "findings": [],
                    }
            elif scanner_label == "mcpscan":
                # MCPScan emits a bare JSON array of finding dicts directly
                # (one per (file, rule_id) pair). Empty array = no findings.
                rule_ids: list[str] = []
                if isinstance(raw, list):
                    for r in raw:
                        if isinstance(r, dict) and r.get("rule_id"):
                            rule_ids.append(str(r["rule_id"]))
                elif isinstance(raw, dict):
                    for r in (raw.get("taint_results") or raw.get("findings") or []):
                        if isinstance(r, dict) and r.get("rule_id"):
                            rule_ids.append(str(r["rule_id"]))
                # Collapse `opt.mcpscan.src.mcpscan.rules.<name>` to just `<name>`
                # so the report is readable.
                short = [rid.rsplit(".", 1)[-1] for rid in rule_ids]
                entry[scanner_label] = {
                    "status": "success",
                    "findings": short,
                    "raw_rule_count": len(short),
                    "unique_rule_count": len(set(short)),
                }

    if not discovered:
        return []

    norm_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)

    normalized: list[dict[str, Any]] = []
    for pkg in sorted(discovered):
        entry = {
            "package": pkg,
            "scanners": discovered[pkg],
        }
        normalized.append(entry)
        with open(norm_dir / f"{pkg}.json", "w") as f:
            json.dump(entry, f, indent=2)
            f.write("\n")

    config_normalized = generate_unknown_lab_config_outputs(results_dir)

    report = _generate_unknown_lab_report(normalized, config_normalized)
    with open(report_dir / "unknown-lab.md", "w") as f:
        f.write(report)

    return normalized


def _generate_unknown_lab_report(
    results: list[dict[str, Any]],
    config_results: list[dict[str, Any]] | None = None,
) -> str:
    lines = ["# Unknown-Lab: Blind comparison on real released packages\n"]
    lines.append(f"Generated: {datetime.now(timezone.utc).isoformat()}\n")
    lines.append(
        "This stage scans unmodified upstream releases. There are no `expected_findings` — "
        "the value is in (a) what each scanner uniquely surfaces, (b) deltas between adjacent "
        "version pairs (e.g. before vs after a security fix).\n"
    )
    lines.append(
        "**Two scan modes covered**: (i) *source* — scan the actual shipped source tree; "
        "(ii) *config* — scan two categories of MCP configs: docs-recommended honest baselines "
        "(FP-rate probes) and CVE-2026-40933 / CVE-2026-30625 sanitizer-bypass patterns from the "
        "[OX research blog](https://www.ox.security/blog/flowise-cve-2026-40933-upsonic-cve-2026-30625-what-to-do-when-best-practice-isnt-enough/). "
        "The bypass pattern is `<allowed_cmd> <innocent-looking-arg> <attacker-controlled-payload>` "
        "(e.g. `npx -c curl ...`, `python -c \"import os; ...\"`, `git -c core.pager=...`) — the "
        "Flowise/Upsonic input sanitizer accepts it because the leading binary is in the allowlist "
        "and the argument string contains no `&|>` shell metacharacters, but the binary itself "
        "interprets the next argument and runs arbitrary code.\n"
    )
    lines.append(
        "Live-launch is intentionally not run here: Flowise (MCP *host/client*) and Upsonic "
        "(MCP *client* SDK) do not expose their own tools as MCP servers — neither has an SSE "
        "endpoint to probe. The CVEs are RCEs in their **stdio launcher paths** "
        "(`MCPHandler.prepare_command` → `StdioServerParameters` → `stdio_client` for Upsonic; "
        "the canvas-UI Custom MCP form for Flowise). A higher-fidelity reproduction would stand "
        "up live instances and submit each bypass through the host's submission path — see "
        "[`lab/unknown/CVE-NOTES.md`](../../lab/unknown/CVE-NOTES.md) for the verified attack "
        "surface and what actually changed between 0.71.6 → 0.72.0 (`prepare_command` body is "
        "byte-identical; the only diff is a console warning).\n"
    )

    # ── Per-package findings ───────────────────────
    lines.append("## Per-package findings\n")
    lines.append("| Package | mcp-guard verdict | mcp-guard findings | MCPScan rules (count × unique) |")
    lines.append("|---|---|---|---|")
    for r in results:
        guard = r["scanners"].get("mcp-guard", {})
        mcps = r["scanners"].get("mcpscan", {})
        verdict = guard.get("policy_verdict") or "—"
        guard_findings = ", ".join(sorted(set(guard.get("findings") or []))) or "—"
        mcps_findings_list = mcps.get("findings") or []
        mcps_unique = sorted(set(mcps_findings_list))
        if mcps_unique:
            mcps_findings = f"{len(mcps_findings_list)} hits across {len(mcps_unique)} rules: {', '.join(mcps_unique)}"
        else:
            mcps_findings = "—"
        lines.append(f"| {r['package']} | {verdict} | {guard_findings} | {mcps_findings} |")
    lines.append("")

    # ── Version-pair deltas ────────────────────────
    pairs = _pair_unknown_versions(results)
    if pairs:
        lines.append("## Version-pair deltas (fix-before → fix-after)\n")
        lines.append("| Pair | Scanner | Before-only | After-only | Common |")
        lines.append("|---|---|---|---|---|")
        for older, newer in pairs:
            for scanner_label in ("mcp-guard", "mcpscan"):
                before = set(_findings_for(older, scanner_label))
                after = set(_findings_for(newer, scanner_label))
                only_before = sorted(before - after) or ["—"]
                only_after = sorted(after - before) or ["—"]
                common = sorted(before & after) or ["—"]
                lines.append(
                    f"| {older['package']} → {newer['package']} | {scanner_label} | "
                    f"{', '.join(only_before)} | {', '.join(only_after)} | "
                    f"{', '.join(common)} |"
                )
        lines.append("")

    # ── Scanner overlap (within each package) ──────
    lines.append("## Scanner overlap (per package)\n")
    lines.append("| Package | mcp-guard only | MCPScan only | Both |")
    lines.append("|---|---|---|---|")
    for r in results:
        g = set(_findings_for(r, "mcp-guard"))
        m = set(_findings_for(r, "mcpscan"))
        only_g = sorted(g - m) or ["—"]
        only_m = sorted(m - g) or ["—"]
        both = sorted(g & m) or ["—"]
        lines.append(
            f"| {r['package']} | {', '.join(only_g)} | {', '.join(only_m)} | {', '.join(both)} |"
        )
    lines.append("")

    # ── Config-mode fixture scans ──────────────────
    lines.append("## Config-mode fixture scans\n")
    lines.append(
        "Two fixture categories: **sanitizer_bypass** are CVE-2026-40933 / CVE-2026-30625 patterns "
        "from the OX research blog — the canonical Flowise/Upsonic command-input sanitizer treats "
        "them as safe (allowed command + no blocked special character) but the runtime interprets a "
        "subsequent argument and executes arbitrary code. A scanner that misses these is letting a "
        "known supply-chain RCE through. **honest_baseline** are non-malicious configs straight from "
        "the Flowise / Upsonic docs — flags here are scanner false positives against real-world paste "
        "targets.\n"
    )
    if not config_results:
        lines.append("No config-mode raw results were found yet.")
        lines.append("")
    else:
        bypass_rows = [r for r in config_results if r.get("category") == "sanitizer_bypass"]
        honest_rows = [r for r in config_results if r.get("category") != "sanitizer_bypass"]

        if bypass_rows:
            lines.append("### sanitizer_bypass — CVE-grade exploit configs\n")
            lines.append("| Config fixture | CVE | mcp-guard | Cisco config | Invariant/Snyk config |")
            lines.append("|---|---|---|---|---|")
            for r in bypass_rows:
                scanners = r.get("scanners", {})
                lines.append(
                    "| {config} | {cve} | {guard} | {cisco} | {invariant} |".format(
                        config=r.get("config", "unknown"),
                        cve=r.get("cve", "—"),
                        guard=_format_unknown_config_cell(scanners.get("mcp-guard", {}), include_verdict=True),
                        cisco=_format_unknown_config_cell(scanners.get("cisco", {})),
                        invariant=_format_unknown_config_cell(scanners.get("invariant", {})),
                    )
                )
            lines.append("")

        if honest_rows:
            lines.append("### honest_baseline — docs-recommended configs (FP-rate probe)\n")
            lines.append("| Config fixture | mcp-guard | Cisco config | Invariant/Snyk config |")
            lines.append("|---|---|---|---|")
            for r in honest_rows:
                scanners = r.get("scanners", {})
                lines.append(
                    "| {config} | {guard} | {cisco} | {invariant} |".format(
                        config=r.get("config", "unknown"),
                        guard=_format_unknown_config_cell(scanners.get("mcp-guard", {}), include_verdict=True),
                        cisco=_format_unknown_config_cell(scanners.get("cisco", {})),
                        invariant=_format_unknown_config_cell(scanners.get("invariant", {})),
                    )
                )
            lines.append("")

    return "\n".join(lines)


def _format_unknown_config_cell(scanner: dict[str, Any], *, include_verdict: bool = False) -> str:
    if not scanner:
        return "not run"

    status = str(scanner.get("status", "success"))
    findings = sorted(set(scanner.get("findings") or []))
    finding_text = ", ".join(findings) if findings else "—"

    if status == "skipped":
        reason = scanner.get("reason") or scanner.get("error")
        return f"skipped ({reason})" if reason else "skipped"
    if status == "failed":
        error = scanner.get("error") or scanner.get("reason")
        return f"failed ({error})" if error else "failed"

    if include_verdict and scanner.get("policy_verdict"):
        return f"{scanner['policy_verdict']}: {finding_text}"
    return finding_text


def _findings_for(entry: dict[str, Any], scanner_label: str) -> list[str]:
    return entry.get("scanners", {}).get(scanner_label, {}).get("findings", []) or []


def _pair_unknown_versions(results: list[dict[str, Any]]) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Group packages by name (e.g. 'flowise', 'upsonic') and return ordered
    pairs (older, newer) per group when exactly two versions exist."""
    by_name: dict[str, list[dict[str, Any]]] = {}
    for r in results:
        name, _, _ = r["package"].rpartition("-")  # "flowise-3.1.0" → "flowise"
        if not name:
            continue
        by_name.setdefault(name, []).append(r)

    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for name, entries in by_name.items():
        if len(entries) < 2:
            continue
        from packaging.version import Version, InvalidVersion

        def _ver(entry: dict[str, Any]) -> Version:
            ver_str = entry["package"].split("-", 1)[1]
            try:
                return Version(ver_str)
            except InvalidVersion:
                return Version("0")

        ordered = sorted(entries, key=_ver)
        for older, newer in zip(ordered, ordered[1:]):
            pairs.append((older, newer))
    return pairs


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
