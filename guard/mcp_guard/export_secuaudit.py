"""Convert mcp-guard scan output → oh-my-secuaudit finding_schema.json payload.

The upstream schema lives at
https://github.com/windshock/oh-my-secuaudit/blob/main/skills/runtime/sec-audit-dast/schemas/finding_schema.json
and requires (top-level): ``task_id`` (regex ``^[0-9]+-[0-9]+$``), ``status``
(``completed|failed|partial``), ``findings`` (list), ``metadata`` (dict).
Each finding requires ``id``, ``title``, ``severity`` (``Critical/High/...``),
``category``, ``description``, ``provenance``
(``binary-confirmed|source-confirmed|runtime-confirmed|not-confirmed``), and
``impacted_flow`` (non-empty list).

This module exposes :func:`build_secuaudit_payload` which produces the
schema-compliant dict and :func:`emit_secuaudit_json` which writes it as
indented JSON to stdout. Wired through the CLI as ``--output secuaudit-json``.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Iterable

from .patterns import PATTERNS

# ── Static maps ──────────────────────────────────────────────────────────

# Mirror of mcp-guard's pattern taxonomy onto OWASP-flavoured categories the
# downstream skill expects. Anything not in here falls back to "Configuration".
_CATEGORY_MAP = {
    "command_exec": "Command Injection",
    "config_to_execution": "Command Injection",
    "command_exec_via_args": "Command Injection",
    "remote_config_loading": "Command Injection",
    "allowlist_bypass": "Command Injection",
    "conditional_command_exec": "Command Injection",
    "runtime_only_danger": "Command Injection",
    "tool_poisoning": "Prompt Injection",
    "authless_endpoint": "Authentication",
    "unrestricted_file_read": "Path Traversal",
    "unrestricted_file_write": "Path Traversal",
    "unrestricted_directory_listing": "Path Traversal",
    "env_exposure": "Information Disclosure",
    "excessive_permissions": "Privilege Escalation",
    "ssrf": "SSRF",
    "internal_metadata_exposure": "Information Disclosure",
    "cors_misconfiguration": "Misconfiguration",
    "hidden_transport": "Hidden Functionality",
    "connector_metadata_exposure": "Information Disclosure",
    "config_injection": "Configuration Tampering",
}

# Best-effort CWE for each pattern_id — used as the optional `cwe_id` field
# (regex `^CWE-[0-9]+$`). Patterns we can't confidently map are left out.
_CWE_MAP = {
    "command_exec": "CWE-78",
    "config_to_execution": "CWE-78",
    "command_exec_via_args": "CWE-78",
    "remote_config_loading": "CWE-829",
    "allowlist_bypass": "CWE-184",
    "conditional_command_exec": "CWE-78",
    "runtime_only_danger": "CWE-78",
    "tool_poisoning": "CWE-94",
    "authless_endpoint": "CWE-306",
    "unrestricted_file_read": "CWE-22",
    "unrestricted_file_write": "CWE-22",
    "unrestricted_directory_listing": "CWE-548",
    "env_exposure": "CWE-200",
    "excessive_permissions": "CWE-269",
    "ssrf": "CWE-918",
    "internal_metadata_exposure": "CWE-200",
    "cors_misconfiguration": "CWE-942",
    "hidden_transport": "CWE-912",
}

# mcp-guard severities are uppercase (CRITICAL/HIGH/...). Schema enum is
# Title-Cased.
_SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Info",
}


# ── Public API ───────────────────────────────────────────────────────────


def build_secuaudit_payload(
    scan_result: dict,
    evaluation: dict,
    *,
    target_kind: str,
    target_value: str,
    task_id: str | None = None,
) -> dict[str, Any]:
    """Translate (scan_result, evaluation) into a schema-compliant payload.

    ``target_kind`` is one of ``path|endpoint|config|inline`` and drives the
    `provenance` mapping; ``target_value`` is the original scan target string.
    """
    findings = _build_findings(scan_result, evaluation, target_kind, target_value)

    if scan_result.get("error"):
        status = "failed"
    elif findings:
        status = "completed"
    else:
        status = "completed"

    return {
        "task_id": task_id or _generate_task_id(),
        "status": status,
        "findings": findings,
        "metadata": _build_metadata(scan_result, evaluation, target_kind, target_value),
        "summary": _build_summary(findings),
    }


def emit_secuaudit_json(
    scan_result: dict,
    evaluation: dict,
    *,
    target_kind: str,
    target_value: str,
    stream=None,
) -> None:
    """Render the schema-compliant payload as indented JSON to stdout."""
    payload = build_secuaudit_payload(
        scan_result,
        evaluation,
        target_kind=target_kind,
        target_value=target_value,
    )
    json.dump(payload, stream or sys.stdout, indent=2, ensure_ascii=False)
    if stream is None:
        sys.stdout.write("\n")


# ── Internals ────────────────────────────────────────────────────────────


def _generate_task_id() -> str:
    """Produce a task_id that matches the schema's ``^[0-9]+-[0-9]+$`` regex."""
    secs = int(time.time())
    suffix = os.getpid() & 0xFFFF  # stable within a single CLI invocation
    return f"{secs}-{suffix}"


def _provenance_for(target_kind: str) -> str:
    """Map the scan kind onto the schema's `provenance` enum."""
    if target_kind == "endpoint":
        return "runtime-confirmed"
    if target_kind in ("path", "config", "inline"):
        return "source-confirmed"
    return "not-confirmed"


def _category_for(pattern_id: str) -> str:
    return _CATEGORY_MAP.get(pattern_id, "Configuration")


def _severity_for(raw: str | None) -> str:
    return _SEVERITY_MAP.get(str(raw or "").upper(), "Info")


def _build_findings(
    scan_result: dict,
    evaluation: dict,
    target_kind: str,
    target_value: str,
) -> list[dict[str, Any]]:
    """Build the findings list from the verdicts emitted by the policy engine.

    The policy engine has already deduplicated via ``(pattern_id, indicator)``
    so we don't try to redo that here — every verdict becomes one finding.
    """
    raw_verdicts: Iterable[dict[str, Any]] = evaluation.get("verdicts") or []

    findings: list[dict[str, Any]] = []
    for index, verdict in enumerate(raw_verdicts, start=1):
        if not isinstance(verdict, dict):
            continue
        pattern_id = str(verdict.get("pattern", "unknown"))
        catalog_entry = PATTERNS.get(pattern_id, {})
        title = catalog_entry.get("name") or pattern_id.replace("_", " ").title()
        description = catalog_entry.get("description") or verdict.get("indicator") or title
        recommendation = catalog_entry.get("recommendation")
        severity = _severity_for(verdict.get("severity"))

        finding: dict[str, Any] = {
            "id": f"MCP-GUARD-{index:03d}",
            "title": title,
            "severity": severity,
            "category": _category_for(pattern_id),
            "description": description,
            "provenance": _provenance_for(target_kind),
            "impacted_flow": ["F1"],
        }

        cwe = _CWE_MAP.get(pattern_id)
        if cwe:
            finding["cwe_id"] = cwe

        indicator = verdict.get("indicator")
        if indicator:
            finding["evidence"] = str(indicator)

        if target_kind == "path":
            finding["affected_file"] = target_value
        elif target_kind == "endpoint":
            finding["affected_endpoint"] = target_value

        if recommendation:
            finding["recommendation"] = recommendation

        findings.append(finding)

    return findings


def _build_metadata(
    scan_result: dict,
    evaluation: dict,
    target_kind: str,
    target_value: str,
) -> dict[str, Any]:
    """Schema-required keys: ``source_repo_url``, ``source_repo_path``,
    ``source_modules``. We derive each from whatever the scanner could
    capture; missing values fall back to empty strings / lists rather
    than getting dropped, so the payload stays schema-compliant even
    for inline / endpoint scans.
    """
    target_metadata = scan_result.get("target_metadata") or {}

    source_repo_url = ""
    source_repo_path = ""
    if isinstance(target_metadata, dict):
        git_info = target_metadata.get("git") or {}
        if isinstance(git_info, dict):
            source_repo_url = git_info.get("remote") or ""
        source_repo_path = (
            target_metadata.get("absolute_path")
            or target_metadata.get("source")
            or ""
        )

    if not source_repo_path:
        if target_kind == "path":
            source_repo_path = target_value
        elif target_kind in ("config", "inline"):
            source_repo_path = target_value or "inline_json"

    source_modules: list[str] = []
    if isinstance(target_metadata, dict):
        servers = target_metadata.get("servers") or []
        if isinstance(servers, list):
            for server in servers:
                if isinstance(server, dict) and server.get("name"):
                    source_modules.append(str(server["name"]))

    if not source_modules:
        # Schema requires minItems=1. Pick the most specific identifier we
        # have so the field carries actual signal: a path's basename, an
        # endpoint's URL, or a generic placeholder.
        from os.path import basename
        from urllib.parse import urlparse
        if target_kind == "endpoint":
            netloc = urlparse(target_value or "").netloc
            source_modules = [netloc or target_value or "endpoint"]
        elif target_kind == "path" and target_value:
            source_modules = [basename(target_value.rstrip("/")) or target_value]
        elif target_kind == "config" and target_value and target_value != "inline_json":
            source_modules = [basename(target_value) or target_value]
        else:
            source_modules = [target_kind or "scan_target"]

    metadata: dict[str, Any] = {
        "source_repo_url": source_repo_url,
        "source_repo_path": source_repo_path,
        "source_modules": source_modules,
        "source_label": target_value or target_kind,
        "scanner": "mcp-guard",
        "target_kind": target_kind,
        "policy_verdict": evaluation.get("overall_verdict")
        or scan_result.get("policy_verdict")
        or "ALLOW",
        "environment": evaluation.get("environment", "production"),
        "risk": scan_result.get("risk", "NONE"),
    }

    if isinstance(target_metadata, dict) and target_metadata:
        metadata["target_metadata"] = target_metadata

    runtime_hints = evaluation.get("runtime_verification") or []
    if runtime_hints:
        metadata["runtime_verification"] = runtime_hints

    return metadata


def _build_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        bucket = str(finding.get("severity", "Info")).lower()
        if bucket in summary:
            summary[bucket] += 1
    return summary
