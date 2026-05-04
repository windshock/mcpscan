"""Cisco mcp-scanner bridge.

Wraps the cisco-ai-mcp-scanner CLI (`mcp-scanner`) and exposes it under the
same finding-dict shape that mcp-guard already speaks. Each cisco-emitted
finding is stamped with a ``source`` of ``cisco-<analyzer>`` so the unified
CLI output and PolicyEngine can distinguish capability-based findings (from
mcp-guard) from malicious-intent findings (from cisco).

The bridge is best-effort: if ``mcp-scanner`` is not installed or the
subprocess fails, the helpers return an empty list and a notes string so the
caller can degrade gracefully and surface the reason in the CLI output.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

# Severities Cisco emits per analyzer; map to mcp-guard severity strings.
_CISCO_SEVERITIES = {"HIGH", "CRITICAL", "MEDIUM", "LOW", "INFO"}


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


def map_cisco_threat(name: str) -> str:
    if not name:
        return "unknown"
    return CISCO_THREAT_MAP.get(name.upper(), name.lower().replace(" ", "_"))


_DEFAULT_BIN = "mcp-scanner"


class BridgeError(RuntimeError):
    """Raised when the cisco subprocess fails for a non-recoverable reason."""


def is_available(binary: str = _DEFAULT_BIN) -> bool:
    """Return True if the cisco mcp-scanner CLI is on PATH."""
    return shutil.which(binary) is not None


def default_analyzers(env: dict[str, str] | None = None) -> list[str]:
    """Pick a sensible analyzer set based on environment.

    yara is always available offline. behavioral and llm need an LLM API key
    (either ``MCP_SCANNER_LLM_API_KEY`` or a vendor-specific OPENAI/etc.)
    Without one, return yara only so we don't generate scary errors at runtime.
    """
    env = env or os.environ
    analyzers = ["yara"]
    if env.get("MCP_SCANNER_LLM_API_KEY"):
        analyzers.extend(["behavioral", "llm"])
    return analyzers


def _run(args: list[str], *, timeout: int, env: dict[str, str] | None = None) -> tuple[int, str, str]:
    """Run mcp-scanner; return (returncode, stdout, stderr)."""
    process_env = dict(env) if env is not None else os.environ.copy()
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=process_env,
            check=False,
        )
    except FileNotFoundError as exc:  # binary not on PATH
        raise BridgeError(f"cisco binary not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise BridgeError(f"cisco scan timed out after {timeout}s") from exc
    return proc.returncode, proc.stdout, proc.stderr


def _findings_from_payload(payload: object) -> list[dict]:
    """Translate cisco scan_results into mcp-guard finding dicts.

    Each unsafe tool result contributes one finding per analyzer that flagged
    it. The pattern_id comes from CISCO_THREAT_MAP; severity is taken from the
    analyzer's severity field; matched_indicator embeds tool name and threat
    summary so the human report stays readable.
    """
    if not isinstance(payload, dict):
        return []

    findings: list[dict] = []
    for tool_result in payload.get("scan_results") or []:
        if not isinstance(tool_result, dict) or tool_result.get("is_safe", True):
            continue
        tool_name = tool_result.get("tool_name") or "<unknown>"
        for analyzer_name, analyzer_data in (tool_result.get("findings") or {}).items():
            if not isinstance(analyzer_data, dict):
                continue
            severity = str(analyzer_data.get("severity") or "").upper()
            if severity in ("", "SAFE"):
                continue
            threats = analyzer_data.get("threat_names") or []
            summary = (analyzer_data.get("threat_summary") or "").strip()
            if not threats:
                pattern_id = map_cisco_threat("")
                findings.append(
                    _build_finding(
                        analyzer_name,
                        pattern_id,
                        severity,
                        tool_name,
                        threat_name="(unspecified)",
                        summary=summary,
                    )
                )
                continue
            for threat in threats:
                pattern_id = map_cisco_threat(str(threat))
                findings.append(
                    _build_finding(
                        analyzer_name,
                        pattern_id,
                        severity,
                        tool_name,
                        threat_name=str(threat),
                        summary=summary,
                    )
                )
    return findings


def _build_finding(
    analyzer_name: str,
    pattern_id: str,
    severity: str,
    tool_name: str,
    *,
    threat_name: str,
    summary: str,
) -> dict:
    severity = severity if severity in _CISCO_SEVERITIES else "HIGH"
    indicator = f"cisco {analyzer_name}: tool '{tool_name}' → {threat_name}"
    if summary:
        indicator += f" ({summary})"
    return {
        "pattern_id": pattern_id,
        "pattern_name": f"cisco {threat_name.lower()}",
        "severity": severity,
        "matched_indicator": indicator,
        "policy": "BLOCK",
        "source": f"cisco-{analyzer_name.replace('_analyzer', '')}",
    }


def _parse_stdout(stdout: str) -> object:
    """Best-effort JSON extraction from cisco --format raw output.

    The CLI sometimes prefixes informational lines; pull the outermost JSON
    object/array out by bracket scanning.
    """
    stdout = stdout.strip()
    if not stdout:
        return None
    if stdout.startswith("{") or stdout.startswith("["):
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            pass
    start = stdout.find("{")
    end = stdout.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(stdout[start : end + 1])
    except json.JSONDecodeError:
        return None


def _common_args(analyzers: Iterable[str]) -> list[str]:
    return [
        "--analyzers",
        ",".join(analyzers),
        "--format",
        "raw",
        "--log-level",
        "error",
    ]


def scan_path(
    path: str,
    *,
    analyzers: list[str] | None = None,
    timeout: int = 60,
    binary: str = _DEFAULT_BIN,
    env: dict[str, str] | None = None,
) -> dict:
    """Run ``mcp-scanner behavioral <path>`` and translate findings.

    Returns ``{"findings": [...], "notes": [str], "ok": bool}``. ``ok`` is
    False when the bridge can't run (binary missing, timeout, parser failure).
    Findings carry ``source: cisco-<analyzer>`` so they survive the merge in
    cli.py.
    """
    analyzers = analyzers or default_analyzers(env)
    args = [binary, *_common_args(analyzers), "behavioral", str(path)]
    return _run_and_parse(args, timeout=timeout, env=env, label="behavioral")


def scan_config(
    config: str,
    *,
    analyzers: list[str] | None = None,
    timeout: int = 60,
    binary: str = _DEFAULT_BIN,
    env: dict[str, str] | None = None,
) -> dict:
    """Run ``mcp-scanner config --config-path <file>``.

    ``config`` may be a filesystem path or an inline JSON string. Inline JSON
    is materialised to a temp file because cisco's `config` subcommand only
    takes a path.
    """
    analyzers = analyzers or default_analyzers(env)
    config_path, cleanup = _resolve_config(config)
    try:
        args = [binary, *_common_args(analyzers), "config", "--config-path", str(config_path)]
        return _run_and_parse(args, timeout=timeout, env=env, label="config")
    finally:
        cleanup()


def scan_endpoint(
    url: str,
    *,
    analyzers: list[str] | None = None,
    timeout: int = 60,
    binary: str = _DEFAULT_BIN,
    env: dict[str, str] | None = None,
) -> dict:
    """Run ``mcp-scanner remote --server-url <url>``."""
    analyzers = analyzers or default_analyzers(env)
    args = [binary, *_common_args(analyzers), "remote", "--server-url", url]
    return _run_and_parse(args, timeout=timeout, env=env, label="remote")


def _run_and_parse(args: list[str], *, timeout: int, env: dict[str, str] | None, label: str) -> dict:
    notes: list[str] = []
    try:
        rc, stdout, stderr = _run(args, timeout=timeout, env=env)
    except BridgeError as exc:
        return {"findings": [], "notes": [f"cisco {label}: {exc}"], "ok": False}

    if rc not in (0, 1):  # cisco emits 1 when threats found
        snippet = (stderr or stdout or "").strip().splitlines()[-1:] or [""]
        notes.append(f"cisco {label} exited rc={rc}: {snippet[0]}")
        return {"findings": [], "notes": notes, "ok": False}

    payload = _parse_stdout(stdout)
    if payload is None:
        notes.append(f"cisco {label}: unparseable JSON output")
        return {"findings": [], "notes": notes, "ok": False}

    findings = _findings_from_payload(payload)
    return {"findings": findings, "notes": notes, "ok": True}


def _resolve_config(config: str) -> tuple[Path, callable]:
    """Return (path, cleanup) — write inline JSON to a temp file when needed."""
    candidate = Path(config)
    stripped = config.strip()
    if stripped.startswith(("{", "[")):
        # inline JSON — write to temp file
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        try:
            tmp.write(stripped)
            tmp.flush()
        finally:
            tmp.close()
        path = Path(tmp.name)

        def _cleanup() -> None:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass

        return path, _cleanup
    if candidate.exists():
        return candidate, lambda: None
    raise BridgeError(f"cisco config target neither exists nor is JSON: {config!r}")
