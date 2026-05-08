import json
import re
import unittest
from unittest import mock

from mcp_guard.export_secuaudit import (
    build_secuaudit_payload,
    _provenance_for,
    _category_for,
    _severity_for,
)


def _scan_result(findings, target="config_json", target_metadata=None):
    raw_findings = [
        {
            "pattern_id": pattern,
            "pattern_name": pattern,
            "severity": severity,
            "matched_indicator": f"indicator for {pattern}",
            "source": "mcp-guard",
            "confidence": "high",
        }
        for pattern, severity in findings
    ]
    result = {
        "target": target,
        "risk": "HIGH" if findings else "NONE",
        "findings": raw_findings,
    }
    if target_metadata is not None:
        result["target_metadata"] = target_metadata
    return result


def _evaluation(verdicts, runtime_hint=False, overall="BLOCK"):
    eval_result = {
        "target": "config_json",
        "risk": "HIGH" if verdicts else "NONE",
        "overall_verdict": overall,
        "environment": "production",
        "verdicts": verdicts,
        "recommendations": [],
        "runtime_verification": [],
    }
    if runtime_hint:
        eval_result["runtime_verification"] = [
            {
                "skill": "oh-my-secuaudit / security-testing-as-code",
                "url": "https://github.com/windshock/oh-my-secuaudit",
                "purpose": "Confirm",
                "example": "lab/unknown/runtime/upsonic-cve-2026-30625/",
            }
        ]
    return eval_result


class ExportSecuauditTest(unittest.TestCase):
    def test_task_id_matches_schema_regex(self):
        scan = _scan_result([("command_exec", "CRITICAL")])
        evaluation = _evaluation([
            {
                "pattern": "command_exec",
                "severity": "CRITICAL",
                "verdict": "BLOCK",
                "indicator": "subprocess.run(...)",
                "source": "mcp-guard",
            }
        ])
        payload = build_secuaudit_payload(
            scan, evaluation,
            target_kind="path",
            target_value="/tmp/repo",
        )
        self.assertRegex(payload["task_id"], r"^[0-9]+-[0-9]+$")

    def test_severity_is_title_cased(self):
        scan = _scan_result([("command_exec", "CRITICAL"), ("env_exposure", "HIGH")])
        evaluation = _evaluation([
            {
                "pattern": "command_exec", "severity": "CRITICAL",
                "verdict": "BLOCK", "indicator": "x", "source": "mcp-guard",
            },
            {
                "pattern": "env_exposure", "severity": "HIGH",
                "verdict": "BLOCK", "indicator": "y", "source": "mcp-guard",
            },
        ])
        payload = build_secuaudit_payload(
            scan, evaluation, target_kind="path", target_value="/tmp/repo",
        )
        severities = {f["severity"] for f in payload["findings"]}
        self.assertEqual(severities, {"Critical", "High"})

    def test_provenance_mapping(self):
        self.assertEqual(_provenance_for("path"), "source-confirmed")
        self.assertEqual(_provenance_for("config"), "source-confirmed")
        self.assertEqual(_provenance_for("endpoint"), "runtime-confirmed")
        self.assertEqual(_provenance_for("discovered"), "not-confirmed")

    def test_category_mapping_for_known_patterns(self):
        self.assertEqual(_category_for("command_exec"), "Command Injection")
        self.assertEqual(_category_for("tool_poisoning"), "Prompt Injection")
        self.assertEqual(_category_for("authless_endpoint"), "Authentication")
        self.assertEqual(_category_for("ssrf"), "SSRF")
        # Unknown patterns fall back to a safe default.
        self.assertEqual(_category_for("never_seen"), "Configuration")

    def test_cwe_attached_for_known_patterns(self):
        scan = _scan_result([("command_exec", "CRITICAL")])
        evaluation = _evaluation([
            {
                "pattern": "command_exec", "severity": "CRITICAL",
                "verdict": "BLOCK", "indicator": "x", "source": "mcp-guard",
            }
        ])
        payload = build_secuaudit_payload(
            scan, evaluation, target_kind="path", target_value="/tmp/repo",
        )
        self.assertEqual(payload["findings"][0]["cwe_id"], "CWE-78")

    def test_source_modules_falls_back_when_no_targets(self):
        scan = _scan_result([("command_exec", "CRITICAL")])
        evaluation = _evaluation([
            {
                "pattern": "command_exec", "severity": "CRITICAL",
                "verdict": "BLOCK", "indicator": "x", "source": "mcp-guard",
            }
        ])
        payload = build_secuaudit_payload(
            scan, evaluation, target_kind="path", target_value="/tmp/some-pkg",
        )
        self.assertEqual(payload["metadata"]["source_modules"], ["some-pkg"])

    def test_source_modules_uses_target_metadata_servers(self):
        target_metadata = {
            "servers": [
                {"name": "evil_server", "command": "git"},
                {"name": "another", "command": "npx"},
            ]
        }
        scan = _scan_result(
            [("command_exec", "CRITICAL")],
            target_metadata=target_metadata,
        )
        evaluation = _evaluation([
            {
                "pattern": "command_exec", "severity": "CRITICAL",
                "verdict": "BLOCK", "indicator": "x", "source": "mcp-guard",
            }
        ])
        payload = build_secuaudit_payload(
            scan, evaluation,
            target_kind="config",
            target_value="/path/to/mcp.json",
        )
        self.assertEqual(
            payload["metadata"]["source_modules"],
            ["evil_server", "another"],
        )

    def test_empty_findings_produces_clean_payload(self):
        scan = _scan_result([])
        evaluation = _evaluation([], overall="ALLOW")
        payload = build_secuaudit_payload(
            scan, evaluation,
            target_kind="path",
            target_value="/tmp/normal-strict",
        )
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(payload["findings"], [])
        self.assertEqual(payload["summary"]["total"], 0)
        # source_modules must still be non-empty per schema.
        self.assertGreaterEqual(len(payload["metadata"]["source_modules"]), 1)

    def test_runtime_verification_hint_carried_in_metadata(self):
        scan = _scan_result([("command_exec", "CRITICAL")])
        evaluation = _evaluation([
            {
                "pattern": "command_exec", "severity": "CRITICAL",
                "verdict": "BLOCK", "indicator": "x", "source": "mcp-guard",
            }
        ], runtime_hint=True)
        payload = build_secuaudit_payload(
            scan, evaluation,
            target_kind="config",
            target_value="/path/to/mcp.json",
        )
        hints = payload["metadata"].get("runtime_verification") or []
        self.assertEqual(len(hints), 1)
        self.assertIn("oh-my-secuaudit", hints[0]["skill"])

    def test_summary_counts_match_severities(self):
        scan = _scan_result([
            ("command_exec", "CRITICAL"),
            ("env_exposure", "HIGH"),
            ("env_exposure", "HIGH"),
        ])
        evaluation = _evaluation([
            {"pattern": "command_exec", "severity": "CRITICAL",
             "verdict": "BLOCK", "indicator": "x", "source": "mcp-guard"},
            {"pattern": "env_exposure", "severity": "HIGH",
             "verdict": "BLOCK", "indicator": "y", "source": "mcp-guard"},
            {"pattern": "env_exposure", "severity": "HIGH",
             "verdict": "BLOCK", "indicator": "z", "source": "mcp-guard"},
        ])
        payload = build_secuaudit_payload(
            scan, evaluation, target_kind="path", target_value="/tmp/x",
        )
        self.assertEqual(payload["summary"]["total"], 3)
        self.assertEqual(payload["summary"]["critical"], 1)
        self.assertEqual(payload["summary"]["high"], 2)


if __name__ == "__main__":
    unittest.main()
