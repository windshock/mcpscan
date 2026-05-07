import io
import json
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from mcp_guard import cli


class CliTests(unittest.TestCase):
    def test_discover_json_output(self):
        discovery = {
            "platform": "Darwin",
            "docker_available": False,
            "candidate_count": 1,
            "candidates": [
                {
                    "kind": "endpoint",
                    "target": "http://127.0.0.1:8000",
                    "score": 90,
                    "source": "host",
                    "scan_ready": True,
                }
            ],
        }
        args = type("Args", (), {"output": "json"})()
        with patch("mcp_guard.cli.discover_targets", return_value=discovery):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                cli._handle_discover(args)

        parsed = json.loads(buffer.getvalue())
        self.assertEqual(parsed["candidate_count"], 1)

    def test_scan_no_args_uses_discovery_and_auto_selection(self):
        scan_result = {
            "target": "/tmp/project",
            "risk": "HIGH",
            "findings": [{"pattern_id": "command_exec", "severity": "CRITICAL", "matched_indicator": "subprocess.run"}],
        }
        args = type(
            "Args",
            (),
            {
                "path": None,
                "config": None,
                "endpoint": None,
                "auto": True,
                "policy": None,
                "env": "production",
                "output": "json",
            },
        )()
        discovery = {
            "platform": "Darwin",
            "docker_available": False,
            "candidate_count": 1,
            "candidates": [{"kind": "path", "target": "/tmp/project", "scan_ready": True}],
        }
        evaluation = {
            "overall_verdict": "BLOCK",
            "verdicts": [{"pattern": "command_exec", "severity": "CRITICAL", "verdict": "BLOCK", "indicator": "subprocess.run"}],
            "recommendations": [{"pattern": "command_exec", "recommendation": "Remove direct command execution."}],
        }
        with patch("mcp_guard.cli.discover_targets", return_value=discovery), patch(
            "mcp_guard.cli.select_candidate", return_value=discovery["candidates"][0]
        ), patch("mcp_guard.cli._scan_discovered_candidate", return_value=scan_result), patch(
            "mcp_guard.cli.PolicyEngine"
        ) as policy_engine_cls:
            policy_engine = policy_engine_cls.return_value
            policy_engine.evaluate.return_value = evaluation
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                with self.assertRaises(SystemExit) as exit_ctx:
                    cli._handle_scan(args)

        self.assertEqual(exit_ctx.exception.code, 1)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["policy_verdict"], "BLOCK")
        self.assertEqual(payload["findings"], ["command_exec"])


class CliCiscoIntegrationTests(unittest.TestCase):
    """Verify --with-cisco flag plumbing through the CLI."""

    def _make_args(self, **overrides):
        defaults = {
            "path": "/tmp/example",
            "config": None,
            "endpoint": None,
            "auto": False,
            "policy": None,
            "env": "production",
            "output": "json",
            "with_cisco": True,
            "cisco_analyzers": None,
            "cisco_timeout": 30,
        }
        defaults.update(overrides)
        return type("Args", (), defaults)()

    def _scan_result(self):
        return {
            "target": "/tmp/example",
            "risk": "HIGH",
            "findings": [
                {
                    "pattern_id": "command_exec",
                    "pattern_name": "Direct Command Execution",
                    "severity": "CRITICAL",
                    "matched_indicator": "subprocess.run",
                    "policy": "BLOCK",
                    "source": "mcp-guard",
                }
            ],
        }

    def test_with_cisco_merges_findings_and_provenance(self):
        scan_result = self._scan_result()
        cisco_findings = {
            "findings": [
                {
                    "pattern_id": "tool_poisoning",
                    "pattern_name": "cisco prompt injection",
                    "severity": "HIGH",
                    "matched_indicator": "cisco yara: tool 'execute' → PROMPT INJECTION",
                    "policy": "BLOCK",
                    "source": "cisco-yara",
                }
            ],
            "notes": [],
            "ok": True,
        }
        args = self._make_args()
        with patch("mcp_guard.cli.scan_path", return_value=scan_result), patch(
            "mcp_guard.cli.PolicyEngine"
        ) as policy_cls, patch(
            "mcp_guard.cisco_bridge.is_available", return_value=True
        ), patch(
            "mcp_guard.cisco_bridge.scan_path", return_value=cisco_findings
        ):
            policy = policy_cls.return_value
            policy.evaluate.return_value = {
                "overall_verdict": "BLOCK",
                "verdicts": [
                    {"pattern": "command_exec", "severity": "CRITICAL", "verdict": "BLOCK", "indicator": "subprocess.run"},
                    {"pattern": "tool_poisoning", "severity": "HIGH", "verdict": "BLOCK", "indicator": "cisco …"},
                ],
                "recommendations": [],
            }
            buffer = io.StringIO()
            with redirect_stdout(buffer), self.assertRaises(SystemExit):
                cli._handle_scan(args)

        payload = json.loads(buffer.getvalue())
        self.assertEqual(sorted(payload["findings"]), ["command_exec", "tool_poisoning"])
        self.assertEqual(payload["provenance"]["command_exec"], ["mcp-guard"])
        self.assertEqual(payload["provenance"]["tool_poisoning"], ["cisco-yara"])

    def test_with_cisco_warns_when_binary_missing(self):
        scan_result = self._scan_result()
        args = self._make_args()
        with patch("mcp_guard.cli.scan_path", return_value=scan_result), patch(
            "mcp_guard.cli.PolicyEngine"
        ) as policy_cls, patch("mcp_guard.cisco_bridge.is_available", return_value=False):
            policy_cls.return_value.evaluate.return_value = {
                "overall_verdict": "BLOCK",
                "verdicts": [],
                "recommendations": [],
            }
            buffer = io.StringIO()
            with redirect_stdout(buffer), self.assertRaises(SystemExit):
                cli._handle_scan(args)

        payload = json.loads(buffer.getvalue())
        self.assertTrue(any("cisco mcp-scanner not on PATH" in note for note in payload["notes"]))
        # Mcp-guard finding still present, no cisco-tagged extras
        self.assertEqual(payload["findings"], ["command_exec"])

    def test_with_cisco_surfaces_timeout_note(self):
        scan_result = self._scan_result()
        args = self._make_args()
        timeout_note = ["cisco behavioral: cisco scan timed out after 30s"]
        with patch("mcp_guard.cli.scan_path", return_value=scan_result), patch(
            "mcp_guard.cli.PolicyEngine"
        ) as policy_cls, patch(
            "mcp_guard.cisco_bridge.is_available", return_value=True
        ), patch(
            "mcp_guard.cisco_bridge.scan_path",
            return_value={"findings": [], "notes": timeout_note, "ok": False},
        ):
            policy_cls.return_value.evaluate.return_value = {
                "overall_verdict": "BLOCK",
                "verdicts": [],
                "recommendations": [],
            }
            buffer = io.StringIO()
            with redirect_stdout(buffer), self.assertRaises(SystemExit):
                cli._handle_scan(args)

        payload = json.loads(buffer.getvalue())
        self.assertIn(timeout_note[0], payload["notes"])


class CliAutoAllTests(unittest.TestCase):
    """Verify --auto-all scans every discovered candidate."""

    def _make_args(self, **overrides):
        defaults = {
            "path": None,
            "config": None,
            "endpoint": None,
            "auto": False,
            "auto_all": True,
            "policy": None,
            "env": "production",
            "output": "json",
            "with_cisco": False,
            "cisco_analyzers": None,
            "cisco_timeout": 30,
        }
        defaults.update(overrides)
        return type("Args", (), defaults)()

    def _scan_result(self, target):
        return {
            "target": target,
            "risk": "HIGH",
            "findings": [
                {
                    "pattern_id": "command_exec",
                    "severity": "CRITICAL",
                    "matched_indicator": "subprocess.run",
                    "policy": "BLOCK",
                    "source": "mcp-guard",
                }
            ],
        }

    def test_auto_all_emits_one_payload_per_candidate(self):
        candidates = [
            {"kind": "endpoint", "target": "http://127.0.0.1:3101", "score": 90, "scan_ready": True},
            {"kind": "endpoint", "target": "http://127.0.0.1:3102", "score": 80, "scan_ready": True},
            {"kind": "path", "target": "/tmp/x", "score": 70, "scan_ready": True},
        ]

        def fake_scan(c):
            return self._scan_result(c["target"])

        evaluation = {
            "overall_verdict": "BLOCK",
            "verdicts": [
                {"pattern": "command_exec", "severity": "CRITICAL", "verdict": "BLOCK", "indicator": "subprocess.run"}
            ],
            "recommendations": [],
        }

        args = self._make_args()
        with patch("mcp_guard.cli.discover_targets", return_value={"candidates": candidates}), patch(
            "mcp_guard.cli._scan_discovered_candidate", side_effect=fake_scan
        ), patch("mcp_guard.cli.target_info.collect", return_value={}), patch(
            "mcp_guard.cli.PolicyEngine"
        ) as policy_cls:
            policy = policy_cls.return_value
            policy.evaluate.return_value = evaluation
            policy.format_output.return_value = "Target: x\nRisk: HIGH"
            buffer = io.StringIO()
            with redirect_stdout(buffer), self.assertRaises(SystemExit) as exit_ctx:
                cli._handle_scan(args)

        # All candidates BLOCK -> exit 1
        self.assertEqual(exit_ctx.exception.code, 1)
        payload = json.loads(buffer.getvalue())
        self.assertEqual(len(payload["results"]), 3)
        targets = [r["target"] for r in payload["results"]]
        self.assertEqual(
            targets, ["http://127.0.0.1:3101", "http://127.0.0.1:3102", "/tmp/x"]
        )
        for r in payload["results"]:
            self.assertEqual(r["policy_verdict"], "BLOCK")
            self.assertEqual(r["findings"], ["command_exec"])

    def test_auto_all_continues_past_per_candidate_errors(self):
        candidates = [
            {"kind": "endpoint", "target": "http://x:1", "score": 90, "scan_ready": True},
            {"kind": "endpoint", "target": "http://x:2", "score": 80, "scan_ready": True},
        ]

        def fake_scan(c):
            if c["target"] == "http://x:2":
                return {"error": "boom"}
            return self._scan_result(c["target"])

        args = self._make_args()
        with patch("mcp_guard.cli.discover_targets", return_value={"candidates": candidates}), patch(
            "mcp_guard.cli._scan_discovered_candidate", side_effect=fake_scan
        ), patch("mcp_guard.cli.target_info.collect", return_value={}), patch(
            "mcp_guard.cli.PolicyEngine"
        ) as policy_cls:
            policy = policy_cls.return_value
            policy.evaluate.return_value = {
                "overall_verdict": "ALLOW",
                "verdicts": [],
                "recommendations": [],
            }
            policy.format_output.return_value = "Target: x"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                # No BLOCK and no exception -> normal exit (no sys.exit call)
                cli._handle_scan(args)

        payload = json.loads(buffer.getvalue())
        self.assertEqual(len(payload["results"]), 2)
        self.assertNotIn("error", payload["results"][0])
        self.assertEqual(payload["results"][1]["error"], "boom")


class PolicyCiscoVerdictTests(unittest.TestCase):
    def test_cisco_high_finding_forces_block_in_development(self):
        from mcp_guard.policy import PolicyEngine

        engine = PolicyEngine()
        scan_result = {
            "target": "x",
            "risk": "HIGH",
            "findings": [
                {
                    "pattern_id": "tool_poisoning",
                    "severity": "HIGH",
                    "matched_indicator": "cisco …",
                    "source": "cisco-yara",
                }
            ],
        }
        evaluation = engine.evaluate(scan_result, environment="development")
        self.assertEqual(evaluation["overall_verdict"], "BLOCK")
        self.assertEqual(evaluation["verdicts"][0]["source"], "cisco-yara")


if __name__ == "__main__":
    unittest.main()
