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


if __name__ == "__main__":
    unittest.main()
