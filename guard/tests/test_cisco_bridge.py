"""Tests for the Cisco mcp-scanner bridge.

The bridge subprocesses an external CLI; tests mock subprocess.run so they
run offline. A second class verifies that ``runner.reporting`` keeps using
the shared CISCO_THREAT_MAP.
"""
from __future__ import annotations

import json
import subprocess
import unittest
from unittest.mock import patch

from mcp_guard import cisco_bridge


_VULN_PAYLOAD = {
    "scan_results": [
        {
            "tool_name": "execute_command",
            "is_safe": False,
            "findings": {
                "yara_analyzer": {
                    "severity": "HIGH",
                    "total_findings": 2,
                    "threat_names": ["CODE EXECUTION", "TOOL POISONING"],
                    "threat_summary": "shell exec",
                },
                "api_analyzer": {"severity": "SAFE", "total_findings": 0},
            },
        },
        {
            "tool_name": "fetch_url",
            "is_safe": False,
            "findings": {
                "behavioral_analyzer": {
                    "severity": "MEDIUM",
                    "threat_names": ["DATA EXFILTRATION"],
                    "threat_summary": "url fetch",
                }
            },
        },
        {
            "tool_name": "safe_tool",
            "is_safe": True,
            "findings": {},
        },
    ]
}


class CiscoBridgeFindingTests(unittest.TestCase):
    def _fake_completed(self, payload: object, returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
        stdout = json.dumps(payload) if not isinstance(payload, str) else payload
        return subprocess.CompletedProcess(
            args=["mcp-scanner"],
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
        )

    def test_scan_path_returns_source_tagged_findings(self):
        with patch(
            "mcp_guard.cisco_bridge.subprocess.run",
            return_value=self._fake_completed(_VULN_PAYLOAD, returncode=1),
        ):
            result = cisco_bridge.scan_path("/tmp/example", analyzers=["yara"])
        self.assertTrue(result["ok"])
        sources = {f["source"] for f in result["findings"]}
        self.assertIn("cisco-yara", sources)
        self.assertIn("cisco-behavioral", sources)
        pattern_ids = {f["pattern_id"] for f in result["findings"]}
        # Cisco threat-name → mcp-guard pattern_id mapping
        self.assertEqual(
            pattern_ids,
            {"command_exec", "tool_poisoning", "ssrf"},
        )

    def test_scan_path_skips_safe_tools_and_safe_analyzers(self):
        with patch(
            "mcp_guard.cisco_bridge.subprocess.run",
            return_value=self._fake_completed(_VULN_PAYLOAD, returncode=1),
        ):
            result = cisco_bridge.scan_path("/tmp/x", analyzers=["yara"])
        # safe_tool should produce zero findings; api_analyzer SAFE should not produce findings
        for finding in result["findings"]:
            self.assertNotIn("safe_tool", finding["matched_indicator"])
            self.assertFalse(finding["source"].endswith("api"))

    def test_scan_endpoint_routes_to_remote_subcommand(self):
        captured: dict = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            return self._fake_completed({"scan_results": []}, returncode=0)

        with patch("mcp_guard.cisco_bridge.subprocess.run", side_effect=fake_run):
            cisco_bridge.scan_endpoint("http://example/sse", analyzers=["yara"])
        self.assertIn("remote", captured["args"])
        self.assertIn("--server-url", captured["args"])
        self.assertEqual(captured["args"][captured["args"].index("--server-url") + 1], "http://example/sse")

    def test_scan_config_inline_json_writes_temp_file(self):
        captured: dict = {}

        def fake_run(args, **kwargs):
            captured["args"] = args
            # cisco config subcommand is reached and a config-path file is provided
            self.assertIn("--config-path", args)
            tmp_path = args[args.index("--config-path") + 1]
            with open(tmp_path) as handle:
                captured["written"] = json.load(handle)
            return self._fake_completed({"scan_results": []}, returncode=0)

        inline = '{"mcpServers":{"x":{"command":"sh"}}}'
        with patch("mcp_guard.cisco_bridge.subprocess.run", side_effect=fake_run):
            cisco_bridge.scan_config(inline, analyzers=["yara"])
        self.assertEqual(captured["written"]["mcpServers"]["x"]["command"], "sh")

    def test_scan_handles_unparseable_output(self):
        with patch(
            "mcp_guard.cisco_bridge.subprocess.run",
            return_value=self._fake_completed("not json at all", returncode=0),
        ):
            result = cisco_bridge.scan_path("/tmp/x", analyzers=["yara"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["findings"], [])
        self.assertTrue(any("unparseable" in note for note in result["notes"]))

    def test_scan_handles_nonzero_exit(self):
        with patch(
            "mcp_guard.cisco_bridge.subprocess.run",
            return_value=self._fake_completed({"scan_results": []}, returncode=2, stderr="boom"),
        ):
            result = cisco_bridge.scan_path("/tmp/x", analyzers=["yara"])
        self.assertFalse(result["ok"])
        self.assertTrue(any("rc=2" in note for note in result["notes"]))

    def test_scan_handles_timeout(self):
        def boom(args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=args, timeout=1)

        with patch("mcp_guard.cisco_bridge.subprocess.run", side_effect=boom):
            result = cisco_bridge.scan_path("/tmp/x", analyzers=["yara"], timeout=1)
        self.assertFalse(result["ok"])
        self.assertTrue(any("timed out" in note for note in result["notes"]))

    def test_scan_handles_missing_binary(self):
        def boom(args, **kwargs):
            raise FileNotFoundError(args[0])

        with patch("mcp_guard.cisco_bridge.subprocess.run", side_effect=boom):
            result = cisco_bridge.scan_path("/tmp/x", analyzers=["yara"])
        self.assertFalse(result["ok"])
        self.assertTrue(any("not found" in note for note in result["notes"]))

    def test_default_analyzers_respects_llm_key(self):
        self.assertEqual(cisco_bridge.default_analyzers(env={}), ["yara"])
        self.assertEqual(
            cisco_bridge.default_analyzers(env={"MCP_SCANNER_LLM_API_KEY": "k"}),
            ["yara", "behavioral", "llm"],
        )

    def test_is_available_reports_path(self):
        with patch("mcp_guard.cisco_bridge.shutil.which", return_value="/usr/bin/mcp-scanner"):
            self.assertTrue(cisco_bridge.is_available())
        with patch("mcp_guard.cisco_bridge.shutil.which", return_value=None):
            self.assertFalse(cisco_bridge.is_available())


class CiscoThreatMapShareTests(unittest.TestCase):
    def test_reporting_imports_shared_threat_map(self):
        from runner import reporting

        self.assertIs(reporting.CISCO_THREAT_MAP, cisco_bridge.CISCO_THREAT_MAP)


if __name__ == "__main__":
    unittest.main()
