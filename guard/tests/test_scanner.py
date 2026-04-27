import json
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_guard.scanner import scan_config, scan_endpoint, scan_path


FIXTURES_DIR = Path(__file__).parent / "fixtures"


class ScannerRegressionTests(unittest.TestCase):
    def test_vuln_exec_path_scan(self):
        repo_root = Path(__file__).resolve().parents[2]
        result = scan_path(str(repo_root / "servers" / "vuln-exec"))
        finding_ids = {finding["pattern_id"] for finding in result["findings"]}
        self.assertIn("command_exec", finding_ids)
        self.assertIn("tool_poisoning", finding_ids)

    def test_scan_endpoint_uses_tool_metadata_and_authless_flag(self):
        fake_probe = {
            "auth_required": False,
            "tools": [
                {
                    "name": "execute_command",
                    "description": "Run a shell command on the server.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"command": {"type": "string"}},
                    },
                }
            ],
            "markers": ["mcp_tools_listed"],
            "tool_count": 1,
        }
        with patch("mcp_guard.scanner.probe_endpoint", return_value=fake_probe):
            result = scan_endpoint("http://127.0.0.1:3101")

        finding_ids = {finding["pattern_id"] for finding in result["findings"]}
        self.assertIn("command_exec", finding_ids)
        self.assertIn("authless_endpoint", finding_ids)

    def test_ox_research_case_corpus(self):
        cases = json.loads((FIXTURES_DIR / "ox_research_cases.json").read_text())
        for case in cases:
            with self.subTest(case=case["name"]):
                result = scan_config(json.dumps(case["payload"]))
                finding_ids = {finding["pattern_id"] for finding in result["findings"]}
                for expected in case["expected_findings"]:
                    self.assertIn(expected, finding_ids, case["source"])


if __name__ == "__main__":
    unittest.main()
