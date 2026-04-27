import json
import tempfile
import unittest
from pathlib import Path

from runner.reporting import generate_lab_outputs, generate_ox_live_outputs, generate_ox_live_report, normalize_ox_live


class ReportingTest(unittest.TestCase):
    def test_normalize_ox_live(self):
        raw = {
            "product_id": "langflow",
            "product_name": "LangFlow",
            "timestamp": "2026-04-21T00:00:00+00:00",
            "source_url": "https://github.com/langflow-ai/langflow",
            "launch_kind": "docker_image",
            "launch_status": "success",
            "health_status": "reachable",
            "scan_status": "success",
            "scan_result": {"findings": ["config_to_execution"]},
            "failure_reason": None,
            "notes": [],
            "evidence": {"launch_logs": "/tmp/langflow.log"},
        }
        expected = {
            "expected_launch_success": True,
            "expected_health_status": "reachable",
            "expected_scan_status": "success",
            "expected_findings": ["config_to_execution"],
            "optional_findings": ["allowlist_bypass"],
        }

        normalized = normalize_ox_live(raw, expected)

        self.assertEqual(normalized["true_positives"], ["config_to_execution"])
        self.assertEqual(normalized["false_positives"], [])
        self.assertTrue(normalized["launch_matches_expectation"])
        self.assertTrue(normalized["health_matches_expectation"])

    def test_generate_ox_live_report(self):
        normalized = [
            {
                "target": "langflow",
                "product_name": "LangFlow",
                "target_type": "ox_live",
                "scanner_name": "mcp-guard-live",
                "source_url": "https://github.com/langflow-ai/langflow",
                "launch_kind": "docker_image",
                "launch_status": "success",
                "health_status": "reachable",
                "scan_status": "success",
                "failure_reason": None,
                "expected_findings": ["config_to_execution"],
                "optional_findings": [],
                "detected_findings": ["config_to_execution"],
                "true_positives": ["config_to_execution"],
                "missed_findings": [],
                "false_positives": [],
                "notes": [],
                "evidence": {"launch_logs": "/tmp/langflow.log"},
            }
        ]

        report = generate_ox_live_report(normalized)

        self.assertIn("# OX Live Validation Report", report)
        self.assertIn("LangFlow (langflow)", report)
        self.assertIn("TP:1/FP:0/FN:0", report)

    def test_generate_lab_outputs_marks_invalid_and_skipped_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            raw_dir = results_dir / "raw"
            (raw_dir / "mcpscan").mkdir(parents=True)
            (raw_dir / "cisco-scanner").mkdir(parents=True)
            (raw_dir / "mcp-guard").mkdir(parents=True)

            (raw_dir / "mcpscan" / "demo.json").write_text("")
            (raw_dir / "cisco-scanner" / "demo.json").write_text(
                json.dumps(
                    {
                        "status": "skipped",
                        "reason": "path mode unsupported",
                        "target": "/servers/demo",
                    }
                )
            )
            (raw_dir / "mcp-guard" / "demo.json").write_text(
                json.dumps(
                    {
                        "status": "success",
                        "findings": ["command_exec"],
                        "policy_verdict": "BLOCK",
                    }
                )
            )

            expected_file = Path(tmpdir) / "expected-findings.json"
            expected_file.write_text(
                json.dumps(
                    {
                        "servers": {
                            "demo": {
                                "expected_findings": ["command_exec"],
                                "expected_false_positives": [],
                            }
                        }
                    }
                )
            )

            normalized = generate_lab_outputs(results_dir, expected_file)

            mcpscan_result = next(result for result in normalized if result["scanner_name"] == "mcpscan")
            cisco_result = next(result for result in normalized if result["scanner_name"] == "cisco-scanner")
            guard_result = next(result for result in normalized if result["scanner_name"] == "mcp-guard")

            self.assertEqual(mcpscan_result["status"], "failed")
            self.assertIn("empty raw result", mcpscan_result["error"])
            self.assertEqual(cisco_result["status"], "skipped")
            self.assertEqual(cisco_result["error"], "path mode unsupported")
            self.assertEqual(guard_result["status"], "success")
            self.assertEqual(guard_result["true_positives"], ["command_exec"])

            comparison_report = (results_dir / "report" / "comparison.md").read_text()
            self.assertIn("FAIL", comparison_report)
            self.assertIn("SKIP", comparison_report)

    def test_generate_lab_outputs_accepts_mcpscan_list_payload(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            raw_dir = results_dir / "raw"
            (raw_dir / "mcpscan").mkdir(parents=True)
            (raw_dir / "cisco-scanner").mkdir(parents=True)
            (raw_dir / "mcp-guard").mkdir(parents=True)

            (raw_dir / "mcpscan" / "demo.json").write_text(
                json.dumps([{"rule_id": "command_exec"}])
            )
            (raw_dir / "cisco-scanner" / "demo.json").write_text(
                json.dumps({"status": "skipped", "reason": "path mode unsupported"})
            )
            (raw_dir / "mcp-guard" / "demo.json").write_text(
                json.dumps({"status": "success", "findings": ["command_exec"]})
            )

            expected_file = Path(tmpdir) / "expected-findings.json"
            expected_file.write_text(
                json.dumps(
                    {
                        "servers": {
                            "demo": {
                                "expected_findings": ["command_exec"],
                                "expected_false_positives": [],
                            }
                        }
                    }
                )
            )

            normalized = generate_lab_outputs(results_dir, expected_file)
            mcpscan_result = next(result for result in normalized if result["scanner_name"] == "mcpscan")

            self.assertEqual(mcpscan_result["status"], "success")
            self.assertEqual(mcpscan_result["true_positives"], ["command_exec"])

    def test_generate_ox_live_outputs_marks_missing_raw_results(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            expected_file = Path(tmpdir) / "ox-live-expected.json"
            expected_file.write_text(
                json.dumps(
                    {
                        "products": {
                            "langflow": {
                                "expected_launch_success": True,
                                "expected_health_status": "reachable",
                                "expected_scan_status": "success",
                                "expected_findings": ["config_to_execution"],
                            }
                        }
                    }
                )
            )

            normalized = generate_ox_live_outputs(results_dir, expected_file)

            self.assertEqual(len(normalized), 1)
            self.assertEqual(normalized[0]["target"], "langflow")
            self.assertEqual(normalized[0]["failure_reason"], "raw_result_unavailable")
            self.assertEqual(normalized[0]["scan_status"], "failed")


if __name__ == "__main__":
    unittest.main()
