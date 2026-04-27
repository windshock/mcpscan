"""MCP Guard Policy Engine — evaluates findings against policy rules."""
from __future__ import annotations
import yaml
from pathlib import Path
from typing import Optional


DEFAULT_POLICY = {
    "rules": [
        {
            "pattern": "command_exec",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "tool_poisoning",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "BLOCK"},
        },
        {
            "pattern": "authless_endpoint",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "unrestricted_file_read",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "unrestricted_file_write",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "BLOCK"},
        },
        {
            "pattern": "env_exposure",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "ssrf",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "cors_misconfiguration",
            "verdict": "CONDITIONAL",
            "environments": {"production": "CONDITIONAL", "development": "ALLOW"},
        },
        {
            "pattern": "allowlist_bypass",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "hidden_transport",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "BLOCK"},
        },
        {
            "pattern": "config_to_execution",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "BLOCK"},
        },
        {
            "pattern": "runtime_only_danger",
            "verdict": "CONDITIONAL",
            "environments": {"production": "CONDITIONAL", "development": "ALLOW"},
        },
        {
            "pattern": "ai_config_injection",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
    ],
    "defaults": {
        "unknown_pattern": "CONDITIONAL",
        "no_findings": "ALLOW",
    },
}


class PolicyEngine:
    def __init__(self, policy_file: Optional[str] = None):
        if policy_file and Path(policy_file).exists():
            with open(policy_file) as f:
                self.policy = yaml.safe_load(f)
        else:
            self.policy = DEFAULT_POLICY

        self.rules = {r["pattern"]: r for r in self.policy.get("rules", [])}
        self.defaults = self.policy.get("defaults", {})

    def evaluate(self, scan_result: dict, environment: str = "production") -> dict:
        """Evaluate scan findings against policy rules."""
        findings = scan_result.get("findings", [])
        verdicts = []
        recommendations = []

        for finding in findings:
            pattern_id = finding.get("pattern_id", "")
            rule = self.rules.get(pattern_id)

            if rule:
                env_verdict = rule.get("environments", {}).get(environment, rule.get("verdict", "CONDITIONAL"))
                verdicts.append({
                    "pattern": pattern_id,
                    "severity": finding.get("severity", "UNKNOWN"),
                    "verdict": env_verdict,
                    "indicator": finding.get("matched_indicator", ""),
                })
            else:
                verdicts.append({
                    "pattern": pattern_id,
                    "severity": finding.get("severity", "UNKNOWN"),
                    "verdict": self.defaults.get("unknown_pattern", "CONDITIONAL"),
                    "indicator": finding.get("matched_indicator", ""),
                })

        # Overall verdict: most restrictive wins
        overall = self._compute_overall_verdict(verdicts)

        # Generate recommendations from pattern catalog
        from .patterns import get_pattern
        for v in verdicts:
            pattern = get_pattern(v["pattern"])
            if pattern and pattern.get("recommendation"):
                recommendations.append({
                    "pattern": v["pattern"],
                    "recommendation": pattern["recommendation"],
                })

        return {
            "target": scan_result.get("target", "unknown"),
            "risk": scan_result.get("risk", "NONE"),
            "overall_verdict": overall,
            "environment": environment,
            "verdicts": verdicts,
            "recommendations": recommendations,
        }

    def _compute_overall_verdict(self, verdicts: list) -> str:
        if not verdicts:
            return self.defaults.get("no_findings", "ALLOW")

        priority = {"BLOCK": 3, "CONDITIONAL": 2, "ALLOW": 1}
        highest = "ALLOW"
        for v in verdicts:
            vd = v.get("verdict", "CONDITIONAL")
            if priority.get(vd, 0) > priority.get(highest, 0):
                highest = vd
        return highest

    def format_output(self, evaluation: dict) -> str:
        """Format evaluation as human-readable output."""
        lines = []
        lines.append(f"Target: {evaluation['target']}")
        lines.append(f"Risk: {evaluation['risk']}")
        lines.append(f"Policy: {evaluation['overall_verdict']} for {evaluation['environment']}")
        lines.append("")

        if evaluation["verdicts"]:
            lines.append("Findings:")
            for v in evaluation["verdicts"]:
                icon = {"BLOCK": "🚫", "CONDITIONAL": "⚠️", "ALLOW": "✅"}.get(v["verdict"], "?")
                lines.append(f"  {icon} [{v['severity']}] {v['pattern']}: {v['verdict']}")
                lines.append(f"     Indicator: {v['indicator']}")

        if evaluation["recommendations"]:
            lines.append("")
            lines.append("Recommendations:")
            for r in evaluation["recommendations"]:
                lines.append(f"  → {r['pattern']}: {r['recommendation']}")

        return "\n".join(lines)
