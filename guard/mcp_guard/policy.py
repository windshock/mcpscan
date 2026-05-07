"""MCP Guard Policy Engine — evaluates findings against policy rules."""
from __future__ import annotations

import logging
import yaml
from pathlib import Path
from typing import Optional

_logger = logging.getLogger("mcp_guard.policy")


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
        {
            "pattern": "command_exec_via_args",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "remote_config_loading",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "BLOCK"},
        },
        {
            "pattern": "internal_metadata_exposure",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "connector_metadata_exposure",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "BLOCK"},
        },
        {
            "pattern": "config_injection",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "BLOCK"},
        },
        {
            "pattern": "excessive_permissions",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "conditional_command_exec",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "static_analysis_bypass",
            "verdict": "BLOCK",
            "environments": {"production": "BLOCK", "development": "CONDITIONAL"},
        },
        {
            "pattern": "unrestricted_directory_listing",
            "verdict": "CONDITIONAL",
            "environments": {"production": "CONDITIONAL", "development": "ALLOW"},
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
            source = finding.get("source") or "mcp-guard"
            severity = finding.get("severity", "UNKNOWN")
            confidence = (finding.get("confidence") or "high").lower()

            # Cisco findings flag confirmed-malicious authoring (not a
            # capability that depends on environment), so HIGH/CRITICAL
            # cisco-* findings escalate to BLOCK regardless of policy rules.
            if source.startswith("cisco-") and str(severity).upper() in ("HIGH", "CRITICAL"):
                _logger.debug(
                    "policy: cisco-source HIGH/CRITICAL escalates to BLOCK (pattern=%s source=%s)",
                    pattern_id, source,
                )
                verdicts.append({
                    "pattern": pattern_id,
                    "severity": severity,
                    "verdict": "BLOCK",
                    "indicator": finding.get("matched_indicator", ""),
                    "source": source,
                })
                continue

            if rule:
                env_verdict = rule.get("environments", {}).get(environment, rule.get("verdict", "CONDITIONAL"))
            else:
                env_verdict = self.defaults.get("unknown_pattern", "CONDITIONAL")

            # Confidence demotion: schema-only or other low-confidence matches
            # (e.g. "tool has path param" without seeing server-side validation)
            # never reach BLOCK. They surface as CONDITIONAL — operator should
            # confirm with a code review or static scan.
            if confidence == "low" and env_verdict == "BLOCK":
                _logger.debug(
                    "policy: low-confidence finding demoted BLOCK -> CONDITIONAL (pattern=%s)",
                    pattern_id,
                )
                env_verdict = "CONDITIONAL"

            verdicts.append({
                "pattern": pattern_id,
                "severity": severity,
                "verdict": env_verdict,
                "indicator": finding.get("matched_indicator", ""),
                "source": source,
                "confidence": confidence,
            })

        # Overall verdict: most restrictive wins
        overall = self._compute_overall_verdict(verdicts)
        _logger.info(
            "policy: %d findings -> overall=%s in %s env",
            len(verdicts), overall, environment,
        )

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
        """Format evaluation as human-readable output, grouped by source.

        mcp-guard findings show capability-based vulnerabilities.
        cisco-* findings show malicious-intent / supply-chain payload patterns.
        Each section is omitted when empty so the existing single-tool output
        stays unchanged.
        """
        lines = []
        lines.append(f"Target: {evaluation['target']}")
        lines.append(f"Risk: {evaluation['risk']}")
        lines.append(f"Policy: {evaluation['overall_verdict']} for {evaluation['environment']}")
        lines.append("")

        if evaluation["verdicts"]:
            sections: list[tuple[str, list[dict]]] = [
                ("Vulnerabilities (mcp-guard)", []),
                ("Malicious patterns (cisco)", []),
            ]
            for v in evaluation["verdicts"]:
                source = v.get("source") or "mcp-guard"
                bucket = 1 if source.startswith("cisco-") else 0
                sections[bucket][1].append(v)

            for title, group in sections:
                if not group:
                    continue
                lines.append(f"{title}:")
                for v in group:
                    icon = {"BLOCK": "🚫", "CONDITIONAL": "⚠️", "ALLOW": "✅"}.get(v["verdict"], "?")
                    suffix = f" via {v['source']}" if v.get("source") and v["source"] != "mcp-guard" else ""
                    lines.append(f"  {icon} [{v['severity']}] {v['pattern']}: {v['verdict']}{suffix}")
                    lines.append(f"     Indicator: {v['indicator']}")
                lines.append("")

        if evaluation["recommendations"]:
            lines.append("Recommendations:")
            seen = set()
            for r in evaluation["recommendations"]:
                key = (r["pattern"], r["recommendation"])
                if key in seen:
                    continue
                seen.add(key)
                lines.append(f"  → {r['pattern']}: {r['recommendation']}")

        return "\n".join(lines).rstrip()
