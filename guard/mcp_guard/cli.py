"""MCP Guard CLI — command-line interface for MCP security guardrail."""
import argparse
import json
import sys

from .discovery import (
    discover_targets,
    format_discovery_text,
    select_candidate,
)
from .policy import PolicyEngine
from .scanner import scan_config, scan_endpoint, scan_path


def main():
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="MCP Security Guardrail — scan MCP servers and configs for security issues",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan an MCP server or config")
    scan_parser.add_argument("--path", "-p", help="Path to MCP server source code")
    scan_parser.add_argument("--config", "-c", help="Path or string of MCP config JSON")
    scan_parser.add_argument("--endpoint", "-e", help="MCP server endpoint URL")
    scan_parser.add_argument("--auto", action="store_true", help="Auto-select the highest-ranked discovered target")
    scan_parser.add_argument("--policy", help="Path to custom policy YAML file")
    scan_parser.add_argument("--env", default="production", choices=["production", "development"], help="Target environment")
    scan_parser.add_argument("--output", "-o", choices=["text", "json"], default="text", help="Output format")

    discover_parser = subparsers.add_parser("discover", help="Discover likely MCP targets on this macOS host")
    discover_parser.add_argument("--output", "-o", choices=["text", "json"], default="text", help="Output format")

    # policy subcommand
    policy_parser = subparsers.add_parser("policy", help="Show or validate policy configuration")
    policy_parser.add_argument("--policy", help="Path to policy YAML file")
    policy_parser.add_argument("--show", action="store_true", help="Show current policy rules")

    # catalog subcommand
    catalog_parser = subparsers.add_parser("catalog", help="Show the vulnerability pattern catalog")
    catalog_parser.add_argument("--pattern", help="Show details for a specific pattern ID")

    args = parser.parse_args()

    if args.command == "scan":
        _handle_scan(args)
    elif args.command == "discover":
        _handle_discover(args)
    elif args.command == "policy":
        _handle_policy(args)
    elif args.command == "catalog":
        _handle_catalog(args)
    else:
        parser.print_help()


def _handle_scan(args):
    policy_engine = PolicyEngine(args.policy)

    if args.path:
        scan_result = scan_path(args.path)
    elif args.config:
        config_str = args.config
        if config_str.startswith("{") or config_str.startswith("["):
            pass  # inline JSON
        else:
            try:
                with open(config_str) as f:
                    config_str = f.read()
            except FileNotFoundError:
                pass
        scan_result = scan_config(config_str)
    elif args.endpoint:
        scan_result = scan_endpoint(args.endpoint)
    else:
        try:
            discovery = discover_targets()
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        candidates = discovery.get("candidates", [])
        if not candidates:
            docker_error = discovery.get("docker_error")
            if docker_error:
                print(f"Error: no MCP targets discovered ({docker_error})", file=sys.stderr)
            else:
                print("Error: no MCP targets discovered", file=sys.stderr)
            sys.exit(1)
        try:
            chosen = select_candidate(candidates, auto=args.auto)
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        scan_result = _scan_discovered_candidate(chosen)

    if "error" in scan_result:
        print(f"Error: {scan_result['error']}", file=sys.stderr)
        sys.exit(1)

    evaluation = policy_engine.evaluate(scan_result, environment=args.env)

    if args.output == "json":
        # Add policy_verdict to scan result for normalization
        scan_result["policy_verdict"] = evaluation["overall_verdict"]
        scan_result["findings"] = scan_result.get("findings", [])
        # Normalize findings for JSON output
        normalized_findings = []
        for f in scan_result.get("findings", []):
            normalized_findings.append(f.get("pattern_id", f.get("pattern_name", "unknown")))
        output = {
            "target": scan_result["target"],
            "risk": scan_result["risk"],
            "policy_verdict": evaluation["overall_verdict"],
            "environment": args.env,
            "findings": normalized_findings,
            "verdicts": evaluation["verdicts"],
            "recommendations": evaluation["recommendations"],
        }
        if scan_result.get("notes"):
            output["notes"] = scan_result["notes"]
        if scan_result.get("probe_summary"):
            output["probe_summary"] = scan_result["probe_summary"]
        print(json.dumps(output, indent=2))
    else:
        print(policy_engine.format_output(evaluation))
        if scan_result.get("notes"):
            print("")
            print("Notes:")
            for note in scan_result["notes"]:
                print(f"  - {note}")

    # Exit code: 1 if BLOCK, 0 otherwise
    if evaluation["overall_verdict"] == "BLOCK":
        sys.exit(1)


def _handle_discover(args):
    try:
        discovery = discover_targets()
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.output == "json":
        print(json.dumps(discovery, indent=2))
    else:
        print(format_discovery_text(discovery))


def _scan_discovered_candidate(candidate: dict) -> dict:
    kind = candidate.get("kind")
    target = candidate.get("target")
    if kind == "path":
        return scan_path(target)
    if kind == "config":
        with open(target) as f:
            config_text = f.read()
        return scan_config(config_text)
    if kind == "endpoint":
        if not candidate.get("scan_ready", True):
            return {"error": f"Candidate is not directly scannable from this host: {target}"}
        return scan_endpoint(target)
    return {"error": f"Unsupported discovered candidate kind: {kind}"}


def _handle_policy(args):
    policy_engine = PolicyEngine(args.policy)

    if args.show:
        print("# Current Policy Rules\n")
        for pattern_id, rule in policy_engine.rules.items():
            print(f"## {pattern_id}")
            print(f"  Default verdict: {rule.get('verdict', 'N/A')}")
            envs = rule.get("environments", {})
            for env, verdict in envs.items():
                print(f"  {env}: {verdict}")
            print()
    else:
        print("Use --show to display current policy rules")


def _handle_catalog(args):
    from .patterns import get_pattern, get_all_patterns

    if args.pattern:
        pattern = get_pattern(args.pattern)
        if pattern:
            print(f"# {pattern['name']} ({pattern['id']})")
            print(f"Severity: {pattern['severity']}")
            print(f"Policy: {pattern['policy']}")
            print(f"\nDescription: {pattern['description']}")
            print(f"\nIndicators:")
            for ind in pattern["indicators"]:
                print(f"  - {ind}")
            print(f"\nRecommendation: {pattern['recommendation']}")
        else:
            print(f"Pattern '{args.pattern}' not found")
    else:
        patterns = get_all_patterns()
        print("# MCP Security Pattern Catalog\n")
        print(f"{'ID':<8} {'Pattern':<35} {'Severity':<10} {'Policy':<12}")
        print("-" * 70)
        for pid, p in patterns.items():
            print(f"{p['id']:<8} {p['name']:<35} {p['severity']:<10} {p['policy']:<12}")


if __name__ == "__main__":
    main()
