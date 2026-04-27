from pathlib import Path
import re
import sys


def main() -> int:
    root = Path(sys.argv[1])
    path = root / "src/mcpscan/core/runner.py"
    text = path.read_text()

    updated = re.sub(
        r"^(\s*simple_results:.*)$",
        r"\1\n    results: List[Dict[str, Any]] = []",
        text,
        count=1,
        flags=re.MULTILINE,
    )
    updated = re.sub(
        r"^(\s*)if monitor_code:\s*$",
        r"\1if True:",
        updated,
        count=1,
        flags=re.MULTILINE,
    )
    updated = re.sub(
        r"^(\s*)if high_risk_files:\s*$",
        r"\1if high_risk_files and monitor_code:",
        updated,
        count=1,
        flags=re.MULTILINE,
    )
    if updated == text:
        raise SystemExit("mcpscan patch anchor not found")
    path.write_text(updated)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
