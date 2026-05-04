# MCP Scanner Benchmark Report

Generated: 2026-05-04T05:20:19.005718+00:00


## mcpscan

- **True Positives**: 0
- **False Positives**: 4
- **False Negatives (Missed)**: 24
- **Total Expected Findings**: 24
- **Successful Scans**: 11
- **Skipped Scans**: 0
- **Failed Scans**: 0
- **Recall**: 0.0%
- **Precision**: 0.0%

  OK **normal-realistic**: TP=0 FP=0 FN=0
  OK **normal-strict**: TP=0 FP=0 FN=0
  OK **normal-tricky**: TP=0 FP=0 FN=0
  WARN **vuln-allowlist-bypass**: TP=0 FP=1 FN=2
  WARN **vuln-authless**: TP=0 FP=0 FN=4
  WARN **vuln-config-exec**: TP=0 FP=1 FN=3
  WARN **vuln-exec**: TP=0 FP=1 FN=2
  WARN **vuln-filesystem**: TP=0 FP=0 FN=4
  WARN **vuln-hidden-transport**: TP=0 FP=0 FN=3
  WARN **vuln-network**: TP=0 FP=0 FN=3
  WARN **vuln-runtime-only**: TP=0 FP=1 FN=3

## cisco-scanner

- **True Positives**: 1
- **False Positives**: 1
- **False Negatives (Missed)**: 23
- **Total Expected Findings**: 24
- **Successful Scans**: 8
- **Skipped Scans**: 0
- **Failed Scans**: 3
- **Recall**: 4.2%
- **Precision**: 50.0%

  OK **normal-realistic**: TP=0 FP=0 FN=0
  OK **normal-strict**: TP=0 FP=0 FN=0
  OK **normal-tricky**: TP=0 FP=0 FN=0
  FAIL **vuln-allowlist-bypass**: TP=0 FP=0 FN=2 Error=cisco-scanner produced invalid JSON output
  WARN **vuln-authless**: TP=1 FP=0 FN=3
  WARN **vuln-config-exec**: TP=0 FP=0 FN=3
  WARN **vuln-exec**: TP=0 FP=0 FN=2
  WARN **vuln-filesystem**: TP=0 FP=1 FN=4
  FAIL **vuln-hidden-transport**: TP=0 FP=0 FN=3 Error=cisco-scanner produced invalid JSON output
  FAIL **vuln-network**: TP=0 FP=0 FN=3 Error=cisco-scanner produced invalid JSON output
  WARN **vuln-runtime-only**: TP=0 FP=0 FN=3

## mcp-guard

- **True Positives**: 23
- **False Positives**: 0
- **False Negatives (Missed)**: 1
- **Total Expected Findings**: 24
- **Successful Scans**: 11
- **Skipped Scans**: 0
- **Failed Scans**: 0
- **Recall**: 95.8%
- **Precision**: 100.0%

  OK **normal-realistic**: TP=0 FP=0 FN=0
  OK **normal-strict**: TP=0 FP=0 FN=0
  OK **normal-tricky**: TP=0 FP=0 FN=0
  OK **vuln-allowlist-bypass**: TP=2 FP=0 FN=0
  WARN **vuln-authless**: TP=3 FP=0 FN=1
  OK **vuln-config-exec**: TP=3 FP=0 FN=0
  OK **vuln-exec**: TP=2 FP=0 FN=0
  OK **vuln-filesystem**: TP=4 FP=0 FN=0
  OK **vuln-hidden-transport**: TP=3 FP=0 FN=0
  OK **vuln-network**: TP=3 FP=0 FN=0
  OK **vuln-runtime-only**: TP=3 FP=0 FN=0

## mcp-guard-endpoint

- **True Positives**: 13
- **False Positives**: 0
- **False Negatives (Missed)**: 11
- **Total Expected Findings**: 24
- **Successful Scans**: 11
- **Skipped Scans**: 0
- **Failed Scans**: 0
- **Recall**: 54.2%
- **Precision**: 100.0%

  OK **normal-realistic**: TP=0 FP=0 FN=0
  OK **normal-strict**: TP=0 FP=0 FN=0
  OK **normal-tricky**: TP=0 FP=0 FN=0
  WARN **vuln-allowlist-bypass**: TP=0 FP=0 FN=2
  OK **vuln-authless**: TP=4 FP=0 FN=0
  WARN **vuln-config-exec**: TP=2 FP=0 FN=1
  OK **vuln-exec**: TP=2 FP=0 FN=0
  OK **vuln-filesystem**: TP=4 FP=0 FN=0
  WARN **vuln-hidden-transport**: TP=0 FP=0 FN=3
  WARN **vuln-network**: TP=1 FP=0 FN=2
  WARN **vuln-runtime-only**: TP=0 FP=0 FN=3

## Cross-Scanner Comparison

| Server | mcpscan | cisco-scanner | mcp-guard | mcp-guard-endpoint |
|--------|---------|---------------|-----------|--------------------|
| normal-realistic | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 |
| normal-strict | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 |
| normal-tricky | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 |
| vuln-allowlist-bypass | WARN TP:0 FP:1 FN:2 | FAIL TP:0 FP:0 FN:2 | OK TP:2 FP:0 FN:0 | WARN TP:0 FP:0 FN:2 |
| vuln-authless | WARN TP:0 FP:0 FN:4 | WARN TP:1 FP:0 FN:3 | WARN TP:3 FP:0 FN:1 | OK TP:4 FP:0 FN:0 |
| vuln-config-exec | WARN TP:0 FP:1 FN:3 | WARN TP:0 FP:0 FN:3 | OK TP:3 FP:0 FN:0 | WARN TP:2 FP:0 FN:1 |
| vuln-exec | WARN TP:0 FP:1 FN:2 | WARN TP:0 FP:0 FN:2 | OK TP:2 FP:0 FN:0 | OK TP:2 FP:0 FN:0 |
| vuln-filesystem | WARN TP:0 FP:0 FN:4 | WARN TP:0 FP:1 FN:4 | OK TP:4 FP:0 FN:0 | OK TP:4 FP:0 FN:0 |
| vuln-hidden-transport | WARN TP:0 FP:0 FN:3 | FAIL TP:0 FP:0 FN:3 | OK TP:3 FP:0 FN:0 | WARN TP:0 FP:0 FN:3 |
| vuln-network | WARN TP:0 FP:0 FN:3 | FAIL TP:0 FP:0 FN:3 | OK TP:3 FP:0 FN:0 | WARN TP:1 FP:0 FN:2 |
| vuln-runtime-only | WARN TP:0 FP:1 FN:3 | WARN TP:0 FP:0 FN:3 | OK TP:3 FP:0 FN:0 | WARN TP:0 FP:0 FN:3 |

## mcp-guard combined (source ∪ endpoint)

- **True Positives**: 24
- **False Positives**: 0
- **False Negatives (Missed)**: 0
- **Total Expected Findings**: 24
- **Recall**: 100.0%
- **Precision**: 100.0%

  OK **normal-realistic**: TP=0 FP=0 FN=0
  OK **normal-strict**: TP=0 FP=0 FN=0
  OK **normal-tricky**: TP=0 FP=0 FN=0
  OK **vuln-allowlist-bypass**: TP=2 FP=0 FN=0
  OK **vuln-authless**: TP=4 FP=0 FN=0
  OK **vuln-config-exec**: TP=3 FP=0 FN=0
  OK **vuln-exec**: TP=2 FP=0 FN=0
  OK **vuln-filesystem**: TP=4 FP=0 FN=0
  OK **vuln-hidden-transport**: TP=3 FP=0 FN=0
  OK **vuln-network**: TP=3 FP=0 FN=0
  OK **vuln-runtime-only**: TP=3 FP=0 FN=0