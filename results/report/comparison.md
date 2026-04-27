# MCP Scanner Benchmark Report

Generated: 2026-04-22T23:17:36.729865+00:00


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

- **True Positives**: 0
- **False Positives**: 0
- **False Negatives (Missed)**: 24
- **Total Expected Findings**: 24
- **Successful Scans**: 0
- **Skipped Scans**: 11
- **Failed Scans**: 0
- **Recall**: 0.0%

  SKIP **normal-realistic**: TP=0 FP=0 FN=0 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **normal-strict**: TP=0 FP=0 FN=0 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **normal-tricky**: TP=0 FP=0 FN=0 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **vuln-allowlist-bypass**: TP=0 FP=0 FN=2 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **vuln-authless**: TP=0 FP=0 FN=4 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **vuln-config-exec**: TP=0 FP=0 FN=3 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **vuln-exec**: TP=0 FP=0 FN=2 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **vuln-filesystem**: TP=0 FP=0 FN=4 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **vuln-hidden-transport**: TP=0 FP=0 FN=3 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **vuln-network**: TP=0 FP=0 FN=3 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint
  SKIP **vuln-runtime-only**: TP=0 FP=0 FN=3 Error=cisco-mcp-scanner does not support source-path scanning; use remote/stdio/config modes against a running endpoint

## mcp-guard

- **True Positives**: 13
- **False Positives**: 6
- **False Negatives (Missed)**: 11
- **Total Expected Findings**: 24
- **Successful Scans**: 11
- **Skipped Scans**: 0
- **Failed Scans**: 0
- **Recall**: 54.2%
- **Precision**: 68.4%

  WARN **normal-realistic**: TP=0 FP=1 FN=0
  OK **normal-strict**: TP=0 FP=0 FN=0
  OK **normal-tricky**: TP=0 FP=0 FN=0
  WARN **vuln-allowlist-bypass**: TP=1 FP=1 FN=1
  WARN **vuln-authless**: TP=3 FP=0 FN=1
  WARN **vuln-config-exec**: TP=2 FP=1 FN=1
  OK **vuln-exec**: TP=2 FP=0 FN=0
  WARN **vuln-filesystem**: TP=3 FP=0 FN=1
  WARN **vuln-hidden-transport**: TP=1 FP=0 FN=2
  WARN **vuln-network**: TP=1 FP=1 FN=2
  WARN **vuln-runtime-only**: TP=0 FP=2 FN=3

## Cross-Scanner Comparison

| Server | mcpscan | cisco-scanner | mcp-guard |
|--------|---------|---------------|-----------|
| normal-realistic | OK TP:0 FP:0 FN:0 | SKIP TP:0 FP:0 FN:0 | WARN TP:0 FP:1 FN:0 |
| normal-strict | OK TP:0 FP:0 FN:0 | SKIP TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 |
| normal-tricky | OK TP:0 FP:0 FN:0 | SKIP TP:0 FP:0 FN:0 | OK TP:0 FP:0 FN:0 |
| vuln-allowlist-bypass | WARN TP:0 FP:1 FN:2 | SKIP TP:0 FP:0 FN:2 | WARN TP:1 FP:1 FN:1 |
| vuln-authless | WARN TP:0 FP:0 FN:4 | SKIP TP:0 FP:0 FN:4 | WARN TP:3 FP:0 FN:1 |
| vuln-config-exec | WARN TP:0 FP:1 FN:3 | SKIP TP:0 FP:0 FN:3 | WARN TP:2 FP:1 FN:1 |
| vuln-exec | WARN TP:0 FP:1 FN:2 | SKIP TP:0 FP:0 FN:2 | OK TP:2 FP:0 FN:0 |
| vuln-filesystem | WARN TP:0 FP:0 FN:4 | SKIP TP:0 FP:0 FN:4 | WARN TP:3 FP:0 FN:1 |
| vuln-hidden-transport | WARN TP:0 FP:0 FN:3 | SKIP TP:0 FP:0 FN:3 | WARN TP:1 FP:0 FN:2 |
| vuln-network | WARN TP:0 FP:0 FN:3 | SKIP TP:0 FP:0 FN:3 | WARN TP:1 FP:1 FN:2 |
| vuln-runtime-only | WARN TP:0 FP:1 FN:3 | SKIP TP:0 FP:0 FN:3 | WARN TP:0 FP:2 FN:3 |