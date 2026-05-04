# Stage 1: Build mcp-guard (non-editable so site-packages is self-contained)
FROM python:3.12-slim AS mcp-guard-builder
WORKDIR /build
COPY guard/ ./guard-src/
RUN pip install --no-cache-dir pyyaml && \
    cd guard-src && \
    pip install --no-cache-dir .

# Stage 2: Runner with all scanners
FROM python:3.12-slim
WORKDIR /app

COPY scanners/mcpscan/patch_mcpscan_runner.py /tmp/patch_mcpscan_runner.py

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy mcp-guard FIRST. The builder stage's site-packages dir is bulk-copied,
# which would otherwise wipe out anything we install in this stage before this
# step (e.g. setuptools). Doing the copy first preserves later installs.
COPY --from=mcp-guard-builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=mcp-guard-builder /usr/local/bin/mcp-guard /usr/local/bin/mcp-guard

# Install MCPScan. semgrep on Python 3.12 still imports pkg_resources via
# opentelemetry instrumentation, so setuptools must be installed explicitly.
# MCPScan also declares semgrep in its own dependencies, which causes slow
# resolver backtracking; install its remaining runtime deps up front and use
# --no-deps for the editable package install.
RUN pip install --no-cache-dir \
    "setuptools<81" \
    semgrep \
    "typer>=0.12" \
    "rich>=13.7" \
    "tqdm>=4.66" \
    "gitpython>=3.1" \
    python-dotenv \
    openai && \
    git clone https://github.com/antgroup/MCPScan.git /opt/mcpscan && \
    python /tmp/patch_mcpscan_runner.py /opt/mcpscan && \
    pip install --no-cache-dir --no-deps -e /opt/mcpscan

# Install Cisco mcp-scanner. uv tool installs into /root/.local/bin, so expose
# that on PATH for downstream scripts.
ENV PATH="/root/.local/bin:${PATH}"
RUN pip install --no-cache-dir uv && \
    uv tool install --python 3.13 cisco-ai-mcp-scanner

# MCPScan loads its LLM client at import time and aborts when DEEPSEEK_API_KEY is
# unset, even with --no-monitor-* flags. We only run static taint analysis, so a
# dummy key is enough to bypass the eager check.
ENV DEEPSEEK_API_KEY=dummy

COPY runner/run-scans.sh .
COPY runner/generate-report.py .
COPY runner/reporting.py .
COPY runner/expected-findings.json .
COPY runner/ox-live-expected.json .
COPY guard/tests/fixtures/ox_research_cases.json /app/ox_research_cases.json

RUN chmod +x run-scans.sh

ENV RESULTS_DIR=/results

ENTRYPOINT ["./run-scans.sh"]
