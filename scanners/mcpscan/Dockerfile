FROM python:3.12-slim
WORKDIR /app

COPY patch_mcpscan_runner.py /tmp/patch_mcpscan_runner.py

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "setuptools<81" \
    semgrep \
    "typer>=0.12" \
    "rich>=13.7" \
    "tqdm>=4.66" \
    "gitpython>=3.1" \
    python-dotenv \
    openai

RUN git clone https://github.com/antgroup/MCPScan.git /opt/mcpscan && \
    python /tmp/patch_mcpscan_runner.py /opt/mcpscan && \
    pip install --no-cache-dir --no-deps -e /opt/mcpscan

WORKDIR /scan
ENTRYPOINT ["mcpscan"]
