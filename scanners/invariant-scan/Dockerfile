FROM python:3.13-slim
WORKDIR /app

RUN pip install --no-cache-dir uv && \
    uv tool install --python 3.13 snyk-agent-scan

ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /scan
ENTRYPOINT ["snyk-agent-scan"]
