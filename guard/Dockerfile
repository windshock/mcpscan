FROM python:3.12-slim
WORKDIR /app

COPY requirements.txt .
COPY pyproject.toml .
RUN pip install --no-cache-dir -r requirements.txt

COPY mcp_guard/ ./mcp_guard/
COPY mcp-policy.yaml .

# Install as package
RUN pip install --no-cache-dir -e .

ENTRYPOINT ["python", "-m", "mcp_guard"]
