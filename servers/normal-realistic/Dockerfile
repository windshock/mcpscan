FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
RUN mkdir -p /data && echo "# Sample data file\nHello from normal-realistic" > /data/sample.txt
EXPOSE 8000
CMD ["python", "server.py"]
