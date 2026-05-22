FROM python:3.12-slim

# Keep Python logs visible immediately in Docker and avoid writing .pyc files.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# iptables is required by the blocker. ca-certificates is needed for Slack HTTPS.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# Install only the runtime Python dependencies declared for the detector daemon.
RUN pip install --no-cache-dir -r requirements.txt

# Copy the daemon source and its default YAML configuration into the image.
COPY *.py ./
COPY config.yaml ./

# Create the paths mounted by Compose for audit logs and persistent ban state.
RUN mkdir -p /var/log/detector /var/lib/detector

# Expose the FastAPI dashboard port used by docker-compose.yml.
EXPOSE 8080

# Start the asyncio daemon entrypoint with unbuffered output for docker logs.
CMD ["python", "-u", "main.py"]
