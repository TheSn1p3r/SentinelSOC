# SentinelSOC — container image for deploying to any VM/host.
#
# The default config binds to 127.0.0.1 INSIDE the container, so a plain
# `docker run -p ...` would map a port nothing listens on. To reach the
# dashboard from outside the container, mount a config with
# `api.host: "0.0.0.0"` (auth stays on unless you deliberately set
# `api.auth_disabled: true` — see config/config.yaml.example).
#
# Build:   docker build -t sentinelsoc .
# Run:     docker run -d --name sentinelsoc -p 8765:8765 \
#            -v "$PWD/config:/app/config" \
#            -v sentinelsoc_data:/app/data \
#            -v sentinelsoc_logs:/app/logs \
#            -v sentinelsoc_quarantine:/app/quarantine \
#            sentinelsoc
# API key: generated into the mounted config/config.yaml on first start
#          (docker exec sentinelsoc cat /app/config/config.yaml | grep api_key)

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY sentinelsoc/ ./sentinelsoc/
COPY config/ ./config/

# Runtime data lives outside the image: mount volumes for ./data, ./logs
# and ./quarantine (see the run command above) so alerts survive rebuilds.

EXPOSE 8765
CMD ["python", "main.py"]
