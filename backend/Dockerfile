# Stage 1: Build Go Discovery Engine
FROM golang:1.22-alpine AS go-builder
WORKDIR /app
COPY discovery/ ./discovery/
WORKDIR /app/discovery
RUN go build -o bin/discovery-engine .

# Stage 2: Build Python dependencies
FROM python:3.12-slim AS py-builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt


# Stage 3: Production Runtime
FROM python:3.12-slim
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/root/.local/bin:$PATH"

# Install runtime dependencies (scanning tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    nmap \
    sslscan \
    curl \
    fontconfig \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libffi-dev \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

# Copy installed python packages from py-builder
COPY --from=py-builder /root/.local /root/.local

# Copy discovery binary from go-builder
COPY --from=go-builder /app/discovery/bin/discovery-engine /app/discovery/bin/discovery-engine

# Copy application code
COPY backend/ .

# Copy GeoIP database (to /app/geoip/ — outside /app/data volume mount)
COPY data/geolite/GeoLite2-City.mmdb /app/geoip/GeoLite2-City.mmdb

# Ensure scripts and binary are executable
RUN chmod +x scripts/*.py scripts/*.sh discovery/bin/discovery-engine 2>/dev/null || true

# Expose port
EXPOSE 8000

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
