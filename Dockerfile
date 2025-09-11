# Multi-stage build for Python apps
FROM python:3.11-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

FROM python:3.11-slim

# Add build arguments
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
ARG VERSION=1.0.0

# Set as environment variables
ENV GIT_COMMIT=$GIT_COMMIT \
    BUILD_DATE=$BUILD_DATE \
    VERSION=$VERSION \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ffmpeg \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 appuser

WORKDIR /app

# Copy from builder
COPY --from=builder --chown=appuser:appuser /root/.local /home/appuser/.local

# Copy application code
COPY --chown=appuser:appuser . .

# Generate version information during build
RUN if [ -f scripts/generate-version.sh ]; then \
        chmod +x scripts/generate-version.sh && \
        ./scripts/generate-version.sh; \
    fi

# Create required directories
RUN mkdir -p /app/config /app/logs && \
    chown -R appuser:appuser /app/config /app/logs

# Update PATH
ENV PATH=/home/appuser/.local/bin:$PATH

USER appuser

EXPOSE 5000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "streamsnap_app:app"]