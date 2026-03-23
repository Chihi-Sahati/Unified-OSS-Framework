# Unified OSS Framework - Multi-stage Dockerfile
# Optimized for production deployment with security best practices

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Stage 2: Production
FROM python:3.11-slim as production

# Security: Create non-root user
RUN groupadd -r unifiedoss && useradd -r -g unifiedoss unifiedoss

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=unifiedoss:unifiedoss src/ ./src/
COPY --chown=unifiedoss:unifiedoss yang-modules/ ./yang-modules/
COPY --chown=unifiedoss:unifiedoss semantic-rules/ ./semantic-rules/
COPY --chown=unifiedoss:unifiedoss config/ ./config/

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    LOG_LEVEL=INFO \
    ENVIRONMENT=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose port
EXPOSE 8080

# Switch to non-root user
USER unifiedoss

# Default command
CMD ["python", "-m", "unified_oss.api.rest.app"]

# Stage 3: Development
FROM production as development

USER root

# Install development tools
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    pytest-asyncio \
    black \
    flake8 \
    mypy \
    ipython

USER unifiedoss

ENV ENVIRONMENT=development \
    LOG_LEVEL=DEBUG

CMD ["python", "-m", "unified_oss.api.rest.app", "--reload"]
