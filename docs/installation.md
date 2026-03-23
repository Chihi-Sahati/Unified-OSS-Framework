# Installation Guide

## Prerequisites

- Python 3.10+
- Docker and Docker Compose
- PostgreSQL 15+ with TimescaleDB
- Redis 7+
- Apache Kafka 3.x

## Quick Start with Docker

```bash
# Clone repository
git clone https://github.com/unified-oss-framework/unified-oss-framework.git
cd unified-oss-framework

# Start all services
docker-compose up -d

# Check status
docker-compose ps
```

## Manual Installation

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
psql -d unified_oss -f sql-migrations/001_initial_schema.sql

# Configure environment
export DB_HOST=localhost
export DB_NAME=unified_oss
export JWT_SECRET=your-secret-key

# Start application
python -m uvicorn unified_oss.api.rest.app:app --host 0.0.0.0 --port 8080
```

## Verification

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "1.0.0"
}
```
