# Docker Deployment Guide

## Quick Start

```bash
# Build image
docker build -t unified-oss-framework:latest .

# Run container
docker run -d \
  --name unified-oss \
  -p 8080:8080 \
  -e DB_HOST=postgres \
  -e JWT_SECRET=your-secret \
  unified-oss-framework:latest
```

## Docker Compose (Full Stack)

```bash
# Start all services
docker-compose up -d

# Services included:
# - unified-oss-app (port 8080)
# - postgres + timescaledb (port 5432)
# - redis (port 6379)
# - kafka + zookeeper (port 9092)
# - grafana (port 3000)
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| DB_HOST | PostgreSQL host | localhost |
| DB_PORT | PostgreSQL port | 5432 |
| DB_NAME | Database name | unified_oss |
| REDIS_HOST | Redis host | localhost |
| KAFKA_BOOTSTRAP_SERVERS | Kafka servers | localhost:9092 |
| JWT_SECRET | JWT signing key | (required) |

## Health Check

```bash
docker exec unified-oss curl -f http://localhost:8080/health
```

## Logs

```bash
docker logs -f unified-oss
```
