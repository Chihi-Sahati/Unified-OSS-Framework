# REST API Reference

## Authentication

All API endpoints require JWT authentication.

```http
Authorization: Bearer <your-jwt-token>
```

## Endpoints

### Alarms

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/alarms` | List alarms with filtering |
| POST | `/api/v1/alarms/acknowledge` | Acknowledge alarms |
| POST | `/api/v1/alarms/clear` | Clear alarms |
| GET | `/api/v1/alarms/statistics` | Get alarm statistics |

### Performance

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/performance/kpis` | List KPIs |
| GET | `/api/v1/performance/dashboard` | Dashboard data |
| GET | `/api/v1/performance/thresholds` | Threshold rules |

### Configuration

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/configuration/{ne_id}` | Get configuration |
| POST | `/api/v1/configuration/apply` | Apply configuration |
| POST | `/api/v1/configuration/rollback/{job_id}` | Rollback change |
| GET | `/api/v1/configuration/{ne_id}/drift` | Detect drift |

### Security

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/security/authenticate` | Authenticate user |
| POST | `/api/v1/security/evaluate-access` | Evaluate permissions |
| GET | `/api/v1/security/audit-log` | Get audit log |

### Accounting

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/accounting/license-status` | License status |
| GET | `/api/v1/accounting/capacity-summary` | Capacity summary |

## OpenAPI Documentation

Interactive API documentation available at:
- Swagger UI: http://localhost:8080/docs
- ReDoc: http://localhost:8080/redoc
- OpenAPI JSON: http://localhost:8080/openapi.json
