# Quick Start Tutorial

## 1. Authenticate

```bash
curl -X POST http://localhost:8080/api/v1/security/authenticate \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

## 2. List Alarms

```bash
curl -X GET "http://localhost:8080/api/v1/alarms?severity=CRITICAL" \
  -H "Authorization: Bearer $TOKEN"
```

## 3. View KPIs

```bash
curl -X GET http://localhost:8080/api/v1/performance/dashboard \
  -H "Authorization: Bearer $TOKEN"
```

## 4. Apply Configuration

```bash
curl -X POST http://localhost:8080/api/v1/configuration/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ne_id": "ENB-001",
    "config_data": {"radio": {"cell": {"tx_power": 43}}},
    "operation": "merge"
  }'
```

## 5. WebSocket Notifications

```javascript
const ws = new WebSocket('ws://localhost:8080/ws/alarms');
ws.onmessage = (event) => console.log(JSON.parse(event.data));
```
