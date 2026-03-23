# Architecture Overview

## System Architecture

The Unified OSS Framework follows a layered architecture:

### Layer 1: Northbound Interfaces
- REST API (FastAPI)
- gRPC Services
- WebSocket (Real-time)
- SNMP Traps

### Layer 2: FCAPS Management
- **Fault**: Alarm Manager, Correlation Engine, Normalization
- **Configuration**: Config Manager, Drift Detection, Workflow
- **Performance**: KPI Manager, Computation, Thresholds
- **Security**: Auth, Authorization, Zero Trust Engine
- **Accounting**: License Manager, Capacity Tracker

### Layer 3: Transformation Engine
- Schema Discovery Service
- Mapping Engine (Bidirectional)
- Validation Engine

### Layer 4: Data Layer
- PostgreSQL (Relational data)
- TimescaleDB (Time-series)
- Redis (Cache)
- Kafka (Streaming)

### Layer 5: Vendor Integration
- Ericsson ENM Connector
- Huawei U2000 Connector
- NETCONF/RESTCONF Adapters

## Key Design Patterns

### Common Information Model (CIM)
Vendor-neutral data model based on 3GPP TS 28.541

### Bidirectional Mapping
Forward: Vendor → CIM
Reverse: CIM → Vendor

### Zero Trust Security
NIST SP 800-207 compliant authorization

## Data Flow

```
Vendor Systems → Connectors → Kafka → Transformation → Database → API → Northbound
```
