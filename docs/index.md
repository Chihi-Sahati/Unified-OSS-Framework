# Unified OSS Framework Documentation

## Overview

The Unified OSS Framework is a comprehensive, vendor-neutral Operational Support System (OSS) designed for multi-vendor network element management. It provides seamless integration between Ericsson ENM and Huawei U2000 systems with a Common Information Model (CIM) based on 3GPP TS 28.541 standards.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Northbound Interfaces                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │ REST API │  │  gRPC    │  │ WebSocket│  │   SNMP   │          │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
└───────┼─────────────┼─────────────┼─────────────┼──────────────────┘
        │             │             │             │
┌───────┴─────────────┴─────────────┴─────────────┴──────────────────┐
│                   Unified OSS Framework                              │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                  FCAPS Management                           │    │
│  │  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐  │    │
│  │  │ Fault  │ │ Config │ │ Acct   │ │ Perf   │ │Security│  │    │
│  │  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘  │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

## Modules

### FCAPS Fault Management
- Alarm lifecycle management
- Cross-vendor correlation
- Root cause analysis

### FCAPS Configuration Management
- NETCONF workflow automation
- Drift detection
- Configuration versioning

### FCAPS Performance Management
- KPI computation and monitoring
- Threshold breach detection
- Dashboard aggregation

### FCAPS Security Management
- Zero Trust authorization
- RBAC implementation
- Audit logging

### FCAPS Accounting Management
- License tracking
- Capacity management
- BSS integration

## Quick Links

- [Installation Guide](installation.md)
- [Quick Start Tutorial](quickstart.md)
- [API Reference](api/rest-api.md)
- [Architecture Overview](architecture/overview.md)
