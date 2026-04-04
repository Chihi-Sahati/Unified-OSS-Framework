# Unified OSS Framework for Multi-Vendor Network Element Management

**Author:** Al-Hussein A. Al-Sahati  
**Supervisor:** Dr. Houda Chihi  
**Repository:** [Unified OSS Framework](https://github.com/Chihi-Sahati/Unified-OSS-Framework.git)

---

## Abstract

This repository contains the scientific architecture and implementation of the Unified OSS Framework, an advanced solution designed to address the critical challenges of vendor heterogeneity in modern telecommunications networks. The framework provides unified abstraction and management capabilities for diverse network management systems, prominently covering Ericsson ENM and Huawei U2000/U2020 environments. 

Through the implementation of a robust Vendor Abstraction Layer (VAL), the system ensures seamless integration across all five FCAPS functional areas (Fault, Configuration, Accounting, Performance, and Security). Key novel contributions include a vendor-agnostic YANG data model augmentation, an AI-assisted semantic mapping engine for configuration translation, multi-method alarm correlation techniques (temporal, topological, and causal), and the first comprehensive OSS framework achieving continuous Zero Trust Architecture compliance per NIST SP 800-207 standards. This unified approach enables operators to manage complex multi-vendor network resources through a single, coherent, and highly secure interface.

---

## System Requirements

The framework requires the following infrastructure to build and run successfully:

**Core Dependencies:**
- **Language Environment:** Python 3.11+
- **Database Backend:** PostgreSQL 14+ (with TimescaleDB extension required)
- **Caching Layer:** Redis 7+
- **Containerization:** Docker Desktop / Docker Compose

---

## Installation and Setup

### 1. Repository Configuration
Clone the repository and initialize the virtual environment.

```bash
git clone https://github.com/Chihi-Sahati/Unified-OSS-Framework.git
cd Unified-OSS-Framework

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Container Deployment
Alternatively, for a complete automated environment setup, use Docker Compose:

```bash
# Build and run all services
docker-compose up -d
```

---

## Execution

To start the framework API and processing engine locally:

```bash
python -m unified_oss.api.rest.app
```

To execute the test suite and validate system components:

```bash
pytest tests/ -v
```

---

## License and Citation

This framework is developed as an academic research project under the supervision of Dr. Houda Chihi for submission to the IEEE Transactions on Network and Service Management.

If you utilize this software in your research, please refer to the `CITATION.cff` file or use the following citation:

```bibtex
@article{unified_oss_2026,
  title={Unified OSS Framework for Multi-Vendor Network Element Management},
  author={Al-Sahati, Al-Hussein A. and Chihi, Houda},
  journal={IEEE Transactions on Network and Service Management},
  year={2026},
  note={In Preparation}
}
```
