"""
Pytest configuration and fixtures.
"""

import pytest
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import os
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)


# ============================================================
# Event Loop Configuration
# ============================================================

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


# ============================================================
# Test Data Directories
# ============================================================

@pytest.fixture(scope="session")
def test_data_dir():
    """Path to test data directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def yang_modules_dir():
    """Path to YANG modules directory."""
    return Path(__file__).parent.parent / "yang-modules"


@pytest.fixture(scope="session")
def semantic_rules_dir():
    """Path to semantic rules directory."""
    return Path(__file__).parent.parent / "semantic-rules"


# ============================================================
# Sample Data Fixtures
# ============================================================

@pytest.fixture
def sample_ericsson_alarm() -> Dict[str, Any]:
    """Sample Ericsson alarm data."""
    return {
        "alarm_id": "A1001",
        "alarm_name": "Radio Unit Connection Failure",
        "alarm_type": "EQUIPMENT_ALARM",
        "severity": "critical",
        "vendor": "ERICSSON",
        "ne_id": "ENB-HCM-001",
        "ne_name": "eNodeB HCM Site 001",
        "ne_type": "ENODEB",
        "timestamp": "2024-01-15T10:30:00.000Z",
        "probable_cause": "HARDWARE_FAILURE",
        "affected_resource": "/network/ERICSSON/ENODEB/ENB-HCM-001",
        "source_ip": "10.1.1.1",
        "location": "HCM_SITE_001",
    }


@pytest.fixture
def sample_huawei_alarm() -> Dict[str, Any]:
    """Sample Huawei alarm data."""
    return {
        "alarm_id": "0x0411FFFF",
        "alarm_name": "RF Unit Hardware Fault",
        "alarm_type": "EQUIPMENT_ALARM",
        "severity": 1,  # Integer severity
        "vendor": "HUAWEI",
        "ne_id": "ENB-HCM-002",
        "ne_name": "eNodeB HCM Site 002",
        "ne_type": "ENODEB",
        "timestamp": 1705315800000,  # Milliseconds
        "probable_cause": "HARDWARE_FAILURE",
        "affected_resource": "/network/HUAWEI/ENODEB/ENB-HCM-002",
        "source_ip": "10.2.1.1",
        "location": "HCM_SITE_002",
    }


@pytest.fixture
def sample_pm_counters() -> Dict[str, Any]:
    """Sample PM counter data."""
    return {
        "ne_id": "ENB-HCM-001",
        "vendor": "ERICSSON",
        "timestamp": datetime.utcnow(),
        "counters": {
            "pmRrcConnEstabAtt": 1000,
            "pmRrcConnEstabSucc": 950,
            "pmHoAtt": 500,
            "pmHoSucc": 475,
            "pmErabEstabAtt": 800,
            "pmErabEstabSucc": 780,
            "pmThroughputDl": 1500000000,
            "pmThroughputUl": 300000000,
        },
    }


@pytest.fixture
def sample_config_data() -> Dict[str, Any]:
    """Sample configuration data."""
    return {
        "ne_id": "ENB-HCM-001",
        "vendor": "ERICSSON",
        "config": {
            "radio": {
                "cell": {
                    "pci": 100,
                    "tx_power": 40,
                    "frequency": 1800,
                }
            },
            "handover": {
                "a3_offset": 4,
                "hysteresis": 2,
            }
        }
    }


@pytest.fixture
def sample_network_elements() -> List[Dict[str, Any]]:
    """Sample network element list."""
    return [
        {
            "ne_id": "ENB-HCM-001",
            "ne_name": "eNodeB HCM Site 001",
            "vendor": "ERICSSON",
            "ne_type": "ENODEB",
            "ip_address": "10.1.1.1",
            "location": "HCM_SITE_001",
            "status": "OPERATIONAL",
        },
        {
            "ne_id": "ENB-HCM-002",
            "ne_name": "eNodeB HCM Site 002",
            "vendor": "HUAWEI",
            "ne_type": "ENODEB",
            "ip_address": "10.2.1.1",
            "location": "HCM_SITE_002",
            "status": "OPERATIONAL",
        },
    ]


# ============================================================
# Mock Fixtures
# ============================================================

@pytest.fixture
def mock_database():
    """Mock database connection."""
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=None)
    mock_db.fetch = AsyncMock(return_value=[])
    mock_db.fetchrow = AsyncMock(return_value=None)
    return mock_db


@pytest.fixture
def mock_redis():
    """Mock Redis client."""
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)
    mock_redis.set = AsyncMock(return_value=True)
    mock_redis.delete = AsyncMock(return_value=1)
    return mock_redis


@pytest.fixture
def mock_kafka_producer():
    """Mock Kafka producer."""
    mock_producer = AsyncMock()
    mock_producer.send = AsyncMock()
    mock_producer.flush = AsyncMock()
    return mock_producer


@pytest.fixture
def mock_kafka_consumer():
    """Mock Kafka consumer."""
    mock_consumer = AsyncMock()
    mock_consumer.__aiter__ = Mock(return_value=iter([]))
    return mock_consumer


# ============================================================
# Component Fixtures
# ============================================================

@pytest.fixture
async def alarm_manager():
    """Create AlarmManager instance."""
    from unified_oss.fcaps.fault.alarm_manager import AlarmManager
    return AlarmManager()


@pytest.fixture
async def kpi_manager():
    """Create KPIManager instance."""
    from unified_oss.fcaps.performance.kpi_manager import KPIManager
    return KPIManager()


@pytest.fixture
async def config_manager():
    """Create ConfigManager instance."""
    from unified_oss.fcaps.configuration.config_manager import ConfigManager
    return ConfigManager()


@pytest.fixture
async def zero_trust_engine():
    """Create ZeroTrustEngine instance."""
    from unified_oss.fcaps.security.zero_trust import ZeroTrustEngine
    return ZeroTrustEngine()


# ============================================================
# Utility Fixtures
# ============================================================

@pytest.fixture
def temp_config_file(tmp_path):
    """Create temporary config file."""
    config_content = """
database:
  host: localhost
  port: 5432
  name: test_db
redis:
  host: localhost
  port: 6379
kafka:
  bootstrap_servers: localhost:9092
"""
    config_file = tmp_path / "test_config.yaml"
    config_file.write_text(config_content)
    return config_file


@pytest.fixture
def temp_yang_file(tmp_path):
    """Create temporary YANG file for testing."""
    yang_content = """
module test-module {
  yang-version 1.1;
  namespace "urn:test:v1";
  prefix test;
  
  container test-container {
    leaf test-leaf {
      type string;
    }
  }
}
"""
    yang_file = tmp_path / "test.yang"
    yang_file.write_text(yang_content)
    return yang_file


# ============================================================
# Marker Configuration
# ============================================================

def pytest_configure(config):
    """Configure custom pytest markers."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "e2e: mark test as an end-to-end test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
