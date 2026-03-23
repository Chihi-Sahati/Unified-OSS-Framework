"""
Unit tests for Alarm Normalization module.

Tests cover alarm normalization, vendor-specific parsing, and ITU-T M.3100
mapping functionality.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from unified_oss.fcaps.fault.normalization import (
    AlarmNormalizer,
    VendorAlarmParser,
    ITUTMapper,
    NormalizedAlarm,
    NormalizationResult,
    VendorType,
    NormalizationError,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def alarm_normalizer():
    """Create an AlarmNormalizer instance for testing."""
    return AlarmNormalizer()


@pytest.fixture
def itu_t_mapper():
    """Create an ITUTMapper instance for testing."""
    return ITUTMapper()


@pytest.fixture
def vendor_parser():
    """Create a VendorAlarmParser instance for testing."""
    return VendorAlarmParser()


@pytest.fixture
def ericsson_alarm_data():
    """Create sample Ericsson alarm data."""
    return {
        "alarmId": "ERIC-ALARM-001",
        "managedObject": "Router-001",
        "eventType": "EquipmentAlarm",
        "probableCause": "Power Failure",
        "specificProblem": "Power Supply Unit Failed",
        "perceivedSeverity": "critical",
        "eventTime": "2024-01-15T10:30:00Z",
        "additionalText": "PSU slot 1 failed",
        "neType": "ERICSSON-7750",
        "customField1": "custom_value_1",
        "location": "Building A",
    }


@pytest.fixture
def huawei_alarm_data():
    """Create sample Huawei alarm data."""
    return {
        "alarmId": "HW-ALARM-001",
        "neName": "Router-002",
        "alarmName": "Link Down",
        "alarmLevel": 3,  # Major
        "neType": "Huawei-NE40E",
        "occurTime": "2024-01-15T11:00:00",
        "clearTime": None,
        "alarmSource": "Interface GigabitEthernet0/0/1",
        "probableCause": "Communication Failure",
    }


@pytest.fixture
def nokia_alarm_data():
    """Create sample Nokia alarm data."""
    return {
        "alarmId": "NOK-ALARM-001",
        "nodeName": "Router-003",
        "alarmCode": "A2",  # Major
        "alarmText": "High CPU Utilization",
        "eventType": "ProcessingError",
        "eventTime": "2024-01-15T12:00:00+00:00",
        "objectName": "CPU Module",
        "probableCause": "Processing Error",
    }


# =============================================================================
# AlarmNormalizer Tests
# =============================================================================

class TestAlarmNormalizer:
    """Tests for AlarmNormalizer class."""

    def test_normalize_ericsson_alarm(self, alarm_normalizer, ericsson_alarm_data):
        """Test normalizing Ericsson alarm."""
        result = alarm_normalizer.normalize(
            ericsson_alarm_data,
            VendorType.ERICSSON
        )
        
        assert result.success is True
        assert result.normalized_alarm is not None
        assert result.normalized_alarm.ne_id == "Router-001"
        assert result.normalized_alarm.severity == "CRITICAL"

    def test_normalize_huawei_alarm(self, alarm_normalizer, huawei_alarm_data):
        """Test normalizing Huawei alarm."""
        result = alarm_normalizer.normalize(
            huawei_alarm_data,
            VendorType.HUAWEI
        )
        
        assert result.success is True
        assert result.normalized_alarm is not None
        assert result.normalized_alarm.ne_id == "Router-002"

    def test_normalize_nokia_alarm(self, alarm_normalizer, nokia_alarm_data):
        """Test normalizing Nokia alarm."""
        result = alarm_normalizer.normalize(
            nokia_alarm_data,
            VendorType.NOKIA
        )
        
        assert result.success is True
        assert result.normalized_alarm is not None

    def test_normalize_unknown_vendor(self, alarm_normalizer):
        """Test normalizing alarm from unknown vendor."""
        alarm_data = {
            "alarm_id": "UNKNOWN-001",
            "ne_id": "Router-999",
        }
        
        with pytest.raises(NormalizationError):
            alarm_normalizer.normalize(alarm_data, "unknown_vendor")

    def test_normalize_with_missing_fields(self, alarm_normalizer):
        """Test normalization with missing required fields."""
        incomplete_data = {
            "alarmId": "INCOMPLETE-001",
            # Missing managedObject and other fields
        }
        
        result = alarm_normalizer.normalize(
            incomplete_data,
            VendorType.ERICSSON,
            strict=False
        )
        
        # Should still succeed with defaults
        assert result.success is True

    def test_add_vendor_parser(self, alarm_normalizer):
        """Test adding custom vendor parser."""
        custom_parser = MagicMock()
        custom_parser.parse.return_value = {
            "alarm_id": "custom-001",
            "ne_id": "custom-ne",
        }
        
        alarm_normalizer.add_vendor_parser("custom_vendor", custom_parser)
        
        result = alarm_normalizer.normalize(
            {"raw": "data"},
            "custom_vendor"
        )
        
        assert custom_parser.parse.called

    def test_normalize_batch(self, alarm_normalizer, ericsson_alarm_data, huawei_alarm_data):
        """Test batch normalization."""
        alarms = [
            (ericsson_alarm_data, VendorType.ERICSSON),
            (huawei_alarm_data, VendorType.HUAWEI),
        ]
        
        results = alarm_normalizer.normalize_batch(alarms)
        
        assert len(results) == 2
        assert all(r.success for r in results)


# =============================================================================
# VendorAlarmParser Tests
# =============================================================================

class TestVendorAlarmParser:
    """Tests for VendorAlarmParser class."""

    def test_parse_ericsson_alarm(self, vendor_parser, ericsson_alarm_data):
        """Test parsing Ericsson alarm."""
        result = vendor_parser.parse_ericsson(ericsson_alarm_data)
        
        assert result["alarm_id"] == "ERIC-ALARM-001"
        assert result["ne_id"] == "Router-001"
        assert result["probable_cause"] == "Power Failure"

    def test_parse_huawei_alarm(self, vendor_parser, huawei_alarm_data):
        """Test parsing Huawei alarm."""
        result = vendor_parser.parse_huawei(huawei_alarm_data)
        
        assert result["alarm_id"] == "HW-ALARM-001"
        assert result["ne_id"] == "Router-002"
        assert "level" in result or "severity" in result

    def test_parse_nokia_alarm(self, vendor_parser, nokia_alarm_data):
        """Test parsing Nokia alarm."""
        result = vendor_parser.parse_nokia(nokia_alarm_data)
        
        assert result["alarm_id"] == "NOK-ALARM-001"
        assert result["ne_id"] == "Router-003"

    def test_map_severity_ericsson(self, vendor_parser):
        """Test Ericsson severity mapping."""
        assert vendor_parser.map_severity_ericsson("critical") == "CRITICAL"
        assert vendor_parser.map_severity_ericsson("major") == "MAJOR"
        assert vendor_parser.map_severity_ericsson("minor") == "MINOR"
        assert vendor_parser.map_severity_ericsson("warning") == "WARNING"
        assert vendor_parser.map_severity_ericsson("unknown") == "MINOR"

    def test_map_severity_huawei(self, vendor_parser):
        """Test Huawei severity mapping."""
        assert vendor_parser.map_severity_huawei(1) == "CRITICAL"
        assert vendor_parser.map_severity_huawei(2) == "MAJOR"
        assert vendor_parser.map_severity_huawei(3) == "MINOR"
        assert vendor_parser.map_severity_huawei(4) == "WARNING"

    def test_map_severity_nokia(self, vendor_parser):
        """Test Nokia severity mapping."""
        assert vendor_parser.map_severity_nokia("A1") == "CRITICAL"
        assert vendor_parser.map_severity_nokia("A2") == "MAJOR"
        assert vendor_parser.map_severity_nokia("A3") == "MINOR"

    def test_parse_timestamp_ericsson(self, vendor_parser):
        """Test parsing Ericsson timestamp format."""
        timestamp = vendor_parser.parse_timestamp("2024-01-15T10:30:00Z")
        
        assert timestamp is not None
        assert timestamp.year == 2024
        assert timestamp.month == 1
        assert timestamp.day == 15

    def test_parse_timestamp_huawei(self, vendor_parser):
        """Test parsing Huawei timestamp format."""
        timestamp = vendor_parser.parse_timestamp("2024-01-15 11:00:00")
        
        assert timestamp is not None
        assert timestamp.year == 2024

    def test_extract_additional_info(self, vendor_parser, ericsson_alarm_data):
        """Test extracting additional information."""
        additional = vendor_parser.extract_additional_info(
            ericsson_alarm_data,
            VendorType.ERICSSON
        )
        
        assert isinstance(additional, dict)
        assert len(additional) > 0


# =============================================================================
# ITUTMapper Tests
# =============================================================================

class TestITUTMapper:
    """Tests for ITUTMapper class."""

    def test_map_alarm_type(self, itu_t_mapper):
        """Test mapping to ITU-T alarm types."""
        result = itu_t_mapper.map_alarm_type("EquipmentAlarm")
        
        assert result in ["COMMUNICATIONS_ALARM", "EQUIPMENT_ALARM", "PROCESSING_ERROR_ALARM"]

    def test_map_probable_cause(self, itu_t_mapper):
        """Test mapping probable cause to ITU-T codes."""
        result = itu_t_mapper.map_probable_cause("Power Failure")
        
        assert result is not None
        assert isinstance(result, int) or isinstance(result, str)

    def test_get_alarm_category(self, itu_t_mapper):
        """Test getting ITU-T alarm category."""
        category = itu_t_mapper.get_alarm_category("EquipmentAlarm")
        
        assert category in ["COMMUNICATIONS", "EQUIPMENT", "PROCESSING", "ENVIRONMENT", "QUALITY_OF_SERVICE"]

    def test_map_severity_to_itu(self, itu_t_mapper):
        """Test mapping severity to ITU-T values."""
        assert itu_t_mapper.map_severity_to_itu("CRITICAL") == "critical"
        assert itu_t_mapper.map_severity_to_itu("MAJOR") == "major"
        assert itu_t_mapper.map_severity_to_itu("MINOR") == "minor"
        assert itu_t_mapper.map_severity_to_itu("WARNING") == "warning"

    def test_lookup_probable_cause_code(self, itu_t_mapper):
        """Test looking up probable cause codes."""
        code = itu_t_mapper.lookup_probable_cause_code("Link Down")
        
        # Should return an ITU-T standard code
        assert code is not None

    def test_reverse_lookup(self, itu_t_mapper):
        """Test reverse lookup from code to cause."""
        # First map a cause
        code = itu_t_mapper.map_probable_cause("Power Failure")
        
        # Then reverse lookup
        if isinstance(code, int):
            cause = itu_t_mapper.reverse_lookup(code)
            assert "Power" in cause or cause != ""


# =============================================================================
# NormalizedAlarm Tests
# =============================================================================

class TestNormalizedAlarm:
    """Tests for NormalizedAlarm dataclass."""

    def test_normalized_alarm_creation(self):
        """Test creating a normalized alarm."""
        alarm = NormalizedAlarm(
            alarm_id="NORM-001",
            ne_id="router-001",
            alarm_type="EQUIPMENT_ALARM",
            severity="MAJOR",
            probable_cause="Power Failure",
            specific_problem="PSU Failure",
            timestamp=datetime.now(timezone.utc),
            vendor="ericsson",
            original_data={"raw": "data"},
        )
        
        assert alarm.alarm_id == "NORM-001"
        assert alarm.ne_id == "router-001"
        assert alarm.vendor == "ericsson"

    def test_normalized_alarm_to_dict(self):
        """Test normalized alarm serialization."""
        alarm = NormalizedAlarm(
            alarm_id="NORM-001",
            ne_id="router-001",
            alarm_type="EQUIPMENT_ALARM",
            severity="MAJOR",
            probable_cause="Power Failure",
            specific_problem="PSU Failure",
            timestamp=datetime.now(timezone.utc),
            vendor="ericsson",
        )
        
        alarm_dict = alarm.to_dict()
        
        assert "alarm_id" in alarm_dict
        assert "ne_id" in alarm_dict
        assert "vendor" in alarm_dict

    def test_normalized_alarm_hash(self):
        """Test normalized alarm hash generation."""
        alarm = NormalizedAlarm(
            alarm_id="NORM-001",
            ne_id="router-001",
            alarm_type="EQUIPMENT_ALARM",
            severity="MAJOR",
            probable_cause="Power Failure",
            specific_problem="PSU Failure",
            timestamp=datetime.now(timezone.utc),
            vendor="ericsson",
        )
        
        hash1 = alarm.calculate_hash()
        hash2 = alarm.calculate_hash()
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256


# =============================================================================
# NormalizationResult Tests
# =============================================================================

class TestNormalizationResult:
    """Tests for NormalizationResult dataclass."""

    def test_successful_result(self):
        """Test creating successful normalization result."""
        result = NormalizationResult(
            success=True,
            normalized_alarm=NormalizedAlarm(
                alarm_id="test",
                ne_id="test",
                alarm_type="EQUIPMENT",
                severity="MAJOR",
                probable_cause="test",
                specific_problem="test",
                timestamp=datetime.now(timezone.utc),
                vendor="test",
            ),
        )
        
        assert result.success is True
        assert result.error is None

    def test_failed_result(self):
        """Test creating failed normalization result."""
        result = NormalizationResult(
            success=False,
            error="Missing required field: ne_id",
        )
        
        assert result.success is False
        assert result.normalized_alarm is None
        assert result.error == "Missing required field: ne_id"


# =============================================================================
# Integration Tests
# =============================================================================

class TestNormalizationIntegration:
    """Integration tests for normalization."""

    def test_full_normalization_workflow(
        self,
        alarm_normalizer,
        ericsson_alarm_data
    ):
        """Test complete normalization workflow."""
        # Normalize
        result = alarm_normalizer.normalize(
            ericsson_alarm_data,
            VendorType.ERICSSON
        )
        
        assert result.success is True
        
        # Access normalized alarm
        alarm = result.normalized_alarm
        
        # Validate ITU-T mapping
        assert alarm.alarm_type is not None
        assert alarm.probable_cause is not None

    def test_multi_vendor_normalization(
        self,
        alarm_normalizer,
        ericsson_alarm_data,
        huawei_alarm_data,
        nokia_alarm_data
    ):
        """Test normalizing alarms from multiple vendors."""
        results = []
        
        for data, vendor in [
            (ericsson_alarm_data, VendorType.ERICSSON),
            (huawei_alarm_data, VendorType.HUAWEI),
            (nokia_alarm_data, VendorType.NOKIA),
        ]:
            result = alarm_normalizer.normalize(data, vendor)
            results.append(result)
        
        assert all(r.success for r in results)
        
        # All should have consistent format
        for result in results:
            alarm = result.normalized_alarm
            assert hasattr(alarm, "alarm_id")
            assert hasattr(alarm, "ne_id")
            assert hasattr(alarm, "severity")


# =============================================================================
# Performance Tests
# =============================================================================

class TestNormalizationPerformance:
    """Performance tests for normalization."""

    def test_batch_normalization_performance(self, alarm_normalizer, ericsson_alarm_data):
        """Test performance of batch normalization."""
        alarms = [
            (ericsson_alarm_data.copy(), VendorType.ERICSSON)
            for _ in range(100)
        ]
        
        start_time = datetime.now(timezone.utc)
        results = alarm_normalizer.normalize_batch(alarms)
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        assert all(r.success for r in results)
        assert duration < 2.0  # Should complete within 2 seconds


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
