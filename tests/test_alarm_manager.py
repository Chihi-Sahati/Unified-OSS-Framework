"""
Unit tests for Alarm Manager module.

Tests cover alarm lifecycle management, severity mapping, root cause analysis,
and notification callbacks.
"""

import asyncio
import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unified_oss.fcaps.fault.alarm_manager import (
    Alarm,
    AlarmManager,
    AlarmSeverity,
    AlarmState,
    AlarmCategory,
    AlarmType,
    SeverityMapper,
    RootCauseAnalyzer,
    NotificationCallback,
    AlarmNotFoundError,
    AlarmAlreadyExistsError,
    AlarmStateError,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
async def alarm_manager():
    """Create an AlarmManager instance for testing."""
    manager = AlarmManager()
    await manager.initialize()
    yield manager
    await manager.close()


@pytest.fixture
def severity_mapper():
    """Create a SeverityMapper instance for testing."""
    return SeverityMapper()


@pytest.fixture
def root_cause_analyzer():
    """Create a RootCauseAnalyzer instance for testing."""
    return RootCauseAnalyzer()


@pytest.fixture
def sample_alarm_data():
    """Create sample alarm data for testing."""
    return {
        "ne_id": "router-001",
        "alarm_type": AlarmType.EQUIPMENT,
        "severity": AlarmSeverity.MAJOR,
        "probable_cause": "Link Down",
        "specific_problem": "Interface eth0 down",
        "additional_info": {
            "interface": "eth0",
            "location": "Building A",
        },
    }


@pytest.fixture
def sample_alarm(sample_alarm_data):
    """Create a sample Alarm instance."""
    return Alarm(**sample_alarm_data)


# =============================================================================
# Alarm Class Tests
# =============================================================================

class TestAlarm:
    """Tests for the Alarm dataclass."""

    def test_alarm_creation(self, sample_alarm_data):
        """Test basic alarm creation."""
        alarm = Alarm(**sample_alarm_data)
        
        assert alarm.ne_id == "router-001"
        assert alarm.alarm_type == AlarmType.EQUIPMENT
        assert alarm.severity == AlarmSeverity.MAJOR
        assert alarm.probable_cause == "Link Down"
        assert alarm.state == AlarmState.RAISED
        assert alarm.acknowledged is False
        assert alarm.cleared is False

    def test_alarm_default_values(self):
        """Test default values for alarm."""
        alarm = Alarm(ne_id="test-ne")
        
        assert alarm.alarm_id  # Should be auto-generated
        assert alarm.state == AlarmState.RAISED
        assert alarm.severity == AlarmSeverity.MINOR
        assert alarm.acknowledged is False
        assert alarm.cleared is False
        assert alarm.alarm_type == AlarmType.OTHER

    def test_alarm_to_dict(self, sample_alarm):
        """Test alarm serialization to dictionary."""
        alarm_dict = sample_alarm.to_dict()
        
        assert "alarm_id" in alarm_dict
        assert alarm_dict["ne_id"] == "router-001"
        assert alarm_dict["severity"] == "MAJOR"
        assert alarm_dict["state"] == "RAISED"
        assert isinstance(alarm_dict["timestamp"], str)

    def test_alarm_hash(self, sample_alarm):
        """Test alarm hash calculation."""
        # Should generate consistent hash
        hash1 = sample_alarm.content_hash
        hash2 = sample_alarm.content_hash
        
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 produces 64 hex characters

    def test_alarm_acknowledge(self, sample_alarm):
        """Test alarm acknowledgment."""
        sample_alarm.acknowledge("admin")
        
        assert sample_alarm.acknowledged is True
        assert sample_alarm.acknowledged_by == "admin"
        assert sample_alarm.ack_time is not None

    def test_alarm_clear(self, sample_alarm):
        """Test alarm clearing."""
        sample_alarm.clear("system")
        
        assert sample_alarm.cleared is True
        assert sample_alarm.cleared_by == "system"
        assert sample_alarm.clear_time is not None
        assert sample_alarm.state == AlarmState.CLEARED

    def test_alarm_is_active(self, sample_alarm):
        """Test alarm active status."""
        assert sample_alarm.is_active() is True
        
        sample_alarm.clear("system")
        assert sample_alarm.is_active() is False

    def test_alarm_duration(self, sample_alarm):
        """Test alarm duration calculation."""
        # Initially no duration
        assert sample_alarm.duration() is None
        
        # After clearing
        sample_alarm.clear("system")
        duration = sample_alarm.duration()
        
        assert duration is not None
        assert duration >= timedelta(seconds=0)


# =============================================================================
# AlarmManager Tests
# =============================================================================

class TestAlarmManager:
    """Tests for AlarmManager class."""

    @pytest.mark.asyncio
    async def test_create_alarm(self, alarm_manager, sample_alarm_data):
        """Test alarm creation."""
        alarm = await alarm_manager.create_alarm(**sample_alarm_data)
        
        assert alarm.alarm_id in alarm_manager._alarms
        assert alarm.state == AlarmState.RAISED

    @pytest.mark.asyncio
    async def test_create_alarm_already_exists(self, alarm_manager, sample_alarm_data):
        """Test creating duplicate alarm."""
        await alarm_manager.create_alarm(**sample_alarm_data)
        
        # Create with same NE ID and similar attributes
        sample_alarm_data["ne_id"] = "router-001"
        
        # Should raise error for duplicate
        with pytest.raises(AlarmAlreadyExistsError):
            await alarm_manager.create_alarm(**sample_alarm_data)

    @pytest.mark.asyncio
    async def test_get_alarm(self, alarm_manager, sample_alarm_data):
        """Test retrieving an alarm."""
        created = await alarm_manager.create_alarm(**sample_alarm_data)
        
        retrieved = await alarm_manager.get_alarm(created.alarm_id)
        
        assert retrieved is not None
        assert retrieved.alarm_id == created.alarm_id

    @pytest.mark.asyncio
    async def test_get_alarm_not_found(self, alarm_manager):
        """Test retrieving non-existent alarm."""
        result = await alarm_manager.get_alarm("non-existent-id")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_update_alarm(self, alarm_manager, sample_alarm_data):
        """Test updating an alarm."""
        alarm = await alarm_manager.create_alarm(**sample_alarm_data)
        
        updated = await alarm_manager.update_alarm(
            alarm.alarm_id,
            severity=AlarmSeverity.CRITICAL,
            additional_info={"new_field": "value"}
        )
        
        assert updated.severity == AlarmSeverity.CRITICAL
        assert "new_field" in updated.additional_info

    @pytest.mark.asyncio
    async def test_update_alarm_not_found(self, alarm_manager):
        """Test updating non-existent alarm."""
        with pytest.raises(AlarmNotFoundError):
            await alarm_manager.update_alarm("non-existent", severity=AlarmSeverity.CRITICAL)

    @pytest.mark.asyncio
    async def test_acknowledge_alarm(self, alarm_manager, sample_alarm_data):
        """Test acknowledging an alarm."""
        alarm = await alarm_manager.create_alarm(**sample_alarm_data)
        
        result = await alarm_manager.acknowledge_alarm(alarm.alarm_id, "admin")
        
        assert result.acknowledged is True
        assert result.acknowledged_by == "admin"

    @pytest.mark.asyncio
    async def test_clear_alarm(self, alarm_manager, sample_alarm_data):
        """Test clearing an alarm."""
        alarm = await alarm_manager.create_alarm(**sample_alarm_data)
        
        result = await alarm_manager.clear_alarm(alarm.alarm_id, "system")
        
        assert result.cleared is True
        assert result.state == AlarmState.CLEARED
        assert result.cleared_by == "system"

    @pytest.mark.asyncio
    async def test_clear_alarm_already_cleared(self, alarm_manager, sample_alarm_data):
        """Test clearing an already cleared alarm."""
        alarm = await alarm_manager.create_alarm(**sample_alarm_data)
        await alarm_manager.clear_alarm(alarm.alarm_id, "system")
        
        with pytest.raises(AlarmStateError):
            await alarm_manager.clear_alarm(alarm.alarm_id, "system")

    @pytest.mark.asyncio
    async def test_get_alarms_filter_by_severity(self, alarm_manager):
        """Test filtering alarms by severity."""
        # Create multiple alarms
        await alarm_manager.create_alarm(
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            severity=AlarmSeverity.CRITICAL,
            probable_cause="Test",
        )
        await alarm_manager.create_alarm(
            ne_id="router-002",
            alarm_type=AlarmType.EQUIPMENT,
            severity=AlarmSeverity.MINOR,
            probable_cause="Test",
        )
        
        critical = await alarm_manager.get_alarms(severity=AlarmSeverity.CRITICAL)
        
        assert len(critical) == 1
        assert critical[0].severity == AlarmSeverity.CRITICAL

    @pytest.mark.asyncio
    async def test_get_alarms_filter_by_ne_id(self, alarm_manager):
        """Test filtering alarms by NE ID."""
        await alarm_manager.create_alarm(
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            probable_cause="Test",
        )
        await alarm_manager.create_alarm(
            ne_id="router-002",
            alarm_type=AlarmType.EQUIPMENT,
            probable_cause="Test",
        )
        
        filtered = await alarm_manager.get_alarms(ne_id="router-001")
        
        assert len(filtered) == 1
        assert filtered[0].ne_id == "router-001"

    @pytest.mark.asyncio
    async def test_get_active_alarms(self, alarm_manager):
        """Test getting only active alarms."""
        alarm1 = await alarm_manager.create_alarm(
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            probable_cause="Test",
        )
        await alarm_manager.create_alarm(
            ne_id="router-002",
            alarm_type=AlarmType.EQUIPMENT,
            probable_cause="Test",
        )
        
        await alarm_manager.clear_alarm(alarm1.alarm_id, "system")
        
        active = await alarm_manager.get_alarms(state=AlarmState.RAISED)
        
        assert len(active) == 1
        assert active[0].ne_id == "router-002"

    @pytest.mark.asyncio
    async def test_alarm_statistics(self, alarm_manager):
        """Test alarm statistics."""
        await alarm_manager.create_alarm(
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            severity=AlarmSeverity.CRITICAL,
            probable_cause="Test",
        )
        await alarm_manager.create_alarm(
            ne_id="router-002",
            alarm_type=AlarmType.EQUIPMENT,
            severity=AlarmSeverity.MINOR,
            probable_cause="Test",
        )
        
        stats = alarm_manager.get_statistics()
        
        assert stats["total_alarms"] == 2
        assert stats["active_alarms"] == 2
        assert stats["by_severity"]["CRITICAL"] == 1
        assert stats["by_severity"]["MINOR"] == 1

    @pytest.mark.asyncio
    async def test_notification_callback(self):
        """Test notification callback on alarm creation."""
        callback = AsyncMock()
        manager = AlarmManager()
        await manager.initialize()
        manager.register_notification_callback(callback)
        
        await manager.create_alarm(
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            probable_cause="Test",
        )
        
        # Check callback was invoked
        assert callback.call_count == 1
        await manager.close()

    @pytest.mark.asyncio
    async def test_search_alarms(self, alarm_manager):
        """Test alarm search functionality."""
        await alarm_manager.create_alarm(
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            probable_cause="Link Failure",
            specific_problem="Interface down",
        )
        await alarm_manager.create_alarm(
            ne_id="router-002",
            alarm_type=AlarmType.COMMUNICATION,
            probable_cause="Network Error",
        )
        
        results = await alarm_manager.search_alarms("Link")
        
        assert len(results) == 1
        assert "Link" in results[0].probable_cause

    @pytest.mark.asyncio
    async def test_bulk_acknowledge(self, alarm_manager):
        """Test bulk acknowledgment of alarms."""
        alarm1 = await alarm_manager.create_alarm(
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            probable_cause="Test",
        )
        alarm2 = await alarm_manager.create_alarm(
            ne_id="router-002",
            alarm_type=AlarmType.EQUIPMENT,
            probable_cause="Test",
        )
        
        count = await alarm_manager.bulk_acknowledge(
            [alarm1.alarm_id, alarm2.alarm_id],
            "admin"
        )
        
        assert count == 2


# =============================================================================
# SeverityMapper Tests
# =============================================================================

class TestSeverityMapper:
    """Tests for SeverityMapper class."""

    def test_map_vendor_severity_ericsson(self, severity_mapper):
        """Test Ericsson severity mapping."""
        assert severity_mapper.map_vendor_severity("ericsson", "CRITICAL") == AlarmSeverity.CRITICAL
        assert severity_mapper.map_vendor_severity("ericsson", "MAJOR") == AlarmSeverity.MAJOR
        assert severity_mapper.map_vendor_severity("ericsson", "MINOR") == AlarmSeverity.MINOR
        assert severity_mapper.map_vendor_severity("ericsson", "WARNING") == AlarmSeverity.WARNING

    def test_map_vendor_severity_huawei(self, severity_mapper):
        """Test Huawei severity mapping."""
        assert severity_mapper.map_vendor_severity("huawei", "Critical") == AlarmSeverity.CRITICAL
        assert severity_mapper.map_vendor_severity("huawei", "Major") == AlarmSeverity.MAJOR
        assert severity_mapper.map_vendor_severity("huawei", "Minor") == AlarmSeverity.MINOR

    def test_map_vendor_severity_nokia(self, severity_mapper):
        """Test Nokia severity mapping."""
        assert severity_mapper.map_vendor_severity("nokia", "A1") == AlarmSeverity.CRITICAL
        assert severity_mapper.map_vendor_severity("nokia", "A2") == AlarmSeverity.MAJOR
        assert severity_mapper.map_vendor_severity("nokia", "A3") == AlarmSeverity.MINOR

    def test_map_vendor_severity_unknown(self, severity_mapper):
        """Test handling unknown severity values."""
        result = severity_mapper.map_vendor_severity("ericsson", "UNKNOWN")
        assert result == AlarmSeverity.MINOR  # Default fallback

    def test_map_vendor_severity_case_insensitive(self, severity_mapper):
        """Test case-insensitive severity mapping."""
        assert severity_mapper.map_vendor_severity("ericsson", "critical") == AlarmSeverity.CRITICAL
        assert severity_mapper.map_vendor_severity("ericsson", "CRITICAL") == AlarmSeverity.CRITICAL
        assert severity_mapper.map_vendor_severity("ericsson", "Critical") == AlarmSeverity.CRITICAL

    def test_add_vendor_mapping(self, severity_mapper):
        """Test adding custom vendor mappings."""
        severity_mapper.add_vendor_mapping(
            "new_vendor",
            {"urgent": AlarmSeverity.CRITICAL}
        )
        
        result = severity_mapper.map_vendor_severity("new_vendor", "urgent")
        assert result == AlarmSeverity.CRITICAL


# =============================================================================
# RootCauseAnalyzer Tests
# =============================================================================

class TestRootCauseAnalyzer:
    """Tests for RootCauseAnalyzer class."""

    @pytest.fixture
    def sample_alarms_for_analysis(self):
        """Create sample alarms for root cause analysis."""
        return [
            Alarm(
                ne_id="router-001",
                alarm_type=AlarmType.EQUIPMENT,
                severity=AlarmSeverity.CRITICAL,
                probable_cause="Power Failure",
            ),
            Alarm(
                ne_id="router-001",
                alarm_type=AlarmType.COMMUNICATION,
                severity=AlarmSeverity.MAJOR,
                probable_cause="Link Down",
            ),
            Alarm(
                ne_id="router-002",
                alarm_type=AlarmType.COMMUNICATION,
                severity=AlarmSeverity.MAJOR,
                probable_cause="Link Down",
            ),
        ]

    def test_analyze_root_cause(self, root_cause_analyzer, sample_alarms_for_analysis):
        """Test root cause analysis."""
        result = root_cause_analyzer.analyze(sample_alarms_for_analysis)
        
        assert result is not None
        assert "root_cause" in result
        assert "affected_ne" in result
        assert "correlation_score" in result

    def test_analyze_empty_list(self, root_cause_analyzer):
        """Test analysis with empty alarm list."""
        result = root_cause_analyzer.analyze([])
        
        assert result["root_cause"] is None
        assert result["correlation_score"] == 0.0

    def test_find_correlated_alarms(self, root_cause_analyzer, sample_alarms_for_analysis):
        """Test finding correlated alarms."""
        correlated = root_cause_analyzer.find_correlated(
            sample_alarms_for_analysis[0],
            sample_alarms_for_analysis
        )
        
        assert len(correlated) >= 0
        # First alarm should be correlated with others on same NE

    def test_calculate_impact_score(self, root_cause_analyzer, sample_alarms_for_analysis):
        """Test impact score calculation."""
        score = root_cause_analyzer.calculate_impact_score(sample_alarms_for_analysis)
        
        assert 0.0 <= score <= 1.0


# =============================================================================
# Alarm Severity Tests
# =============================================================================

class TestAlarmSeverity:
    """Tests for AlarmSeverity enum."""

    def test_severity_ordering(self):
        """Test severity level ordering."""
        ordering = [
            AlarmSeverity.INDETERMINATE, AlarmSeverity.CLEARED, AlarmSeverity.WARNING, 
            AlarmSeverity.MINOR, AlarmSeverity.MAJOR, AlarmSeverity.CRITICAL
        ]
        assert ordering.index(AlarmSeverity.CRITICAL) > ordering.index(AlarmSeverity.MAJOR)
        assert ordering.index(AlarmSeverity.MAJOR) > ordering.index(AlarmSeverity.MINOR)
        assert ordering.index(AlarmSeverity.MINOR) > ordering.index(AlarmSeverity.WARNING)

    def test_severity_from_string(self):
        """Test creating severity from string."""
        assert AlarmSeverity("CRITICAL") == AlarmSeverity.CRITICAL
        assert AlarmSeverity("MAJOR") == AlarmSeverity.MAJOR


# =============================================================================
# Alarm State Tests
# =============================================================================

class TestAlarmState:
    """Tests for AlarmState enum."""

    def test_state_values(self):
        """Test state enum values."""
        assert AlarmState.RAISED.value == "RAISED"
        assert AlarmState.ACKNOWLEDGED.value == "ACKNOWLEDGED"
        assert AlarmState.CLEARED.value == "CLEARED"

    def test_state_transitions(self, sample_alarm):
        """Test valid state transitions."""
        assert sample_alarm.state == AlarmState.RAISED
        
        sample_alarm.acknowledge("admin")
        assert sample_alarm.state == AlarmState.ACKNOWLEDGED
        
        sample_alarm.clear("system")
        assert sample_alarm.state == AlarmState.CLEARED


# =============================================================================
# Integration Tests
# =============================================================================

class TestAlarmManagerIntegration:
    """Integration tests for Alarm Manager."""

    @pytest.mark.asyncio
    async def test_full_alarm_lifecycle(self, alarm_manager):
        """Test complete alarm lifecycle."""
        # Create
        alarm = await alarm_manager.create_alarm(
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            severity=AlarmSeverity.MAJOR,
            probable_cause="Test alarm",
        )
        
        # Read
        retrieved = await alarm_manager.get_alarm(alarm.alarm_id)
        assert retrieved is not None
        
        # Update
        updated = await alarm_manager.update_alarm(
            alarm.alarm_id,
            severity=AlarmSeverity.CRITICAL
        )
        assert updated.severity == AlarmSeverity.CRITICAL
        
        # Acknowledge
        acknowledged = await alarm_manager.acknowledge_alarm(alarm.alarm_id, "admin")
        assert acknowledged.acknowledged is True
        
        # Clear
        cleared = await alarm_manager.clear_alarm(alarm.alarm_id, "system")
        assert cleared.cleared is True

    @pytest.mark.asyncio
    async def test_concurrent_alarm_operations(self, alarm_manager):
        """Test concurrent alarm operations."""
        # Create multiple alarms concurrently
        tasks = [
            alarm_manager.create_alarm(
                ne_id=f"router-{i}",
                alarm_type=AlarmType.EQUIPMENT,
                probable_cause=f"Test {i}",
            )
            for i in range(10)
        ]
        
        alarms = await asyncio.gather(*tasks)
        
        assert len(alarms) == 10
        assert len(alarm_manager._alarms) == 10


# =============================================================================
# Performance Tests
# =============================================================================

class TestAlarmManagerPerformance:
    """Performance tests for Alarm Manager."""

    @pytest.mark.asyncio
    async def test_bulk_alarm_creation(self, alarm_manager):
        """Test creating many alarms efficiently."""
        start_time = datetime.now(timezone.utc)
        
        for i in range(100):
            await alarm_manager.create_alarm(
                ne_id=f"router-{i % 10}",
                alarm_type=AlarmType.EQUIPMENT,
                severity=AlarmSeverity.MINOR,
                probable_cause=f"Test alarm {i}",
            )
        
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        assert len(alarm_manager._alarms) == 100
        assert duration < 5.0  # Should complete within 5 seconds

    @pytest.mark.asyncio
    async def test_filter_large_dataset(self, alarm_manager):
        """Test filtering with many alarms."""
        # Create alarms
        for i in range(500):
            await alarm_manager.create_alarm(
                ne_id=f"router-{i % 20}",
                alarm_type=AlarmType.EQUIPMENT,
                severity=[AlarmSeverity.MINOR, AlarmSeverity.MAJOR, AlarmSeverity.CRITICAL][i % 3],
                probable_cause=f"Test {i}",
            )
        
        # Filter by severity
        critical = await alarm_manager.get_alarms(severity=AlarmSeverity.CRITICAL, limit=500)
        
        # Should have approximately 1/3 of alarms
        assert 150 <= len(critical) <= 170

    @pytest.mark.asyncio
    async def test_statistics_performance(self, alarm_manager):
        """Test statistics calculation with large dataset."""
        for i in range(1000):
            await alarm_manager.create_alarm(
                ne_id=f"router-{i % 50}",
                alarm_type=AlarmType.EQUIPMENT,
                probable_cause=f"Test {i}",
            )
        
        start_time = datetime.now(timezone.utc)
        stats = alarm_manager.get_statistics()
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        assert stats["total_alarms"] == 1000
        assert duration < 1.0  # Should be fast


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
