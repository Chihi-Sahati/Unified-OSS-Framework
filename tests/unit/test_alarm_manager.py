"""
Unit tests for Alarm Manager.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock, patch
import uuid

from unified_oss.fcaps.fault.alarm_manager import (
    AlarmManager,
    AlarmLifecycle,
    AlarmNotifier,
    AlarmState,
    AlarmSeverity,
)


@pytest.fixture
def alarm_manager():
    """Create AlarmManager instance for testing."""
    return AlarmManager()


@pytest.fixture
def sample_alarm_data():
    """Sample alarm data for testing."""
    return {
        "alarm_id": str(uuid.uuid4()),
        "alarm_name": "Radio Unit Connection Failure",
        "alarm_type": "EQUIPMENT_ALARM",
        "severity": "critical",
        "vendor": "ERICSSON",
        "ne_id": "ENB-HCM-001",
        "ne_name": "eNodeB HCM Site 001",
        "ne_type": "ENODEB",
        "timestamp": datetime.utcnow().isoformat(),
        "probable_cause": "HARDWARE_FAILURE",
        "affected_resource": "/network/ERICSSON/ENODEB/ENB-HCM-001",
    }


class TestAlarmManager:
    """Test cases for AlarmManager."""
    
    @pytest.mark.asyncio
    async def test_ingest_alarm_creates_alarm(self, alarm_manager, sample_alarm_data):
        """Test that ingesting alarm creates a new alarm."""
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        assert alarm is not None
        assert alarm.alarm_name == sample_alarm_data["alarm_name"]
        assert alarm.state == AlarmState.ACTIVE
    
    @pytest.mark.asyncio
    async def test_ingest_alarm_normalizes_severity(self, alarm_manager, sample_alarm_data):
        """Test that severity is normalized from vendor format."""
        sample_alarm_data["severity"] = "critical"  # Ericsson format
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        assert alarm.severity == AlarmSeverity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_ingest_alarm_huawei_severity(self, alarm_manager, sample_alarm_data):
        """Test Huawei integer severity normalization."""
        sample_alarm_data["vendor"] = "HUAWEI"
        sample_alarm_data["severity"] = 1  # Huawei critical
        
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        assert alarm.severity == AlarmSeverity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_acknowledge_alarm(self, alarm_manager, sample_alarm_data):
        """Test alarm acknowledgment."""
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        result = await alarm_manager.acknowledge_alarm(
            alarm.alarm_id,
            acknowledged_by="test_user",
            notes="Test acknowledgment"
        )
        
        assert result.state == AlarmState.ACKNOWLEDGED
        assert result.acknowledged_by == "test_user"
    
    @pytest.mark.asyncio
    async def test_acknowledge_nonexistent_alarm_raises(self, alarm_manager):
        """Test that acknowledging nonexistent alarm raises error."""
        with pytest.raises(Exception):
            await alarm_manager.acknowledge_alarm(
                "nonexistent-id",
                acknowledged_by="test_user"
            )
    
    @pytest.mark.asyncio
    async def test_clear_alarm(self, alarm_manager, sample_alarm_data):
        """Test alarm clearing."""
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        result = await alarm_manager.clear_alarm(
            alarm.alarm_id,
            cleared_by="test_user",
            clearance_reason="RESOLVED"
        )
        
        assert result.state == AlarmState.CLEARED
        assert result.cleared_by == "test_user"
    
    @pytest.mark.asyncio
    async def test_get_active_alarms(self, alarm_manager, sample_alarm_data):
        """Test retrieving active alarms."""
        await alarm_manager.ingest_alarm(sample_alarm_data)
        
        active_alarms = await alarm_manager.get_active_alarms()
        
        assert len(active_alarms) >= 1
        assert all(a.state != AlarmState.CLEARED for a in active_alarms)
    
    @pytest.mark.asyncio
    async def test_get_active_alarms_with_filters(self, alarm_manager, sample_alarm_data):
        """Test filtering active alarms."""
        await alarm_manager.ingest_alarm(sample_alarm_data)
        
        filtered = await alarm_manager.get_active_alarms(
            vendor="ERICSSON",
            severity=AlarmSeverity.CRITICAL
        )
        
        assert all(a.vendor == "ERICSSON" for a in filtered)
    
    @pytest.mark.asyncio
    async def test_deduplication(self, alarm_manager, sample_alarm_data):
        """Test that duplicate alarms are deduplicated."""
        alarm1 = await alarm_manager.ingest_alarm(sample_alarm_data)
        alarm2 = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        # Should return same alarm for duplicate
        assert alarm1.alarm_id == alarm2.alarm_id
    
    @pytest.mark.asyncio
    async def test_alarm_lifecycle_transitions(self, alarm_manager, sample_alarm_data):
        """Test valid state transitions."""
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        # ACTIVE -> ACKNOWLEDGED
        await alarm_manager.acknowledge_alarm(alarm.alarm_id, "user1")
        
        # ACKNOWLEDGED -> CLEARED
        await alarm_manager.clear_alarm(alarm.alarm_id, "user2", "RESOLVED")


class TestAlarmLifecycle:
    """Test cases for AlarmLifecycle."""
    
    def test_initial_state_is_active(self):
        """Test that initial state is ACTIVE."""
        lifecycle = AlarmLifecycle()
        assert lifecycle.current_state == AlarmState.ACTIVE
    
    def test_can_transition_active_to_acknowledged(self):
        """Test valid transition ACTIVE -> ACKNOWLEDGED."""
        lifecycle = AlarmLifecycle()
        lifecycle.transition(AlarmState.ACKNOWLEDGED)
        
        assert lifecycle.current_state == AlarmState.ACKNOWLEDGED
    
    def test_can_transition_active_to_cleared(self):
        """Test valid transition ACTIVE -> CLEARED."""
        lifecycle = AlarmLifecycle()
        lifecycle.transition(AlarmState.CLEARED)
        
        assert lifecycle.current_state == AlarmState.CLEARED
    
    def test_invalid_transition_raises(self):
        """Test that invalid transition raises error."""
        lifecycle = AlarmLifecycle()
        lifecycle.transition(AlarmState.CLEARED)
        
        # Cannot transition from CLEARED
        with pytest.raises(Exception):
            lifecycle.transition(AlarmState.ACTIVE)


class TestAlarmNotifier:
    """Test cases for AlarmNotifier."""
    
    @pytest.fixture
    def notifier(self):
        """Create AlarmNotifier instance."""
        return AlarmNotifier()
    
    @pytest.mark.asyncio
    async def test_subscribe_and_notify(self, notifier, sample_alarm_data):
        """Test subscription and notification flow."""
        received = []
        
        async def callback(alarm):
            received.append(alarm)
        
        await notifier.subscribe("test_client", callback)
        await notifier.notify(sample_alarm_data)
        
        assert len(received) == 1
    
    @pytest.mark.asyncio
    async def test_unsubscribe(self, notifier, sample_alarm_data):
        """Test unsubscribing from notifications."""
        received = []
        
        async def callback(alarm):
            received.append(alarm)
        
        await notifier.subscribe("test_client", callback)
        await notifier.unsubscribe("test_client")
        await notifier.notify(sample_alarm_data)
        
        assert len(received) == 0
    
    @pytest.mark.asyncio
    async def test_filter_by_severity(self, notifier, sample_alarm_data):
        """Test notification filtering by severity."""
        received = []
        
        async def callback(alarm):
            received.append(alarm)
        
        await notifier.subscribe(
            "test_client",
            callback,
            filter_severity=[AlarmSeverity.CRITICAL]
        )
        
        # Notify with matching severity
        sample_alarm_data["severity"] = "critical"
        await notifier.notify(sample_alarm_data)
        
        # Notify with non-matching severity
        sample_alarm_data["alarm_id"] = str(uuid.uuid4())
        sample_alarm_data["severity"] = "warning"
        await notifier.notify(sample_alarm_data)
        
        # Should only receive critical
        assert len(received) == 1


class TestAlarmSeverityNormalization:
    """Test severity normalization."""
    
    def test_ericsson_string_normalization(self, alarm_manager):
        """Test Ericsson string severity normalization."""
        assert alarm_manager.normalize_severity("critical", "ERICSSON") == AlarmSeverity.CRITICAL
        assert alarm_manager.normalize_severity("major", "ERICSSON") == AlarmSeverity.MAJOR
        assert alarm_manager.normalize_severity("minor", "ERICSSON") == AlarmSeverity.MINOR
        assert alarm_manager.normalize_severity("warning", "ERICSSON") == AlarmSeverity.WARNING
    
    def test_huawei_int_normalization(self, alarm_manager):
        """Test Huawei integer severity normalization."""
        assert alarm_manager.normalize_severity(1, "HUAWEI") == AlarmSeverity.CRITICAL
        assert alarm_manager.normalize_severity(2, "HUAWEI") == AlarmSeverity.MAJOR
        assert alarm_manager.normalize_severity(3, "HUAWEI") == AlarmSeverity.MINOR
        assert alarm_manager.normalize_severity(4, "HUAWEI") == AlarmSeverity.WARNING
    
    def test_unknown_severity_returns_indeterminate(self, alarm_manager):
        """Test that unknown severity returns INDETERMINATE."""
        assert alarm_manager.normalize_severity("unknown", "ERICSSON") == AlarmSeverity.INDETERMINATE
        assert alarm_manager.normalize_severity(99, "HUAWEI") == AlarmSeverity.INDETERMINATE
