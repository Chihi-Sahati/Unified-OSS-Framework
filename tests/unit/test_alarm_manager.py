"""
Unit tests for Alarm Manager.
"""

import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, AsyncMock, patch
import uuid

from unified_oss.fcaps.fault.alarm_manager import (
    AlarmManager,
    AlarmLifecycle,
    AlarmNotifier,
    AlarmState,
    AlarmSeverity,
    AlarmSource,
    Alarm,
    AlarmStateError,
    AlarmNotFoundError,
)


@pytest.fixture
def alarm_manager():
    """Create AlarmManager instance for testing."""
    return AlarmManager()


@pytest.fixture
def sample_alarm_data():
    """Sample alarm data for testing."""
    return {
        "alarmId": "12345",
        "alarmName": "Radio Unit Connection Failure",
        "perceivedSeverity": "critical",
        "vendor": "ERICSSON",
        "moId": "SubNetwork=ROOT,ManagedElement=ENB-HCM-001",
        "ne_id": "ENB-HCM-001",
        "ne_name": "eNodeB HCM Site 001",
        "ne_type": "ENODEB",
        "raised_at": datetime.now(timezone.utc).isoformat(),
        "probableCause": "HARDWARE_FAILURE",
        "resource_path": "/network/sites/HCM_SITE_001/elements/ENB-HCM-001",
    }


class TestAlarmManager:
    """Test cases for AlarmManager."""
    
    @pytest.mark.asyncio
    async def test_ingest_alarm_creates_alarm(self, alarm_manager, sample_alarm_data):
        """Test that ingesting alarm creates a new alarm."""
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        assert alarm is not None
        assert alarm.alarm_text == sample_alarm_data["alarmName"]
        assert alarm.state == AlarmState.RAISED
    
    @pytest.mark.asyncio
    async def test_ingest_alarm_normalizes_severity(self, alarm_manager, sample_alarm_data):
        """Test that severity is normalized from vendor format."""
        sample_alarm_data["perceivedSeverity"] = "critical"  # Ericsson format
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        assert alarm.severity == AlarmSeverity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_ingest_alarm_huawei_severity(self, alarm_manager, sample_alarm_data):
        """Test Huawei integer severity normalization."""
        huawei_data = {
            "alarmId": "H-1",
            "severity": 1,  # Huawei critical
            "vendor": "HUAWEI",
            "ne_id": "NE-01",
        }
        
        alarm = await alarm_manager.ingest_alarm(huawei_data)
        assert alarm.severity == AlarmSeverity.CRITICAL
    
    @pytest.mark.asyncio
    async def test_acknowledge_alarm(self, alarm_manager, sample_alarm_data):
        """Test alarm acknowledgment."""
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        result = await alarm_manager.acknowledge_alarm(
            alarm.alarm_id,
            user="test_user",
            comment="Test acknowledgment"
        )
        
        assert result.state == AlarmState.ACKNOWLEDGED
        assert result.acknowledged_by == "test_user"
        assert result.acknowledged is True
    
    @pytest.mark.asyncio
    async def test_acknowledge_nonexistent_alarm_raises(self, alarm_manager):
        """Test that acknowledging nonexistent alarm raises error."""
        with pytest.raises(AlarmNotFoundError):
            await alarm_manager.acknowledge_alarm(
                "nonexistent-id",
                user="test_user"
            )
    
    @pytest.mark.asyncio
    async def test_clear_alarm(self, alarm_manager, sample_alarm_data):
        """Test alarm clearing."""
        alarm = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        result = await alarm_manager.clear_alarm(
            alarm.alarm_id,
            user="test_user",
            reason="RESOLVED"
        )
        
        assert result.state == AlarmState.CLEARED
        assert result.cleared_by == "test_user"
        assert result.cleared is True
    
    @pytest.mark.asyncio
    async def test_get_active_alarms(self, alarm_manager, sample_alarm_data):
        """Test retrieving active alarms."""
        await alarm_manager.ingest_alarm(sample_alarm_data)
        
        active_alarms = await alarm_manager.get_active_alarms()
        
        assert len(active_alarms) >= 1
        assert all(a.state != AlarmState.CLEARED for a in active_alarms)
    
    @pytest.mark.asyncio
    async def test_deduplication(self, alarm_manager, sample_alarm_data):
        """Test that duplicate alarms are deduplicated."""
        # Setup fingerprints etc happens in ingest_alarm
        alarm1 = await alarm_manager.ingest_alarm(sample_alarm_data)
        alarm2 = await alarm_manager.ingest_alarm(sample_alarm_data)
        
        # Should return same alarm for duplicate
        assert alarm1.alarm_id == alarm2.alarm_id
        assert alarm_manager._stats["total_deduplicated"] >= 1


class TestAlarmLifecycle:
    """Test cases for AlarmLifecycle."""
    
    def test_can_transition_active_to_acknowledged(self):
        """Test valid transition."""
        lifecycle = AlarmLifecycle()
        alarm = Alarm(state=AlarmState.RAISED)
        
        assert lifecycle.can_transition(AlarmState.RAISED, AlarmState.ACKNOWLEDGED) is True
        lifecycle.transition(alarm, AlarmState.ACKNOWLEDGED, user="admin")
        
        assert alarm.state == AlarmState.ACKNOWLEDGED
    
    def test_invalid_transition_raises(self):
        """Test that invalid transition raises error."""
        lifecycle = AlarmLifecycle()
        alarm = Alarm(state=AlarmState.CLEARED)
        
        # Cannot transition from CLEARED (terminal state)
        with pytest.raises(AlarmStateError):
            lifecycle.transition(alarm, AlarmState.RAISED)


class TestAlarmNotifier:
    """Test cases for AlarmNotifier."""
    
    @pytest.fixture
    async def notifier(self):
        """Create AlarmNotifier instance."""
        n = AlarmNotifier()
        await n.start()
        yield n
        await n.stop()
    
    @pytest.mark.asyncio
    async def test_subscribe_and_notify(self, notifier):
        """Test subscription and notification flow."""
        received = []
        
        async def callback(notification):
            received.append(notification)
        
        sub_id = await notifier.subscribe("test_client", callback)
        alarm = Alarm(alarm_id="notif-1", alarm_text="Test")
        await notifier.notify(alarm)
        
        # Wait a bit for async delivery
        await asyncio.sleep(0.1)
        
        assert len(received) == 1
        assert received[0]["alarm"]["alarm_id"] == "notif-1"
    
    @pytest.mark.asyncio
    async def test_unsubscribe(self, notifier):
        """Test unsubscribing from notifications."""
        received = []
        
        async def callback(notification):
            received.append(notification)
        
        sub_id = await notifier.subscribe("test_client", callback)
        await notifier.unsubscribe(sub_id)
        
        alarm = Alarm(alarm_id="notif-2", alarm_text="Test")
        await notifier.notify(alarm)
        await asyncio.sleep(0.1)
        
        assert len(received) == 0


class TestAlarmSeverityNormalization:
    """Test severity normalization."""
    
    def test_ericsson_string_normalization(self, alarm_manager):
        """Test Ericsson string severity normalization."""
        assert alarm_manager._map_severity("critical", AlarmSource.ERICSSON) == AlarmSeverity.CRITICAL
        assert alarm_manager._map_severity("major", AlarmSource.ERICSSON) == AlarmSeverity.MAJOR
        assert alarm_manager._map_severity("minor", AlarmSource.ERICSSON) == AlarmSeverity.MINOR
    
    def test_huawei_int_normalization(self, alarm_manager):
        """Test Huawei integer severity normalization."""
        assert alarm_manager._map_severity(1, AlarmSource.HUAWEI) == AlarmSeverity.CRITICAL
        assert alarm_manager._map_severity(2, AlarmSource.HUAWEI) == AlarmSeverity.MAJOR
