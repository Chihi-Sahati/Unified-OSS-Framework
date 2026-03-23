"""
Unit tests for Alarm Correlation module.

Tests cover alarm correlation engine, root cause analysis, and correlation
algorithms including temporal, spatial, and causal correlation.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from unified_oss.fcaps.fault.correlation import (
    CorrelationEngine,
    CorrelationResult,
    CorrelationType,
    CorrelationRule,
    RootCauseCandidate,
    AlarmGrouper,
    CorrelationMetrics,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def correlation_engine():
    """Create a CorrelationEngine instance for testing."""
    return CorrelationEngine()


@pytest.fixture
def alarm_grouper():
    """Create an AlarmGrouper instance for testing."""
    return AlarmGrouper()


@pytest.fixture
def sample_alarms():
    """Create sample alarms for correlation testing."""
    from unified_oss.fcaps.fault.alarm_manager import Alarm, AlarmType, AlarmSeverity
    
    now = datetime.now(timezone.utc)
    return [
        Alarm(
            alarm_id="alarm-001",
            ne_id="router-001",
            alarm_type=AlarmType.EQUIPMENT,
            severity=AlarmSeverity.CRITICAL,
            probable_cause="Power Failure",
            timestamp=now,
        ),
        Alarm(
            alarm_id="alarm-002",
            ne_id="router-001",
            alarm_type=AlarmType.COMMUNICATION,
            severity=AlarmSeverity.MAJOR,
            probable_cause="Link Down",
            timestamp=now + timedelta(seconds=30),
        ),
        Alarm(
            alarm_id="alarm-003",
            ne_id="router-002",
            alarm_type=AlarmType.COMMUNICATION,
            severity=AlarmSeverity.MAJOR,
            probable_cause="Link Down",
            timestamp=now + timedelta(seconds=45),
        ),
        Alarm(
            alarm_id="alarm-004",
            ne_id="router-003",
            alarm_type=AlarmType.EQUIPMENT,
            severity=AlarmSeverity.MINOR,
            probable_cause="Temperature High",
            timestamp=now + timedelta(minutes=10),
        ),
    ]


@pytest.fixture
def correlation_rule():
    """Create a sample correlation rule."""
    return CorrelationRule(
        rule_id="rule-001",
        name="Power Failure Cascade",
        description="Detects cascade failures from power issues",
        correlation_type=CorrelationType.CAUSAL,
        conditions={
            "root_cause_pattern": {"probable_cause": "Power Failure"},
            "dependent_pattern": {"alarm_type": "COMMUNICATION"},
            "time_window_seconds": 300,
        },
        priority=100,
    )


# =============================================================================
# CorrelationEngine Tests
# =============================================================================

class TestCorrelationEngine:
    """Tests for CorrelationEngine class."""

    @pytest.mark.asyncio
    async def test_correlate_alarms(self, correlation_engine, sample_alarms):
        """Test basic alarm correlation."""
        result = await correlation_engine.correlate(sample_alarms)
        
        assert result is not None
        assert isinstance(result, CorrelationResult)
        assert result.total_alarms == len(sample_alarms)

    @pytest.mark.asyncio
    async def test_correlate_empty_list(self, correlation_engine):
        """Test correlation with empty alarm list."""
        result = await correlation_engine.correlate([])
        
        assert result.total_alarms == 0
        assert result.correlation_groups == []

    @pytest.mark.asyncio
    async def test_temporal_correlation(self, correlation_engine, sample_alarms):
        """Test temporal correlation logic."""
        result = await correlation_engine.correlate(
            sample_alarms,
            correlation_type=CorrelationType.TEMPORAL
        )
        
        # Should group alarms that occurred close in time
        assert len(result.correlation_groups) > 0

    @pytest.mark.asyncio
    async def test_spatial_correlation(self, correlation_engine, sample_alarms):
        """Test spatial correlation by network element."""
        result = await correlation_engine.correlate(
            sample_alarms,
            correlation_type=CorrelationType.SPATIAL
        )
        
        # Should group alarms by NE
        ne_ids_in_groups = set()
        for group in result.correlation_groups:
            for alarm in group.alarms:
                ne_ids_in_groups.add(alarm.ne_id)

    @pytest.mark.asyncio
    async def test_causal_correlation(self, correlation_engine, sample_alarms):
        """Test causal correlation logic."""
        result = await correlation_engine.correlate(
            sample_alarms,
            correlation_type=CorrelationType.CAUSAL
        )
        
        # Should identify root cause candidates
        assert result.root_cause_candidates is not None

    @pytest.mark.asyncio
    async def test_add_correlation_rule(self, correlation_engine, correlation_rule):
        """Test adding custom correlation rules."""
        correlation_engine.add_rule(correlation_rule)
        
        assert correlation_rule.rule_id in correlation_engine._rules

    @pytest.mark.asyncio
    async def test_remove_correlation_rule(self, correlation_engine, correlation_rule):
        """Test removing correlation rules."""
        correlation_engine.add_rule(correlation_rule)
        correlation_engine.remove_rule(correlation_rule.rule_id)
        
        assert correlation_rule.rule_id not in correlation_engine._rules

    @pytest.mark.asyncio
    async def test_find_root_cause(self, correlation_engine, sample_alarms):
        """Test root cause identification."""
        result = await correlation_engine.correlate(sample_alarms)
        
        # Should identify most likely root cause
        if result.root_cause_candidates:
            root_cause = result.root_cause_candidates[0]
            assert isinstance(root_cause, RootCauseCandidate)
            assert root_cause.alarm is not None
            assert root_cause.confidence >= 0.0


# =============================================================================
# AlarmGrouper Tests
# =============================================================================

class TestAlarmGrouper:
    """Tests for AlarmGrouper class."""

    def test_group_by_ne(self, alarm_grouper, sample_alarms):
        """Test grouping alarms by network element."""
        groups = alarm_grouper.group_by_ne(sample_alarms)
        
        assert len(groups) == 3  # router-001, router-002, router-003

    def test_group_by_severity(self, alarm_grouper, sample_alarms):
        """Test grouping alarms by severity."""
        groups = alarm_grouper.group_by_severity(sample_alarms)
        
        severities = set(groups.keys())
        assert "CRITICAL" in severities or "MAJOR" in severities

    def test_group_by_time_window(self, alarm_grouper, sample_alarms):
        """Test grouping alarms by time window."""
        groups = alarm_grouper.group_by_time_window(
            sample_alarms,
            window_seconds=60
        )
        
        # Alarms within 60 seconds should be grouped
        assert len(groups) >= 1

    def test_group_by_alarm_type(self, alarm_grouper, sample_alarms):
        """Test grouping alarms by type."""
        groups = alarm_grouper.group_by_alarm_type(sample_alarms)
        
        types = set(groups.keys())
        assert "EQUIPMENT" in types or "COMMUNICATION" in types


# =============================================================================
# CorrelationResult Tests
# =============================================================================

class TestCorrelationResult:
    """Tests for CorrelationResult dataclass."""

    def test_result_creation(self, sample_alarms):
        """Test creating correlation result."""
        result = CorrelationResult(
            total_alarms=len(sample_alarms),
            correlation_groups=[],
            root_cause_candidates=[],
        )
        
        assert result.total_alarms == 4
        assert result.processing_time_ms == 0.0

    def test_result_to_dict(self, sample_alarms):
        """Test result serialization."""
        result = CorrelationResult(
            total_alarms=len(sample_alarms),
            correlation_groups=[],
            root_cause_candidates=[],
        )
        
        result_dict = result.to_dict()
        
        assert "total_alarms" in result_dict
        assert "correlation_groups" in result_dict


# =============================================================================
# CorrelationRule Tests
# =============================================================================

class TestCorrelationRule:
    """Tests for CorrelationRule dataclass."""

    def test_rule_creation(self):
        """Test creating a correlation rule."""
        rule = CorrelationRule(
            rule_id="test-rule",
            name="Test Rule",
            description="Test description",
            correlation_type=CorrelationType.TEMPORAL,
            conditions={"time_window_seconds": 300},
        )
        
        assert rule.rule_id == "test-rule"
        assert rule.enabled is True
        assert rule.priority == 0

    def test_rule_matches(self, correlation_rule, sample_alarms):
        """Test rule matching logic."""
        # Test if rule conditions match alarms
        matches = correlation_rule.matches(sample_alarms[0])
        
        # Based on conditions, check if it should match
        if "Power Failure" in sample_alarms[0].probable_cause:
            assert matches is True


# =============================================================================
# RootCauseCandidate Tests
# =============================================================================

class TestRootCauseCandidate:
    """Tests for RootCauseCandidate dataclass."""

    def test_candidate_creation(self, sample_alarms):
        """Test creating a root cause candidate."""
        from unified_oss.fcaps.fault.alarm_manager import AlarmSeverity
        
        candidate = RootCauseCandidate(
            alarm=sample_alarms[0],
            confidence=0.85,
            affected_alarms=sample_alarms[1:3],
            reasoning="Power failure likely caused communication alarms",
        )
        
        assert candidate.confidence == 0.85
        assert len(candidate.affected_alarms) == 2
        assert candidate.reasoning != ""

    def test_candidate_to_dict(self, sample_alarms):
        """Test candidate serialization."""
        candidate = RootCauseCandidate(
            alarm=sample_alarms[0],
            confidence=0.9,
            affected_alarms=[],
            reasoning="Test",
        )
        
        candidate_dict = candidate.to_dict()
        
        assert "confidence" in candidate_dict
        assert "reasoning" in candidate_dict


# =============================================================================
# CorrelationMetrics Tests
# =============================================================================

class TestCorrelationMetrics:
    """Tests for CorrelationMetrics class."""

    def test_metrics_creation(self):
        """Test creating metrics instance."""
        metrics = CorrelationMetrics()
        
        assert metrics.total_correlations == 0
        assert metrics.avg_processing_time_ms == 0.0

    def test_record_correlation(self):
        """Test recording correlation metrics."""
        metrics = CorrelationMetrics()
        
        metrics.record(processing_time_ms=50.0, alarms_processed=10)
        
        assert metrics.total_correlations == 1
        assert metrics.total_alarms_processed == 10

    def test_average_calculation(self):
        """Test average metrics calculation."""
        metrics = CorrelationMetrics()
        
        metrics.record(processing_time_ms=100.0, alarms_processed=10)
        metrics.record(processing_time_ms=200.0, alarms_processed=20)
        
        assert metrics.avg_processing_time_ms == 150.0


# =============================================================================
# Integration Tests
# =============================================================================

class TestCorrelationIntegration:
    """Integration tests for correlation engine."""

    @pytest.mark.asyncio
    async def test_full_correlation_workflow(self, correlation_engine, sample_alarms):
        """Test complete correlation workflow."""
        # Add custom rule
        rule = CorrelationRule(
            rule_id="custom-rule",
            name="Custom Correlation",
            description="Test rule",
            correlation_type=CorrelationType.TEMPORAL,
            conditions={"time_window_seconds": 120},
        )
        correlation_engine.add_rule(rule)
        
        # Run correlation
        result = await correlation_engine.correlate(sample_alarms)
        
        assert result.total_alarms == len(sample_alarms)
        assert result.processing_time_ms >= 0

    @pytest.mark.asyncio
    async def test_correlation_with_large_dataset(self, correlation_engine):
        """Test correlation with many alarms."""
        from unified_oss.fcaps.fault.alarm_manager import Alarm, AlarmType, AlarmSeverity
        
        # Create many alarms
        alarms = []
        now = datetime.now(timezone.utc)
        
        for i in range(100):
            alarms.append(Alarm(
                alarm_id=f"alarm-{i}",
                ne_id=f"router-{i % 10}",
                alarm_type=AlarmType.EQUIPMENT,
                severity=AlarmSeverity.MINOR,
                probable_cause=f"Test {i}",
                timestamp=now + timedelta(seconds=i % 60),
            ))
        
        result = await correlation_engine.correlate(alarms)
        
        assert result.total_alarms == 100


# =============================================================================
# Performance Tests
# =============================================================================

class TestCorrelationPerformance:
    """Performance tests for correlation engine."""

    @pytest.mark.asyncio
    async def test_correlation_performance(self, correlation_engine):
        """Test correlation with performance measurement."""
        from unified_oss.fcaps.fault.alarm_manager import Alarm, AlarmType, AlarmSeverity
        
        alarms = []
        now = datetime.now(timezone.utc)
        
        for i in range(500):
            alarms.append(Alarm(
                alarm_id=f"alarm-{i}",
                ne_id=f"router-{i % 20}",
                alarm_type=[AlarmType.EQUIPMENT, AlarmType.COMMUNICATION][i % 2],
                severity=[AlarmSeverity.MINOR, AlarmSeverity.MAJOR][i % 2],
                probable_cause=f"Cause {i % 5}",
                timestamp=now + timedelta(seconds=i % 100),
            ))
        
        start_time = datetime.now(timezone.utc)
        result = await correlation_engine.correlate(alarms)
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        
        assert duration < 5.0  # Should complete within 5 seconds
        assert result.total_alarms == 500


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
