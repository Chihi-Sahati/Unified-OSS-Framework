"""
Unit tests for Alarm Correlation Engine.
"""

import pytest
import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, AsyncMock
import uuid

from unified_oss.fcaps.fault.correlation import (
    AlarmCorrelator,
    CorrelationEngine,
    CorrelationRule,
    CorrelationType,
    CorrelationResult,
    CorrelatedAlarmGroup,
    CorrelationPriority,
)


@pytest.fixture
def correlator():
    """Create AlarmCorrelator instance for testing."""
    return AlarmCorrelator()


@pytest.fixture
def sample_alarms():
    """Sample alarms for correlation testing."""
    now = datetime.now(timezone.utc)
    
    return [
        {
            "alarm_id": "alarm-1",
            "alarm_text": "Site Power Failure",
            "severity": "CRITICAL",
            "vendor": "ERICSSON",
            "ne_id": "ENB-HCM-001",
            "resource_path": "/network/sites/HCM_SITE_001/elements/ENB-HCM-001",
            "raised_at": (now - timedelta(seconds=10)).isoformat(),
        },
        {
            "alarm_id": "alarm-2",
            "alarm_text": "Radio Unit Connection Failure",
            "severity": "MAJOR",
            "vendor": "ERICSSON",
            "ne_id": "ENB-HCM-001",
            "resource_path": "/network/sites/HCM_SITE_001/elements/ENB-HCM-001",
            "raised_at": (now - timedelta(seconds=5)).isoformat(),
        },
        {
            "alarm_id": "alarm-3",
            "alarm_text": "S1 Interface Down",
            "severity": "MAJOR",
            "vendor": "ERICSSON",
            "ne_id": "ENB-HCM-001",
            "resource_path": "/network/sites/HCM_SITE_001/elements/ENB-HCM-001",
            "raised_at": now.isoformat(),
        },
        {
            "alarm_id": "alarm-4",
            "alarm_text": "Transmission Link Failure",
            "severity": "CRITICAL",
            "vendor": "HUAWEI",
            "ne_id": "ENB-HCM-002",
            "resource_path": "/network/sites/HCM_SITE_002/elements/ENB-HCM-002",
            "raised_at": now.isoformat(),
        },
    ]


class TestAlarmCorrelator:
    """Test cases for AlarmCorrelator."""
    
    @pytest.mark.asyncio
    async def test_correlate_returns_results(self, correlator, sample_alarms):
        """Test that correlation returns results."""
        # Correlate alarm-2 against existing alarm-1
        result = await correlator.correlate(sample_alarms[1], [sample_alarms[0]])
        
        assert result is not None
        assert isinstance(result, CorrelatedAlarmGroup)
    
    @pytest.mark.asyncio
    async def test_temporal_correlation(self, correlator, sample_alarms):
        """Test temporal correlation (same time window)."""
        # Create alarms with NO topological link to force temporal
        a1 = {**sample_alarms[0], "resource_path": "/network/a", "ne_id": "a"}
        a2 = {**sample_alarms[1], "resource_path": "/network/b", "ne_id": "b"}
        
        # Add a specific temporal rule for testing
        correlator.add_rule(CorrelationRule(
            rule_id="test-temporal",
            name="Test Temporal",
            correlation_type=CorrelationType.TEMPORAL,
            time_window=timedelta(minutes=1),
            conditions=[{"field": "alarm_id", "operator": "exists"}]
        ))
        
        result = await correlator.correlate(a2, [a1])
        assert result is not None
        assert result.correlation_type == CorrelationType.TEMPORAL
    
    @pytest.mark.asyncio
    async def test_topological_correlation(self, correlator, sample_alarms):
        """Test topological correlation (same location/site)."""
        # Ensure we have a rule for topological
        correlator.add_rule(CorrelationRule(
            rule_id="topo-site",
            name="Same Site Correlation",
            correlation_type=CorrelationType.TOPOLOGICAL,
            confidence_weight=0.75,
        ))
        
        result = await correlator.correlate(sample_alarms[1], [sample_alarms[0]])
        
        assert result is not None
        # Should be topo group
        assert result.correlation_type == CorrelationType.TOPOLOGICAL
        assert "topo" in result.group_id
    
    @pytest.mark.asyncio
    async def test_find_root_cause(self, correlator, sample_alarms):
        """Test root cause identification."""
        root_cause = await correlator.find_root_cause(sample_alarms)
        
        assert root_cause is not None
        # Root cause should be the earliest critical alarm or the one with power keywords
        assert root_cause["alarm_id"] == "alarm-1" # Site Power Failure
    
    @pytest.mark.asyncio
    async def test_calculate_confidence(self, correlator, sample_alarms):
        """Test confidence score calculation."""
        confidence = correlator.calculate_confidence(
            sample_alarms[0], [sample_alarms[1]], CorrelationType.TEMPORAL
        )
        assert 0.0 <= confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_get_correlated_alarms(self, correlator, sample_alarms):
        """Test retrieving correlated alarms."""
        await correlator.correlate(sample_alarms[1], [sample_alarms[0]])
        
        correlated = correlator.get_correlated_alarms("alarm-1")
        assert isinstance(correlated, list)


class TestCorrelationEngine:
    """Test cases for CorrelationEngine."""
    
    @pytest.fixture
    def engine(self):
        """Create CorrelationEngine instance."""
        return CorrelationEngine()
    
    @pytest.mark.asyncio
    async def test_batch_correlation(self, engine, sample_alarms):
        """Test that a batch of alarms can be correlated."""
        result = await engine.correlate(sample_alarms)
        assert isinstance(result, CorrelationResult)
        assert result.total_alarms == len(sample_alarms)
    
    @pytest.mark.asyncio
    async def test_temporal_correlation_within_window(self, engine, sample_alarms):
        """Test that alarms within time window are correlated."""
        engine.add_rule(CorrelationRule(
            rule_id="t1", name="T1", correlation_type=CorrelationType.TEMPORAL,
            time_window=timedelta(minutes=5),
            conditions=[{"field": "ne_id", "operator": "exists"}]
        ))
        
        result = await engine._correlate_temporal(sample_alarms[0], [sample_alarms[1]])
        assert result is not None
        assert result.correlation_type == CorrelationType.TEMPORAL
    
    @pytest.mark.asyncio
    async def test_temporal_correlation_outside_window(self, engine):
        """Test that alarms outside time window are not correlated."""
        now = datetime.now(timezone.utc)
        alarms = [
            {"alarm_id": "1", "raised_at": now.isoformat()},
            {"alarm_id": "2", "raised_at": (now + timedelta(hours=2)).isoformat()},
        ]
        
        engine.add_rule(CorrelationRule(
            rule_id="t1", name="T1", correlation_type=CorrelationType.TEMPORAL,
            time_window=timedelta(minutes=5),
            conditions=[{"field": "alarm_id", "operator": "exists"}]
        ))
        
        result = await engine._correlate_temporal(alarms[0], [alarms[1]])
        assert result is None


class TestCorrelationRule:
    """Test cases for CorrelationRule."""
    
    def test_rule_matches_alarm(self):
        """Test that rule correctly matches alarms."""
        rule = CorrelationRule(
            rule_id="test-rule-1",
            name="Power Failure Correlation",
            correlation_type=CorrelationType.CAUSAL,
            conditions=[
                {"field": "alarm_text", "operator": "contains", "value": "Power"},
                {"field": "severity", "operator": "equals", "value": "CRITICAL"},
            ],
            confidence_weight=0.8,
        )
        
        alarm = {
            "alarm_text": "Site Power Failure",
            "severity": "CRITICAL",
        }
        
        assert rule.matches(alarm)
    
    def test_rule_does_not_match_alarm(self):
        """Test that rule correctly rejects non-matching alarms."""
        rule = CorrelationRule(
            rule_id="test-rule-2",
            name="Power Failure Correlation",
            correlation_type=CorrelationType.CAUSAL,
            conditions=[
                {"field": "alarm_text", "operator": "contains", "value": "Power"},
            ],
        )
        
        alarm = {
            "alarm_text": "Radio Link Failure",
            "severity": "MAJOR",
        }
        
        assert not rule.matches(alarm)


class TestCrossVendorCorrelation:
    """Test cross-vendor correlation scenarios."""
    
    @pytest.mark.asyncio
    async def test_correlate_across_vendors(self, correlator):
        """Test correlation across vendors."""
        now = datetime.now(timezone.utc).isoformat()
        alarms = [
            {
                "alarm_id": "v-1",
                "alarm_text": "S1 Interface Down",
                "vendor": "ERICSSON",
                "ne_id": "ENB-001",
                "resource_path": "/network/sites/SITE_A/elements/ENB-001",
                "severity": "CRITICAL",
                "raised_at": now,
            },
            {
                "alarm_id": "v-2",
                "alarm_text": "S1 Interface Failure",
                "vendor": "HUAWEI",
                "ne_id": "ENB-001",
                "resource_path": "/network/sites/SITE_A/elements/ENB-001",
                "severity": "CRITICAL",
                "raised_at": now,
            },
        ]
        
        result = await correlator.correlate(alarms[1], [alarms[0]])
        # Cross-vendor is attempted last, but since site_id matches and vendors differ, it should match
        assert result is not None
        assert result.correlation_type in [CorrelationType.CROSS_VENDOR, CorrelationType.TOPOLOGICAL]
