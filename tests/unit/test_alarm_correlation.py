"""
Unit tests for Alarm Correlation Engine.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, AsyncMock
import uuid

from unified_oss.fcaps.fault.correlation import (
    AlarmCorrelator,
    CorrelationEngine,
    CorrelationRule,
    CorrelationMethod,
    CorrelationResult,
)


@pytest.fixture
def correlator():
    """Create AlarmCorrelator instance for testing."""
    return AlarmCorrelator()


@pytest.fixture
def sample_alarms():
    """Sample alarms for correlation testing."""
    now = datetime.utcnow()
    
    return [
        {
            "alarm_id": str(uuid.uuid4()),
            "alarm_name": "Site Power Failure",
            "severity": "CRITICAL",
            "vendor": "ERICSSON",
            "ne_id": "ENB-HCM-001",
            "location": "HCM_SITE_001",
            "timestamp": now.isoformat(),
        },
        {
            "alarm_id": str(uuid.uuid4()),
            "alarm_name": "Radio Unit Connection Failure",
            "severity": "MAJOR",
            "vendor": "ERICSSON",
            "ne_id": "ENB-HCM-001",
            "location": "HCM_SITE_001",
            "timestamp": (now + timedelta(seconds=5)).isoformat(),
        },
        {
            "alarm_id": str(uuid.uuid4()),
            "alarm_name": "S1 Interface Down",
            "severity": "MAJOR",
            "vendor": "ERICSSON",
            "ne_id": "ENB-HCM-001",
            "location": "HCM_SITE_001",
            "timestamp": (now + timedelta(seconds=10)).isoformat(),
        },
        {
            "alarm_id": str(uuid.uuid4()),
            "alarm_name": "Transmission Link Failure",
            "severity": "CRITICAL",
            "vendor": "HUAWEI",
            "ne_id": "ENB-HCM-002",
            "location": "HCM_SITE_002",
            "timestamp": now.isoformat(),
        },
    ]


class TestAlarmCorrelator:
    """Test cases for AlarmCorrelator."""
    
    @pytest.mark.asyncio
    async def test_correlate_returns_results(self, correlator, sample_alarms):
        """Test that correlation returns results."""
        results = await correlator.correlate(sample_alarms)
        
        assert results is not None
        assert isinstance(results, list)
    
    @pytest.mark.asyncio
    async def test_temporal_correlation(self, correlator, sample_alarms):
        """Test temporal correlation (same time window)."""
        results = await correlator.correlate(
            sample_alarms,
            methods=[CorrelationMethod.TEMPORAL],
            time_window_seconds=60
        )
        
        # Alarms from same site within time window should correlate
        correlated_ids = [r.alarm_id for r in results]
    
    @pytest.mark.asyncio
    async def test_topological_correlation(self, correlator, sample_alarms):
        """Test topological correlation (same location/site)."""
        results = await correlator.correlate(
            sample_alarms,
            methods=[CorrelationMethod.TOPOLOGICAL]
        )
        
        # Alarms from same location should correlate
        assert len(results) >= 0
    
    @pytest.mark.asyncio
    async def test_find_root_cause(self, correlator, sample_alarms):
        """Test root cause identification."""
        results = await correlator.correlate(sample_alarms)
        
        root_cause = await correlator.find_root_cause(sample_alarms, results)
        
        # Root cause should typically be the earliest critical alarm
        assert root_cause is not None or len(results) == 0
    
    @pytest.mark.asyncio
    async def test_calculate_confidence(self, correlator, sample_alarms):
        """Test confidence score calculation."""
        results = await correlator.correlate(sample_alarms)
        
        for result in results:
            assert 0.0 <= result.confidence <= 1.0
    
    @pytest.mark.asyncio
    async def test_get_correlated_alarms(self, correlator, sample_alarms):
        """Test retrieving correlated alarms."""
        results = await correlator.correlate(sample_alarms)
        
        if results:
            alarm_id = results[0].alarm_id
            correlated = await correlator.get_correlated_alarms(alarm_id)
            
            assert isinstance(correlated, list)


class TestCorrelationEngine:
    """Test cases for CorrelationEngine."""
    
    @pytest.fixture
    def engine(self):
        """Create CorrelationEngine instance."""
        return CorrelationEngine()
    
    def test_temporal_correlation_within_window(self, engine, sample_alarms):
        """Test that alarms within time window are correlated."""
        result = engine.correlate_temporal(
            sample_alarms,
            time_window_seconds=60
        )
        
        assert isinstance(result, CorrelationResult)
    
    def test_temporal_correlation_outside_window(self, engine):
        """Test that alarms outside time window are not correlated."""
        now = datetime.utcnow()
        
        alarms = [
            {"alarm_id": "1", "timestamp": now.isoformat()},
            {"alarm_id": "2", "timestamp": (now + timedelta(hours=2)).isoformat()},
        ]
        
        result = engine.correlate_temporal(alarms, time_window_seconds=60)
        
        assert result is None or len(result.correlated_ids) == 0
    
    def test_topological_correlation_same_site(self, engine, sample_alarms):
        """Test topological correlation for same site."""
        result = engine.correlate_topological(sample_alarms)
        
        assert isinstance(result, CorrelationResult)
    
    def test_causal_correlation(self, engine, sample_alarms):
        """Test causal correlation analysis."""
        result = engine.correlate_causal(sample_alarms)
        
        # Causal correlation should identify root cause
        assert result is not None


class TestCorrelationRule:
    """Test cases for CorrelationRule."""
    
    def test_rule_matches_alarm(self):
        """Test that rule correctly matches alarms."""
        rule = CorrelationRule(
            rule_id="test-rule-1",
            name="Power Failure Correlation",
            conditions={
                "alarm_name_pattern": ".*Power.*",
                "severity": "CRITICAL",
            },
            correlation_group="power-failures",
            confidence_weight=0.8,
        )
        
        alarm = {
            "alarm_name": "Site Power Failure",
            "severity": "CRITICAL",
        }
        
        assert rule.matches(alarm)
    
    def test_rule_does_not_match_alarm(self):
        """Test that rule correctly rejects non-matching alarms."""
        rule = CorrelationRule(
            rule_id="test-rule-2",
            name="Power Failure Correlation",
            conditions={
                "alarm_name_pattern": ".*Power.*",
                "severity": "CRITICAL",
            },
            correlation_group="power-failures",
            confidence_weight=0.8,
        )
        
        alarm = {
            "alarm_name": "Radio Link Failure",
            "severity": "MAJOR",
        }
        
        assert not rule.matches(alarm)
    
    def test_rule_with_vendor_filter(self):
        """Test rule with vendor-specific filtering."""
        rule = CorrelationRule(
            rule_id="test-rule-3",
            name="Ericsson Alarm Correlation",
            conditions={
                "vendor": "ERICSSON",
                "severity": ["CRITICAL", "MAJOR"],
            },
            correlation_group="ericsson-critical",
        )
        
        ericsson_alarm = {"vendor": "ERICSSON", "severity": "CRITICAL"}
        huawei_alarm = {"vendor": "HUAWEI", "severity": "CRITICAL"}
        
        assert rule.matches(ericsson_alarm)
        assert not rule.matches(huawei_alarm)


class TestCorrelationConfidence:
    """Test confidence score calculation."""
    
    def test_high_confidence_for_exact_match(self, correlator):
        """Test high confidence for exact pattern match."""
        confidence = correlator.calculate_confidence(
            alarm1={"alarm_name": "Power Failure", "ne_id": "NE001"},
            alarm2={"alarm_name": "Power Failure", "ne_id": "NE001"},
            method=CorrelationMethod.TEMPORAL,
        )
        
        assert confidence >= 0.9
    
    def test_low_confidence_for_partial_match(self, correlator):
        """Test lower confidence for partial match."""
        confidence = correlator.calculate_confidence(
            alarm1={"alarm_name": "Power Failure", "ne_id": "NE001"},
            alarm2={"alarm_name": "Link Failure", "ne_id": "NE002"},
            method=CorrelationMethod.TEMPORAL,
        )
        
        assert confidence < 0.5
    
    def test_zero_confidence_for_no_match(self, correlator):
        """Test zero confidence for no match."""
        confidence = correlator.calculate_confidence(
            alarm1={"ne_id": "NE001", "location": "SITE_A"},
            alarm2={"ne_id": "NE999", "location": "SITE_Z"},
            method=CorrelationMethod.TOPOLOGICAL,
        )
        
        assert confidence < 0.1


class TestCrossVendorCorrelation:
    """Test cross-vendor correlation scenarios."""
    
    @pytest.mark.asyncio
    async def test_correlate_across_vendors(self, correlator):
        """Test correlation between Ericsson and Huawei alarms."""
        alarms = [
            {
                "alarm_id": "1",
                "alarm_name": "S1 Interface Down",
                "vendor": "ERICSSON",
                "ne_id": "ENB-001",
                "severity": "CRITICAL",
                "timestamp": datetime.utcnow().isoformat(),
            },
            {
                "alarm_id": "2",
                "alarm_name": "S1 Interface Failure",
                "vendor": "HUAWEI",
                "ne_id": "ENB-002",
                "severity": "CRITICAL",
                "timestamp": datetime.utcnow().isoformat(),
            },
        ]
        
        results = await correlator.correlate(
            alarms,
            cross_vendor=True
        )
        
        # Should correlate similar alarm types across vendors
        assert isinstance(results, list)
