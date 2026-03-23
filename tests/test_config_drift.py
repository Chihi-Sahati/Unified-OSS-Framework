"""
Unit tests for Configuration Drift Detection module.

Tests cover drift detection, severity classification, and drift reporting.
"""

import hashlib
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from unified_oss.fcaps.configuration.drift_detection import (
    DriftDetector,
    DriftReport,
    DriftEntry,
    DriftType,
    DriftSeverity,
    SeverityClassifier,
    ComparisonMode,
    MonitoringSchedule,
    MonitoringState,
    DriftAlert,
    ComparisonError,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def drift_detector():
    """Create a DriftDetector instance for testing."""
    return DriftDetector()


@pytest.fixture
def severity_classifier():
    """Create a SeverityClassifier instance for testing."""
    return SeverityClassifier()


@pytest.fixture
def sample_config_xml():
    """Create sample XML configuration."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <system>
        <hostname>router-001</hostname>
        <timezone>UTC</timezone>
    </system>
    <interfaces>
        <interface>
            <name>eth0</name>
            <ip>192.168.1.1</ip>
            <enabled>true</enabled>
        </interface>
    </interfaces>
</config>
"""


@pytest.fixture
def modified_config_xml():
    """Create modified XML configuration with drifts."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<config>
    <system>
        <hostname>router-001</hostname>
        <timezone>PST</timezone>
    </system>
    <interfaces>
        <interface>
            <name>eth0</name>
            <ip>192.168.1.2</ip>
            <enabled>true</enabled>
        </interface>
        <interface>
            <name>eth1</name>
            <ip>192.168.2.1</ip>
            <enabled>true</enabled>
        </interface>
    </interfaces>
</config>
"""


@pytest.fixture
def sample_config_text():
    """Create sample text-based configuration."""
    return """
hostname router-001
interface eth0
 ip address 192.168.1.1 255.255.255.0
 no shutdown
!
ntp server 10.0.0.1
"""


@pytest.fixture
def monitoring_schedule():
    """Create a sample monitoring schedule."""
    return MonitoringSchedule(
        schedule_id="schedule-001",
        ne_ids=["router-001", "router-002"],
        interval_seconds=300,
    )


# =============================================================================
# DriftDetector Tests
# =============================================================================

class TestDriftDetector:
    """Tests for DriftDetector class."""

    @pytest.mark.asyncio
    async def test_detect_drift_no_change(self, drift_detector, sample_config_xml):
        """Test drift detection with identical configurations."""
        report = await drift_detector.detect_drift(
            baseline_config=sample_config_xml,
            current_config=sample_config_xml,
            ne_id="router-001",
        )
        
        assert report is not None
        assert len(report.drift_entries) == 0
        assert report.baseline_hash == report.current_hash

    @pytest.mark.asyncio
    async def test_detect_drift_with_changes(
        self,
        drift_detector,
        sample_config_xml,
        modified_config_xml
    ):
        """Test drift detection with configuration changes."""
        report = await drift_detector.detect_drift(
            baseline_config=sample_config_xml,
            current_config=modified_config_xml,
            ne_id="router-001",
        )
        
        assert report is not None
        assert len(report.drift_entries) > 0

    @pytest.mark.asyncio
    async def test_detect_drift_xml(self, drift_detector, sample_config_xml, modified_config_xml):
        """Test XML configuration drift detection."""
        report = await drift_detector.detect_drift(
            baseline_config=sample_config_xml,
            current_config=modified_config_xml,
            ne_id="router-001",
            comparison_mode=ComparisonMode.NORMALIZED,
        )
        
        assert report.comparison_mode == ComparisonMode.NORMALIZED
        # Should detect timezone and IP changes

    @pytest.mark.asyncio
    async def test_detect_drift_text(self, drift_detector, sample_config_text):
        """Test text-based configuration drift detection."""
        modified = sample_config_text.replace("192.168.1.1", "192.168.1.100")
        
        report = await drift_detector.detect_drift(
            baseline_config=sample_config_text,
            current_config=modified,
            ne_id="router-001",
        )
        
        assert report is not None

    @pytest.mark.asyncio
    async def test_compare_configs(self, drift_detector, sample_config_xml, modified_config_xml):
        """Test configuration comparison."""
        drift_entries = await drift_detector.compare_configs(
            config1=sample_config_xml,
            config2=modified_config_xml,
            ne_id="router-001",
        )
        
        assert isinstance(drift_entries, list)

    @pytest.mark.asyncio
    async def test_classify_severity(self, drift_detector):
        """Test severity classification."""
        entry = DriftEntry(
            drift_type=DriftType.VALUE_CHANGED,
            path="/system/security/admin-password",
            expected="***",
            actual="newpassword",
            description="Security setting changed",
            ne_id="router-001",
        )
        
        severity = drift_detector.classify_severity(entry)
        
        assert severity in [DriftSeverity.LOW, DriftSeverity.MODERATE, DriftSeverity.HIGH, DriftSeverity.CRITICAL]

    @pytest.mark.asyncio
    async def test_generate_report(self, drift_detector, sample_config_xml, modified_config_xml):
        """Test drift report generation."""
        report = await drift_detector.detect_drift(
            baseline_config=sample_config_xml,
            current_config=modified_config_xml,
            ne_id="router-001",
        )
        
        # Generate JSON report
        json_report = await drift_detector.generate_report(report, format_type="json")
        
        assert json_report is not None
        assert isinstance(json_report, str)

    @pytest.mark.asyncio
    async def test_generate_summary_report(self, drift_detector, sample_config_xml, modified_config_xml):
        """Test summary report generation."""
        report = await drift_detector.detect_drift(
            baseline_config=sample_config_xml,
            current_config=modified_config_xml,
            ne_id="router-001",
        )
        
        summary = await drift_detector.generate_report(report, format_type="summary")
        
        assert summary is not None
        assert "Drift Detection Report" in summary

    @pytest.mark.asyncio
    async def test_set_and_get_baseline(self, drift_detector, sample_config_xml):
        """Test baseline management."""
        await drift_detector.set_baseline("router-001", sample_config_xml)
        
        baseline = await drift_detector.get_baseline("router-001")
        
        assert baseline == sample_config_xml

    @pytest.mark.asyncio
    async def test_start_monitoring(self, drift_detector, monitoring_schedule):
        """Test starting drift monitoring."""
        result = await drift_detector.start_monitoring(monitoring_schedule)
        
        assert result is True
        assert monitoring_schedule.schedule_id in drift_detector._monitoring_schedules

    @pytest.mark.asyncio
    async def test_stop_monitoring(self, drift_detector, monitoring_schedule):
        """Test stopping drift monitoring."""
        await drift_detector.start_monitoring(monitoring_schedule)
        result = await drift_detector.stop_monitoring(monitoring_schedule.schedule_id)
        
        assert result is True

    @pytest.mark.asyncio
    async def test_get_alerts(self, drift_detector):
        """Test getting drift alerts."""
        alerts = await drift_detector.get_alerts()
        
        assert isinstance(alerts, list)

    @pytest.mark.asyncio
    async def test_get_stats(self, drift_detector):
        """Test getting detector statistics."""
        stats = drift_detector.get_stats()
        
        assert "baselines_count" in stats
        assert "state" in stats


# =============================================================================
# DriftReport Tests
# =============================================================================

class TestDriftReport:
    """Tests for DriftReport dataclass."""

    def test_report_creation(self):
        """Test creating a drift report."""
        report = DriftReport(
            ne_id="router-001",
            baseline_id="baseline-001",
            baseline_hash="abc123",
            current_hash="def456",
            drift_entries=[],
            comparison_mode=ComparisonMode.NORMALIZED,
        )
        
        assert report.ne_id == "router-001"
        assert len(report.drift_entries) == 0

    def test_report_summary(self):
        """Test report summary calculation."""
        entry1 = DriftEntry(
            drift_type=DriftType.VALUE_CHANGED,
            path="/test",
            expected="a",
            actual="b",
            severity=DriftSeverity.HIGH,
            ne_id="router-001",
        )
        entry2 = DriftEntry(
            drift_type=DriftType.MISSING,
            path="/test2",
            expected="c",
            actual="",
            severity=DriftSeverity.CRITICAL,
            ne_id="router-001",
        )
        
        report = DriftReport(
            ne_id="router-001",
            baseline_id="",
            baseline_hash="",
            current_hash="",
            drift_entries=[entry1, entry2],
            comparison_mode=ComparisonMode.NORMALIZED,
        )
        
        summary = report.summary
        
        assert summary["critical_count"] == 1
        assert summary["high_count"] == 1

    def test_report_to_dict(self):
        """Test report serialization."""
        report = DriftReport(
            ne_id="router-001",
            baseline_id="baseline-001",
            baseline_hash="abc123",
            current_hash="def456",
            drift_entries=[],
            comparison_mode=ComparisonMode.NORMALIZED,
        )
        
        report_dict = report.to_dict()
        
        assert "ne_id" in report_dict
        assert "drift_entries" in report_dict


# =============================================================================
# DriftEntry Tests
# =============================================================================

class TestDriftEntry:
    """Tests for DriftEntry dataclass."""

    def test_entry_creation(self):
        """Test creating a drift entry."""
        entry = DriftEntry(
            drift_type=DriftType.VALUE_CHANGED,
            path="/system/hostname",
            expected="router-001",
            actual="router-002",
            description="Hostname changed",
            ne_id="router-001",
        )
        
        assert entry.drift_type == DriftType.VALUE_CHANGED
        assert entry.severity == DriftSeverity.LOW  # Default

    def test_entry_to_dict(self):
        """Test entry serialization."""
        entry = DriftEntry(
            drift_type=DriftType.MISSING,
            path="/test",
            expected="value",
            actual="",
            ne_id="router-001",
        )
        
        entry_dict = entry.to_dict()
        
        assert "drift_type" in entry_dict
        assert "path" in entry_dict


# =============================================================================
# SeverityClassifier Tests
# =============================================================================

class TestSeverityClassifier:
    """Tests for SeverityClassifier class."""

    def test_classify_missing_critical(self, severity_classifier):
        """Test classifying missing critical configuration."""
        entry = DriftEntry(
            drift_type=DriftType.MISSING,
            path="/system/security/firewall",
            expected="enabled",
            actual="",
            ne_id="router-001",
        )
        
        severity = severity_classifier.classify(entry)
        
        assert severity == DriftSeverity.CRITICAL

    def test_classify_security_change(self, severity_classifier):
        """Test classifying security configuration change."""
        entry = DriftEntry(
            drift_type=DriftType.VALUE_CHANGED,
            path="/system/security/admin-password",
            expected="***",
            actual="newvalue",
            ne_id="router-001",
        )
        
        severity = severity_classifier.classify(entry)
        
        assert severity in [DriftSeverity.HIGH, DriftSeverity.CRITICAL]

    def test_classify_minor_change(self, severity_classifier):
        """Test classifying minor configuration change."""
        entry = DriftEntry(
            drift_type=DriftType.VALUE_CHANGED,
            path="/system/description",
            expected="old description",
            actual="new description",
            ne_id="router-001",
        )
        
        severity = severity_classifier.classify(entry)
        
        assert severity in [DriftSeverity.LOW, DriftSeverity.MODERATE]

    def test_classify_with_context(self, severity_classifier):
        """Test classification with additional context."""
        entry = DriftEntry(
            drift_type=DriftType.UNEXPECTED,
            path="/interfaces/eth1",
            expected="",
            actual="new interface",
            ne_id="router-001",
        )
        
        context = {
            "environment": "production",
            "change_request": "CR-001",
        }
        
        severity = severity_classifier.classify(entry, context)
        
        assert severity in [DriftSeverity.LOW, DriftSeverity.MODERATE, DriftSeverity.HIGH]

    def test_add_custom_rule(self, severity_classifier):
        """Test adding custom classification rule."""
        def custom_rule(entry: DriftEntry) -> DriftSeverity:
            if "custom" in entry.path:
                return DriftSeverity.CRITICAL
            return DriftSeverity.LOW
        
        severity_classifier.add_rule(custom_rule)
        
        entry = DriftEntry(
            drift_type=DriftType.VALUE_CHANGED,
            path="/custom/config",
            expected="a",
            actual="b",
            ne_id="router-001",
        )
        
        severity = severity_classifier.classify(entry)
        
        assert severity == DriftSeverity.CRITICAL


# =============================================================================
# MonitoringSchedule Tests
# =============================================================================

class TestMonitoringSchedule:
    """Tests for MonitoringSchedule dataclass."""

    def test_schedule_creation(self):
        """Test creating a monitoring schedule."""
        schedule = MonitoringSchedule(
            schedule_id="schedule-001",
            ne_ids=["router-001", "router-002"],
            interval_seconds=300,
        )
        
        assert schedule.enabled is True
        assert schedule.state == MonitoringState.STOPPED

    def test_schedule_next_run(self):
        """Test calculating next run time."""
        schedule = MonitoringSchedule(
            schedule_id="schedule-001",
            ne_ids=["router-001"],
            interval_seconds=300,
        )
        
        next_run = schedule.calculate_next_run()
        
        assert next_run is not None
        assert next_run > datetime.now(timezone.utc)

    def test_schedule_expiry(self):
        """Test schedule expiry check."""
        schedule = MonitoringSchedule(
            schedule_id="schedule-001",
            ne_ids=["router-001"],
            interval_seconds=300,
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        
        assert schedule.is_expired() is True


# =============================================================================
# DriftAlert Tests
# =============================================================================

class TestDriftAlert:
    """Tests for DriftAlert dataclass."""

    def test_alert_creation(self):
        """Test creating a drift alert."""
        alert = DriftAlert(
            report_id="report-001",
            ne_id="router-001",
            severity=DriftSeverity.HIGH,
            title="Configuration Drift Detected",
            message="Found 5 drift entries",
            drift_count=5,
        )
        
        assert alert.acknowledged is False
        assert alert.drift_count == 5

    def test_alert_acknowledgment(self):
        """Test alert acknowledgment."""
        alert = DriftAlert(
            report_id="report-001",
            ne_id="router-001",
            severity=DriftSeverity.HIGH,
            title="Test Alert",
            message="Test",
            drift_count=1,
        )
        
        alert.acknowledged = True
        alert.acknowledged_by = "admin"
        
        assert alert.acknowledged is True
        assert alert.acknowledged_by == "admin"


# =============================================================================
# Integration Tests
# =============================================================================

class TestDriftDetectionIntegration:
    """Integration tests for drift detection."""

    @pytest.mark.asyncio
    async def test_full_drift_detection_workflow(
        self,
        drift_detector,
        sample_config_xml,
        modified_config_xml
    ):
        """Test complete drift detection workflow."""
        # Set baseline
        await drift_detector.set_baseline("router-001", sample_config_xml)
        
        # Detect drift
        report = await drift_detector.detect_drift(
            baseline_config=sample_config_xml,
            current_config=modified_config_xml,
            ne_id="router-001",
        )
        
        # Generate report
        summary = await drift_detector.generate_report(report, format_type="summary")
        
        assert report is not None
        assert summary is not None

    @pytest.mark.asyncio
    async def test_monitoring_workflow(self, drift_detector, sample_config_xml, monitoring_schedule):
        """Test drift monitoring workflow."""
        # Set baseline
        await drift_detector.set_baseline("router-001", sample_config_xml)
        
        # Start monitoring
        result = await drift_detector.start_monitoring(monitoring_schedule)
        assert result is True
        
        # Stop monitoring
        result = await drift_detector.stop_monitoring(monitoring_schedule.schedule_id)
        assert result is True


# =============================================================================
# Performance Tests
# =============================================================================

class TestDriftDetectionPerformance:
    """Performance tests for drift detection."""

    @pytest.mark.asyncio
    async def test_large_config_comparison(self, drift_detector):
        """Test comparing large configurations."""
        # Generate large config
        lines = [f"line {i} value {i}" for i in range(1000)]
        baseline = "\n".join(lines)
        
        # Modify some lines
        current_lines = lines.copy()
        for i in [10, 50, 100, 500, 999]:
            current_lines[i] = f"line {i} modified"
        current = "\n".join(current_lines)
        
        import time
        start_time = time.time()
        report = await drift_detector.detect_drift(
            baseline_config=baseline,
            current_config=current,
            ne_id="router-001",
        )
        duration = time.time() - start_time
        
        assert duration < 2.0  # Should complete within 2 seconds
        assert len(report.drift_entries) > 0

    @pytest.mark.asyncio
    async def test_multiple_simultaneous_detections(self, drift_detector, sample_config_xml):
        """Test multiple simultaneous drift detections."""
        import asyncio
        import time
        
        tasks = [
            drift_detector.detect_drift(
                baseline_config=sample_config_xml,
                current_config=sample_config_xml.replace("192.168.1.1", f"192.168.{i}.1"),
                ne_id=f"router-{i}",
            )
            for i in range(10)
        ]
        
        start_time = time.time()
        results = await asyncio.gather(*tasks)
        duration = time.time() - start_time
        
        assert len(results) == 10
        assert duration < 5.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
