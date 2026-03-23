"""
Configuration Drift Detection Module for Unified OSS Framework.

This module provides comprehensive configuration drift detection capabilities
including baseline comparison, severity classification, and alert generation
for network element configuration management.

Features:
    - Configuration drift detection (MISSING, MODIFIED, UNEXPECTED)
    - Severity classification (CRITICAL, MODERATE, LOW)
    - Baseline comparison
    - Schedule-based drift monitoring
    - Alert generation for drift events

Author: Unified OSS Framework Team
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from xml.etree import ElementTree as ET

# Configure module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Enums and Constants
# =============================================================================


class DriftType(Enum):
    """Types of configuration drift."""
    MISSING = "missing"          # Expected configuration is missing
    MODIFIED = "modified"        # Configuration has been modified
    UNEXPECTED = "unexpected"    # Unexpected configuration found
    ADDED = "added"             # New configuration added
    REMOVED = "removed"         # Configuration removed
    VALUE_CHANGED = "value_changed"  # Value changed


class DriftSeverity(Enum):
    """Severity levels for configuration drift."""
    CRITICAL = "critical"       # Service-affecting drift
    HIGH = "high"               # Significant configuration change
    MODERATE = "moderate"       # Noticeable change
    LOW = "low"                 # Minor change
    INFO = "info"               # Informational only


class ComparisonMode(Enum):
    """Modes for configuration comparison."""
    EXACT = "exact"             # Exact match required
    NORMALIZED = "normalized"   # Normalized comparison
    SEMANTIC = "semantic"       # Semantic comparison


class MonitoringState(Enum):
    """States for drift monitoring."""
    ACTIVE = "active"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERROR = "error"


# =============================================================================
# Exceptions
# =============================================================================


class DriftDetectionError(Exception):
    """Base exception for drift detection errors."""

    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Initialize drift detection error.

        Args:
            message: Error message.
            details: Additional error details.
        """
        super().__init__(message)
        self.details = details or {}


class BaselineNotFoundError(DriftDetectionError):
    """Exception raised when baseline configuration not found."""
    pass


class ComparisonError(DriftDetectionError):
    """Exception raised when comparison fails."""
    pass


# =============================================================================
# Dataclasses
# =============================================================================


@dataclass
class DriftEntry:
    """Represents a single configuration drift entry.

    Attributes:
        entry_id: Unique entry identifier.
        drift_type: Type of drift detected.
        severity: Severity level of the drift.
        path: Configuration path where drift was detected.
        expected: Expected configuration value.
        actual: Actual configuration value.
        description: Human-readable description.
        detected_at: Detection timestamp.
        ne_id: Network element identifier.
        metadata: Additional metadata.
    """

    entry_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    drift_type: DriftType = DriftType.MODIFIED
    severity: DriftSeverity = DriftSeverity.MODERATE
    path: str = ""
    expected: str = ""
    actual: str = ""
    description: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    ne_id: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of drift entry.
        """
        return {
            "entry_id": self.entry_id,
            "drift_type": self.drift_type.value,
            "severity": self.severity.value,
            "path": self.path,
            "expected": self.expected[:500] if self.expected else "",
            "actual": self.actual[:500] if self.actual else "",
            "description": self.description,
            "detected_at": self.detected_at.isoformat(),
            "ne_id": self.ne_id,
            "metadata": self.metadata,
        }

    def __hash__(self) -> int:
        """Generate hash for deduplication."""
        return hash((self.drift_type, self.path, self.expected, self.actual))


@dataclass
class DriftReport:
    """Comprehensive drift detection report.

    Attributes:
        report_id: Unique report identifier.
        ne_id: Network element identifier.
        baseline_id: Baseline configuration ID.
        baseline_hash: Hash of baseline configuration.
        current_hash: Hash of current configuration.
        drift_entries: List of detected drift entries.
        summary: Summary statistics.
        detected_at: Detection timestamp.
        comparison_mode: Mode used for comparison.
        duration_ms: Duration of comparison in milliseconds.
    """

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ne_id: str = ""
    baseline_id: str = ""
    baseline_hash: str = ""
    current_hash: str = ""
    drift_entries: List[DriftEntry] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    comparison_mode: ComparisonMode = ComparisonMode.NORMALIZED
    duration_ms: float = 0.0

    def __post_init__(self) -> None:
        """Calculate summary after initialization."""
        if not self.summary:
            self.summary = self._calculate_summary()

    def _calculate_summary(self) -> Dict[str, Any]:
        """Calculate summary statistics.

        Returns:
            Summary dictionary.
        """
        summary = {
            "total_drifts": len(self.drift_entries),
            "by_severity": {},
            "by_type": {},
            "critical_count": 0,
            "high_count": 0,
            "moderate_count": 0,
            "low_count": 0,
        }

        for entry in self.drift_entries:
            # Count by severity
            severity_key = entry.severity.value
            summary["by_severity"][severity_key] = (
                summary["by_severity"].get(severity_key, 0) + 1
            )

            # Count by type
            type_key = entry.drift_type.value
            summary["by_type"][type_key] = (
                summary["by_type"].get(type_key, 0) + 1
            )

            # Specific counts
            if entry.severity == DriftSeverity.CRITICAL:
                summary["critical_count"] += 1
            elif entry.severity == DriftSeverity.HIGH:
                summary["high_count"] += 1
            elif entry.severity == DriftSeverity.MODERATE:
                summary["moderate_count"] += 1
            else:
                summary["low_count"] += 1

        return summary

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of report.
        """
        return {
            "report_id": self.report_id,
            "ne_id": self.ne_id,
            "baseline_id": self.baseline_id,
            "baseline_hash": self.baseline_hash,
            "current_hash": self.current_hash,
            "drift_count": len(self.drift_entries),
            "drift_entries": [e.to_dict() for e in self.drift_entries],
            "summary": self.summary,
            "detected_at": self.detected_at.isoformat(),
            "comparison_mode": self.comparison_mode.value,
            "duration_ms": self.duration_ms,
        }

    def has_critical_drift(self) -> bool:
        """Check if report contains critical drift.

        Returns:
            True if any critical drift detected.
        """
        return any(e.severity == DriftSeverity.CRITICAL for e in self.drift_entries)

    def get_drifts_by_severity(self, severity: DriftSeverity) -> List[DriftEntry]:
        """Get drift entries by severity level.

        Args:
            severity: Severity level to filter by.

        Returns:
            List of matching drift entries.
        """
        return [e for e in self.drift_entries if e.severity == severity]


@dataclass
class DriftAlert:
    """Alert generated from drift detection.

    Attributes:
        alert_id: Unique alert identifier.
        report_id: Associated report ID.
        ne_id: Network element identifier.
        severity: Alert severity.
        title: Alert title.
        message: Alert message.
        drift_count: Number of drifts detected.
        created_at: Creation timestamp.
        acknowledged: Whether alert has been acknowledged.
        acknowledged_by: User who acknowledged.
    """

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    report_id: str = ""
    ne_id: str = ""
    severity: DriftSeverity = DriftSeverity.MODERATE
    title: str = ""
    message: str = ""
    drift_count: int = 0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation.

        Returns:
            Dictionary representation of alert.
        """
        return {
            "alert_id": self.alert_id,
            "report_id": self.report_id,
            "ne_id": self.ne_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "drift_count": self.drift_count,
            "created_at": self.created_at.isoformat(),
            "acknowledged": self.acknowledged,
            "acknowledged_by": self.acknowledged_by,
        }


@dataclass
class MonitoringSchedule:
    """Schedule for periodic drift monitoring.

    Attributes:
        schedule_id: Unique schedule identifier.
        ne_ids: List of network element IDs to monitor.
        interval_seconds: Monitoring interval in seconds.
        baseline_configs: Mapping of NE ID to baseline config.
        enabled: Whether monitoring is enabled.
        last_run: Last execution timestamp.
        next_run: Next scheduled execution.
        created_at: Creation timestamp.
    """

    schedule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ne_ids: List[str] = field(default_factory=list)
    interval_seconds: int = 3600  # 1 hour default
    baseline_configs: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def calculate_next_run(self) -> datetime:
        """Calculate next run time.

        Returns:
            Next scheduled run time.
        """
        now = datetime.now(timezone.utc)
        if self.last_run:
            return self.last_run + timedelta(seconds=self.interval_seconds)
        return now + timedelta(seconds=self.interval_seconds)


# =============================================================================
# Severity Classifier
# =============================================================================


class SeverityClassifier:
    """Classifies drift severity based on rules and patterns.

    Provides rule-based severity classification for configuration
    drift entries.

    Attributes:
        rules: List of classification rules.
    """

    # Critical configuration patterns
    CRITICAL_PATTERNS = [
        r"security\s+disable",
        r"authentication\s+none",
        r"encryption\s+off",
        r"firewall\s+disable",
        r"access-list.*delete",
        r"password.*clear",
        r"acl.*remove",
        r"shutdown\s+interface",
    ]

    # High severity patterns
    HIGH_PATTERNS = [
        r"snmp-community",
        r"tacacs\s+server",
        r"radius\s+server",
        r"logging\s+disable",
        r"ntp\s+server",
        r"vlan\s+\d+",
        r"ip\s+route",
        r"ospf|bgp|isis",
    ]

    # Moderate severity patterns
    MODERATE_PATTERNS = [
        r"interface\s+description",
        r"bandwidth",
        r"mtu",
        r"qos",
        r"queue",
        r"policy-map",
    ]

    def __init__(self) -> None:
        """Initialize severity classifier."""
        self._custom_rules: List[Callable[[DriftEntry], DriftSeverity]] = []

    def classify(
        self,
        drift_entry: DriftEntry,
        context: Optional[Dict[str, Any]] = None
    ) -> DriftSeverity:
        """Classify the severity of a drift entry.

        Args:
            drift_entry: Drift entry to classify.
            context: Additional context for classification.

        Returns:
            Severity level.
        """
        context = context or {}
        path = drift_entry.path.lower()
        actual = drift_entry.actual.lower()
        expected = drift_entry.expected.lower()

        # Check custom rules first
        for rule in self._custom_rules:
            try:
                severity = rule(drift_entry)
                if severity != DriftSeverity.INFO:
                    return severity
            except Exception as e:
                logger.warning("Custom classification rule error: %s", e)

        # Check critical patterns
        for pattern in self.CRITICAL_PATTERNS:
            if re.search(pattern, path) or re.search(pattern, actual):
                return DriftSeverity.CRITICAL

        # Check high severity patterns
        for pattern in self.HIGH_PATTERNS:
            if re.search(pattern, path) or re.search(pattern, actual):
                return DriftSeverity.HIGH

        # Check moderate severity patterns
        for pattern in self.MODERATE_PATTERNS:
            if re.search(pattern, path) or re.search(pattern, actual):
                return DriftSeverity.MODERATE

        # Default severity based on drift type
        if drift_entry.drift_type == DriftType.MISSING:
            return DriftSeverity.HIGH
        elif drift_entry.drift_type == DriftType.UNEXPECTED:
            return DriftSeverity.MODERATE
        elif drift_entry.drift_type == DriftType.VALUE_CHANGED:
            return DriftSeverity.LOW

        return DriftSeverity.LOW

    def add_rule(
        self,
        rule: Callable[[DriftEntry], DriftSeverity]
    ) -> None:
        """Add a custom classification rule.

        Args:
            rule: Classification function.
        """
        self._custom_rules.append(rule)


# =============================================================================
# Drift Detector
# =============================================================================


class DriftDetector:
    """Configuration drift detection engine.

    Provides comprehensive drift detection including baseline comparison,
    severity classification, and alert generation.

    Attributes:
        classifier: Severity classifier instance.
        comparison_mode: Default comparison mode.
        monitoring_schedules: Active monitoring schedules.

    Example:
        >>> detector = DriftDetector()
        >>> report = await detector.detect_drift(
        ...     baseline_config=config_xml,
        ...     current_config=running_config,
        ...     ne_id="router-001"
        ... )
    """

    def __init__(
        self,
        comparison_mode: ComparisonMode = ComparisonMode.NORMALIZED
    ) -> None:
        """Initialize drift detector.

        Args:
            comparison_mode: Default comparison mode.
        """
        self.comparison_mode = comparison_mode
        self.classifier = SeverityClassifier()

        self._baselines: Dict[str, str] = {}  # ne_id -> config content
        self._baseline_hashes: Dict[str, str] = {}
        self._monitoring_schedules: Dict[str, MonitoringSchedule] = {}
        self._monitoring_tasks: Dict[str, asyncio.Task[None]] = {}
        self._alerts: List[DriftAlert] = []
        self._state = MonitoringState.STOPPED
        self._lock = asyncio.Lock()

        logger.info("DriftDetector initialized with mode=%s", comparison_mode.value)

    async def detect_drift(
        self,
        baseline_config: str,
        current_config: str,
        ne_id: str,
        baseline_id: Optional[str] = None,
        comparison_mode: Optional[ComparisonMode] = None
    ) -> DriftReport:
        """Detect configuration drift between baseline and current config.

        Args:
            baseline_config: Baseline configuration content.
            current_config: Current configuration content.
            ne_id: Network element identifier.
            baseline_id: Optional baseline identifier.
            comparison_mode: Comparison mode override.

        Returns:
            DriftReport with detected drifts.
        """
        start_time = datetime.now(timezone.utc)
        mode = comparison_mode or self.comparison_mode

        logger.info(
            "Starting drift detection for NE %s with mode %s",
            ne_id, mode.value
        )

        try:
            # Calculate hashes
            baseline_hash = self._calculate_hash(baseline_config)
            current_hash = self._calculate_hash(current_config)

            # If hashes match, no drift
            if baseline_hash == current_hash:
                logger.info("No drift detected for NE %s (hashes match)", ne_id)
                return DriftReport(
                    ne_id=ne_id,
                    baseline_id=baseline_id or "",
                    baseline_hash=baseline_hash,
                    current_hash=current_hash,
                    drift_entries=[],
                    comparison_mode=mode,
                    duration_ms=0.0,
                )

            # Perform detailed comparison
            drift_entries = await self.compare_configs(
                baseline_config,
                current_config,
                ne_id,
                mode
            )

            # Classify severity for each entry
            for entry in drift_entries:
                entry.severity = self.classifier.classify(entry)

            # Calculate duration
            duration_ms = (datetime.now(timezone.utc) - start_time).total_seconds() * 1000

            report = DriftReport(
                ne_id=ne_id,
                baseline_id=baseline_id or "",
                baseline_hash=baseline_hash,
                current_hash=current_hash,
                drift_entries=drift_entries,
                comparison_mode=mode,
                duration_ms=duration_ms,
            )

            logger.info(
                "Drift detection completed for NE %s: %d drifts found (%.2f ms)",
                ne_id, len(drift_entries), duration_ms
            )

            return report

        except Exception as e:
            logger.error("Drift detection failed for NE %s: %s", ne_id, e)
            raise ComparisonError(
                f"Drift detection failed: {e}",
                details={"ne_id": ne_id, "error": str(e)}
            )

    async def compare_configs(
        self,
        config1: str,
        config2: str,
        ne_id: str,
        comparison_mode: Optional[ComparisonMode] = None
    ) -> List[DriftEntry]:
        """Compare two configurations and identify differences.

        Args:
            config1: First (baseline) configuration.
            config2: Second (current) configuration.
            ne_id: Network element identifier.
            comparison_mode: Comparison mode override.

        Returns:
            List of drift entries.
        """
        mode = comparison_mode or self.comparison_mode
        drift_entries: List[DriftEntry] = []

        # Normalize if required
        if mode == ComparisonMode.NORMALIZED:
            config1 = self._normalize_config(config1)
            config2 = self._normalize_config(config2)

        # Detect format and compare
        if config1.strip().startswith("<") and config2.strip().startswith("<"):
            # XML comparison
            drift_entries = self._compare_xml(config1, config2, ne_id)
        else:
            # Line-based comparison
            drift_entries = self._compare_lines(config1, config2, ne_id)

        return drift_entries

    def classify_severity(
        self,
        drift_entry: DriftEntry,
        context: Optional[Dict[str, Any]] = None
    ) -> DriftSeverity:
        """Classify severity of a drift entry.

        Args:
            drift_entry: Drift entry to classify.
            context: Additional context.

        Returns:
            Severity level.
        """
        return self.classifier.classify(drift_entry, context)

    async def generate_report(
        self,
        report: DriftReport,
        include_entries: bool = True,
        format_type: str = "dict"
    ) -> Union[Dict[str, Any], str]:
        """Generate a formatted drift report.

        Args:
            report: Drift report to format.
            include_entries: Whether to include individual entries.
            format_type: Output format (dict, json, summary).

        Returns:
            Formatted report.
        """
        if format_type == "json":
            import json
            return json.dumps(report.to_dict(), indent=2, default=str)
        elif format_type == "summary":
            return self._generate_summary(report)

        result = report.to_dict()
        if not include_entries:
            result.pop("drift_entries", None)
        return result

    def _generate_summary(self, report: DriftReport) -> str:
        """Generate human-readable summary.

        Args:
            report: Drift report.

        Returns:
            Summary string.
        """
        lines = [
            f"Drift Detection Report: {report.report_id[:8]}",
            f"Network Element: {report.ne_id}",
            f"Detected: {report.detected_at.isoformat()}",
            "",
            "Summary:",
            f"  Total Drifts: {len(report.drift_entries)}",
            f"  Critical: {report.summary.get('critical_count', 0)}",
            f"  High: {report.summary.get('high_count', 0)}",
            f"  Moderate: {report.summary.get('moderate_count', 0)}",
            f"  Low: {report.summary.get('low_count', 0)}",
            "",
        ]

        if report.drift_entries:
            lines.append("Top Critical/High Severity Drifts:")
            critical_high = [
                e for e in report.drift_entries
                if e.severity in (DriftSeverity.CRITICAL, DriftSeverity.HIGH)
            ]
            for entry in critical_high[:5]:
                lines.append(f"  - [{entry.severity.value}] {entry.path}")
                lines.append(f"    Expected: {entry.expected[:50]}")
                lines.append(f"    Actual: {entry.actual[:50]}")

        return "\n".join(lines)

    def _calculate_hash(self, content: str) -> str:
        """Calculate hash of configuration content.

        Args:
            content: Configuration content.

        Returns:
            SHA-256 hash string.
        """
        return hashlib.sha256(content.encode()).hexdigest()

    def _normalize_config(self, config: str) -> str:
        """Normalize configuration for comparison.

        Args:
            config: Configuration content.

        Returns:
            Normalized configuration.
        """
        # Remove comments
        lines = []
        for line in config.splitlines():
            # Remove inline comments
            if "!" in line:
                line = line.split("!")[0]
            # Skip empty lines
            if line.strip():
                lines.append(line.strip())

        return "\n".join(lines)

    def _compare_lines(
        self,
        baseline: str,
        current: str,
        ne_id: str
    ) -> List[DriftEntry]:
        """Compare configurations line by line.

        Args:
            baseline: Baseline configuration.
            current: Current configuration.
            ne_id: Network element identifier.

        Returns:
            List of drift entries.
        """
        drift_entries: List[DriftEntry] = []

        baseline_lines = set(baseline.splitlines())
        current_lines = set(current.splitlines())

        # Find missing lines (in baseline but not in current)
        missing = baseline_lines - current_lines
        for line in missing:
            if line.strip():
                drift_entries.append(DriftEntry(
                    drift_type=DriftType.MISSING,
                    path=self._extract_path(line),
                    expected=line,
                    actual="",
                    description=f"Missing configuration: {line[:100]}",
                    ne_id=ne_id,
                ))

        # Find unexpected lines (in current but not in baseline)
        unexpected = current_lines - baseline_lines
        for line in unexpected:
            if line.strip():
                drift_entries.append(DriftEntry(
                    drift_type=DriftType.UNEXPECTED,
                    path=self._extract_path(line),
                    expected="",
                    actual=line,
                    description=f"Unexpected configuration: {line[:100]}",
                    ne_id=ne_id,
                ))

        return drift_entries

    def _compare_xml(
        self,
        baseline: str,
        current: str,
        ne_id: str
    ) -> List[DriftEntry]:
        """Compare XML configurations.

        Args:
            baseline: Baseline XML configuration.
            current: Current XML configuration.
            ne_id: Network element identifier.

        Returns:
            List of drift entries.
        """
        drift_entries: List[DriftEntry] = []

        try:
            baseline_root = ET.fromstring(baseline)
            current_root = ET.fromstring(current)

            # Compare elements recursively
            self._compare_xml_elements(
                baseline_root, current_root, "", ne_id, drift_entries
            )

        except ET.ParseError as e:
            logger.warning("XML parse error: %s, falling back to line comparison", e)
            return self._compare_lines(baseline, current, ne_id)

        return drift_entries

    def _compare_xml_elements(
        self,
        elem1: ET.Element,
        elem2: ET.Element,
        path: str,
        ne_id: str,
        drift_entries: List[DriftEntry]
    ) -> None:
        """Compare XML elements recursively.

        Args:
            elem1: First element.
            elem2: Second element.
            path: Current path.
            ne_id: Network element identifier.
            drift_entries: List to append drift entries to.
        """
        current_path = f"{path}/{elem1.tag}" if path else elem1.tag

        # Compare attributes
        attrs1 = dict(elem1.attrib)
        attrs2 = dict(elem2.attrib)

        for attr, value in attrs1.items():
            if attr not in attrs2:
                drift_entries.append(DriftEntry(
                    drift_type=DriftType.MISSING,
                    path=f"{current_path}[@{attr}]",
                    expected=value,
                    actual="",
                    description=f"Missing attribute: {attr}",
                    ne_id=ne_id,
                ))
            elif attrs2[attr] != value:
                drift_entries.append(DriftEntry(
                    drift_type=DriftType.VALUE_CHANGED,
                    path=f"{current_path}[@{attr}]",
                    expected=value,
                    actual=attrs2[attr],
                    description=f"Attribute value changed: {attr}",
                    ne_id=ne_id,
                ))

        for attr, value in attrs2.items():
            if attr not in attrs1:
                drift_entries.append(DriftEntry(
                    drift_type=DriftType.UNEXPECTED,
                    path=f"{current_path}[@{attr}]",
                    expected="",
                    actual=value,
                    description=f"Unexpected attribute: {attr}",
                    ne_id=ne_id,
                ))

        # Compare text content
        if elem1.text != elem2.text:
            text1 = (elem1.text or "").strip()
            text2 = (elem2.text or "").strip()
            if text1 != text2:
                drift_entries.append(DriftEntry(
                    drift_type=DriftType.VALUE_CHANGED,
                    path=current_path,
                    expected=text1,
                    actual=text2,
                    description="Element value changed",
                    ne_id=ne_id,
                ))

        # Compare child elements
        children1 = {c.tag: c for c in elem1}
        children2 = {c.tag: c for c in elem2}

        for tag in children1:
            if tag not in children2:
                drift_entries.append(DriftEntry(
                    drift_type=DriftType.MISSING,
                    path=f"{current_path}/{tag}",
                    expected="",
                    actual="",
                    description=f"Missing element: {tag}",
                    ne_id=ne_id,
                ))
            else:
                self._compare_xml_elements(
                    children1[tag], children2[tag],
                    current_path, ne_id, drift_entries
                )

        for tag in children2:
            if tag not in children1:
                drift_entries.append(DriftEntry(
                    drift_type=DriftType.UNEXPECTED,
                    path=f"{current_path}/{tag}",
                    expected="",
                    actual="",
                    description=f"Unexpected element: {tag}",
                    ne_id=ne_id,
                ))

    def _extract_path(self, line: str) -> str:
        """Extract configuration path from a line.

        Args:
            line: Configuration line.

        Returns:
            Extracted path.
        """
        # Simple path extraction
        parts = line.strip().split()
        if parts:
            return parts[0]
        return line[:50]

    async def set_baseline(
        self,
        ne_id: str,
        config: str
    ) -> str:
        """Set baseline configuration for a network element.

        Args:
            ne_id: Network element identifier.
            config: Baseline configuration content.

        Returns:
            Baseline hash.
        """
        async with self._lock:
            self._baselines[ne_id] = config
            self._baseline_hashes[ne_id] = self._calculate_hash(config)
            logger.info("Set baseline for NE %s", ne_id)
            return self._baseline_hashes[ne_id]

    async def get_baseline(self, ne_id: str) -> Optional[str]:
        """Get baseline configuration for a network element.

        Args:
            ne_id: Network element identifier.

        Returns:
            Baseline configuration or None.
        """
        return self._baselines.get(ne_id)

    async def start_monitoring(
        self,
        schedule: MonitoringSchedule
    ) -> bool:
        """Start scheduled drift monitoring.

        Args:
            schedule: Monitoring schedule configuration.

        Returns:
            True if started successfully.
        """
        async with self._lock:
            if schedule.schedule_id in self._monitoring_tasks:
                logger.warning("Monitoring already active for schedule %s", schedule.schedule_id)
                return False

            schedule.enabled = True
            schedule.next_run = schedule.calculate_next_run()
            self._monitoring_schedules[schedule.schedule_id] = schedule

            # Start monitoring task
            task = asyncio.create_task(self._monitoring_loop(schedule))
            self._monitoring_tasks[schedule.schedule_id] = task

            logger.info(
                "Started drift monitoring schedule %s for %d NEs",
                schedule.schedule_id[:8], len(schedule.ne_ids)
            )

            return True

    async def stop_monitoring(self, schedule_id: str) -> bool:
        """Stop scheduled drift monitoring.

        Args:
            schedule_id: Schedule identifier.

        Returns:
            True if stopped successfully.
        """
        async with self._lock:
            if schedule_id not in self._monitoring_tasks:
                return False

            task = self._monitoring_tasks[schedule_id]
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

            del self._monitoring_tasks[schedule_id]
            if schedule_id in self._monitoring_schedules:
                self._monitoring_schedules[schedule_id].enabled = False

            logger.info("Stopped drift monitoring schedule %s", schedule_id[:8])
            return True

    async def _monitoring_loop(self, schedule: MonitoringSchedule) -> None:
        """Monitoring loop for scheduled drift detection.

        Args:
            schedule: Monitoring schedule.
        """
        while schedule.enabled:
            try:
                await asyncio.sleep(schedule.interval_seconds)

                schedule.last_run = datetime.now(timezone.utc)
                schedule.next_run = schedule.calculate_next_run()

                # Perform drift detection for each NE
                for ne_id in schedule.ne_ids:
                    baseline = self._baselines.get(ne_id)
                    if not baseline:
                        logger.warning("No baseline for NE %s, skipping", ne_id)
                        continue

                    # In production, fetch current config from device
                    # For now, use baseline as placeholder
                    report = await self.detect_drift(
                        baseline_config=baseline,
                        current_config=baseline,  # Placeholder
                        ne_id=ne_id
                    )

                    # Generate alert if drifts detected
                    if report.drift_entries:
                        await self._generate_alert(report)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Monitoring loop error: %s", e)
                await asyncio.sleep(60)  # Wait before retry

    async def _generate_alert(self, report: DriftReport) -> DriftAlert:
        """Generate alert from drift report.

        Args:
            report: Drift report.

        Returns:
            Generated alert.
        """
        # Determine overall severity
        severity = DriftSeverity.LOW
        for entry in report.drift_entries:
            if entry.severity == DriftSeverity.CRITICAL:
                severity = DriftSeverity.CRITICAL
                break
            elif entry.severity == DriftSeverity.HIGH and severity != DriftSeverity.CRITICAL:
                severity = DriftSeverity.HIGH
            elif entry.severity == DriftSeverity.MODERATE and severity not in (
                DriftSeverity.CRITICAL, DriftSeverity.HIGH
            ):
                severity = DriftSeverity.MODERATE

        alert = DriftAlert(
            report_id=report.report_id,
            ne_id=report.ne_id,
            severity=severity,
            title=f"Configuration Drift Detected: {report.ne_id}",
            message=f"Detected {len(report.drift_entries)} configuration drift(s) "
                   f"on network element {report.ne_id}. "
                   f"Critical: {report.summary.get('critical_count', 0)}, "
                   f"High: {report.summary.get('high_count', 0)}",
            drift_count=len(report.drift_entries),
        )

        self._alerts.append(alert)

        logger.warning(
            "Drift alert generated for NE %s: %d drifts, severity %s",
            report.ne_id, len(report.drift_entries), severity.value
        )

        return alert

    async def get_alerts(
        self,
        acknowledged: Optional[bool] = None,
        severity: Optional[DriftSeverity] = None,
        limit: int = 100
    ) -> List[DriftAlert]:
        """Get drift alerts with filtering.

        Args:
            acknowledged: Filter by acknowledgement status.
            severity: Filter by severity.
            limit: Maximum alerts to return.

        Returns:
            List of alerts.
        """
        alerts = self._alerts

        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]

        return sorted(alerts, key=lambda a: a.created_at, reverse=True)[:limit]

    async def acknowledge_alert(
        self,
        alert_id: str,
        user: str
    ) -> bool:
        """Acknowledge a drift alert.

        Args:
            alert_id: Alert identifier.
            user: User acknowledging the alert.

        Returns:
            True if acknowledged.
        """
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledged = True
                alert.acknowledged_by = user
                logger.info("Alert %s acknowledged by %s", alert_id[:8], user)
                return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get drift detection statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            "baselines_count": len(self._baselines),
            "monitoring_schedules": len(self._monitoring_schedules),
            "active_monitoring": sum(
                1 for s in self._monitoring_schedules.values() if s.enabled
            ),
            "total_alerts": len(self._alerts),
            "unacknowledged_alerts": sum(
                1 for a in self._alerts if not a.acknowledged
            ),
            "state": self._state.value,
        }
