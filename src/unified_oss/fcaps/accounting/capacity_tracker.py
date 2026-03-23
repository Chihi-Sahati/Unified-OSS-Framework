"""
Capacity Tracker Module for Unified OSS Framework.

This module provides comprehensive capacity management and tracking
capabilities for multi-vendor network environments, including RF capacity,
throughput monitoring, subscriber tracking, and procurement recommendations.

Supports:
    - RF capacity monitoring (spectrum, power)
    - Throughput capacity tracking (bandwidth)
    - Subscriber capacity management (active/inactive)
    - Multi-vendor normalization (Ericsson, Huawei)
    - Procurement recommendations based on utilization
    - Trend analysis for capacity planning
    - BSS integration for billing and forecasting
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import statistics
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum, auto
from typing import (
    Any,
    AsyncGenerator,
    Awaitable,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Protocol,
    Set,
    Tuple,
    TypeVar,
    Union,
)

# Configure module logger
logger = logging.getLogger(__name__)

# Type aliases
T = TypeVar("T")
MetricValue = Union[int, float]
VendorType = str  # "ericsson" | "huawei"


class CapacityType(Enum):
    """Enumeration of capacity types for tracking.

    Attributes:
        RF_SPECTRUM: Radio frequency spectrum capacity.
        RF_POWER: RF transmission power capacity.
        THROUGHPUT: Network throughput/bandwidth capacity.
        SUBSCRIBER_ACTIVE: Active subscriber capacity.
        SUBSCRIBER_TOTAL: Total subscriber capacity.
        SESSION: Concurrent session capacity.
        STORAGE: Storage capacity.
        COMPUTE: Compute resource capacity.
        MEMORY: Memory allocation capacity.
    """

    RF_SPECTRUM = auto()
    RF_POWER = auto()
    THROUGHPUT = auto()
    SUBSCRIBER_ACTIVE = auto()
    SUBSCRIBER_TOTAL = auto()
    SESSION = auto()
    STORAGE = auto()
    COMPUTE = auto()
    MEMORY = auto()

    def __str__(self) -> str:
        """Return string representation."""
        return self.name.lower().replace("_", "-")


class CapacityUnit(Enum):
    """Enumeration of capacity measurement units.

    Attributes:
        HERTZ: Frequency in Hertz.
        MEGAHERTZ: Frequency in MHz.
        GIGAHERTZ: Frequency in GHz.
        WATT: Power in Watts.
        DECIBEL_MILLIWATT: Power in dBm.
        BITS_PER_SECOND: Data rate in bps.
        KILOBITS_PER_SECOND: Data rate in Kbps.
        MEGABITS_PER_SECOND: Data rate in Mbps.
        GIGABITS_PER_SECOND: Data rate in Gbps.
        COUNT: Simple count.
        PERCENT: Percentage.
        MEGABYTES: Storage in MB.
        GIGABYTES: Storage in GB.
        TERABYTES: Storage in TB.
    """

    HERTZ = auto()
    MEGAHERTZ = auto()
    GIGAHERTZ = auto()
    WATT = auto()
    DECIBEL_MILLIWATT = auto()
    BITS_PER_SECOND = auto()
    KILOBITS_PER_SECOND = auto()
    MEGABITS_PER_SECOND = auto()
    GIGABITS_PER_SECOND = auto()
    COUNT = auto()
    PERCENT = auto()
    MEGABYTES = auto()
    GIGABYTES = auto()
    TERABYTES = auto()

    def format_value(self, value: float) -> str:
        """Format value with appropriate unit suffix.

        Args:
            value: Numeric value to format.

        Returns:
            Formatted string with unit.
        """
        unit_suffixes = {
            CapacityUnit.HERTZ: "Hz",
            CapacityUnit.MEGAHERTZ: "MHz",
            CapacityUnit.GIGAHERTZ: "GHz",
            CapacityUnit.WATT: "W",
            CapacityUnit.DECIBEL_MILLIWATT: "dBm",
            CapacityUnit.BITS_PER_SECOND: "bps",
            CapacityUnit.KILOBITS_PER_SECOND: "Kbps",
            CapacityUnit.MEGABITS_PER_SECOND: "Mbps",
            CapacityUnit.GIGABITS_PER_SECOND: "Gbps",
            CapacityUnit.COUNT: "",
            CapacityUnit.PERCENT: "%",
            CapacityUnit.MEGABYTES: "MB",
            CapacityUnit.GIGABYTES: "GB",
            CapacityUnit.TERABYTES: "TB",
        }
        return f"{value:.2f} {unit_suffixes.get(self, '')}".strip()


class AlertSeverity(Enum):
    """Severity levels for capacity alerts."""

    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFORMATIONAL = auto()


class TrendDirection(Enum):
    """Trend direction for capacity analysis."""

    INCREASING = auto()
    DECREASING = auto()
    STABLE = auto()
    UNKNOWN = auto()


class RecommendationPriority(Enum):
    """Priority levels for procurement recommendations."""

    URGENT = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFORMATIONAL = auto()


@dataclass
class CapacityMetric:
    """Represents a single capacity measurement.

    Attributes:
        metric_id: Unique identifier for the metric.
        name: Human-readable metric name.
        capacity_type: Type of capacity being measured.
        vendor: Source vendor system.
        network_element_id: Associated network element.
        total_capacity: Maximum capacity available.
        used_capacity: Currently used capacity.
        unit: Measurement unit.
        timestamp: Measurement timestamp.
        vendor_metadata: Original vendor-specific metadata.
        tags: Additional tags for categorization.
    """

    metric_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    capacity_type: CapacityType = CapacityType.THROUGHPUT
    vendor: VendorType = "cim"
    network_element_id: str = ""
    total_capacity: float = 0.0
    used_capacity: float = 0.0
    unit: CapacityUnit = CapacityUnit.COUNT
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    vendor_metadata: Dict[str, Any] = field(default_factory=dict)
    tags: Dict[str, str] = field(default_factory=dict)

    @property
    def available_capacity(self) -> float:
        """Calculate available capacity.

        Returns:
            Remaining available capacity.
        """
        return max(0, self.total_capacity - self.used_capacity)

    @property
    def utilization_percentage(self) -> float:
        """Calculate utilization percentage.

        Returns:
            Utilization as percentage (0-100).
        """
        if self.total_capacity == 0:
            return 0.0
        return min(100.0, (self.used_capacity / self.total_capacity) * 100.0)

    @property
    def utilization_status(self) -> str:
        """Get utilization status label.

        Returns:
            Status string (healthy, warning, critical, exceeded).
        """
        pct = self.utilization_percentage
        if pct >= 100:
            return "exceeded"
        if pct >= 90:
            return "critical"
        if pct >= 75:
            return "warning"
        return "healthy"

    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary representation.

        Returns:
            Dictionary representation of the metric.
        """
        return {
            "metric_id": self.metric_id,
            "name": self.name,
            "capacity_type": str(self.capacity_type),
            "vendor": self.vendor,
            "network_element_id": self.network_element_id,
            "total_capacity": self.total_capacity,
            "used_capacity": self.used_capacity,
            "available_capacity": self.available_capacity,
            "utilization_percentage": round(self.utilization_percentage, 2),
            "utilization_status": self.utilization_status,
            "unit": self.unit.name,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
        }


@dataclass
class CapacityAlert:
    """Represents a capacity-related alert.

    Attributes:
        alert_id: Unique identifier for the alert.
        metric_id: Associated capacity metric ID.
        alert_type: Type of alert (threshold, trend, forecast).
        severity: Alert severity level.
        message: Human-readable alert message.
        current_value: Current metric value.
        threshold_value: Threshold that triggered the alert.
        created_at: Alert creation timestamp.
        acknowledged: Whether alert has been acknowledged.
        acknowledged_at: Acknowledgment timestamp.
        acknowledged_by: User who acknowledged.
        recommendation: Recommended action.
        details: Additional alert details.
    """

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metric_id: str = ""
    alert_type: str = ""
    severity: AlertSeverity = AlertSeverity.INFORMATIONAL
    message: str = ""
    current_value: float = 0.0
    threshold_value: float = 0.0
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
    recommendation: str = ""
    details: Dict[str, Any] = field(default_factory=dict)

    def acknowledge(self, user: str) -> None:
        """Acknowledge the alert.

        Args:
            user: User acknowledging the alert.
        """
        self.acknowledged = True
        self.acknowledged_at = datetime.now(timezone.utc)
        self.acknowledged_by = user

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary representation.

        Returns:
            Dictionary representation of the alert.
        """
        return {
            "alert_id": self.alert_id,
            "metric_id": self.metric_id,
            "alert_type": self.alert_type,
            "severity": self.severity.name,
            "message": self.message,
            "current_value": self.current_value,
            "threshold_value": self.threshold_value,
            "created_at": self.created_at.isoformat(),
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "recommendation": self.recommendation,
            "details": self.details,
        }


@dataclass
class CapacityTrend:
    """Represents capacity trend analysis results.

    Attributes:
        metric_id: Associated metric ID.
        period_start: Start of analysis period.
        period_end: End of analysis period.
        direction: Trend direction.
        slope: Rate of change per day.
        forecast_date: Projected exhaustion date (if applicable).
        confidence: Confidence score (0-1).
        data_points: Number of data points analyzed.
        min_value: Minimum value in period.
        max_value: Maximum value in period.
        avg_value: Average value in period.
        std_deviation: Standard deviation of values.
    """

    metric_id: str = ""
    period_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    period_end: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    direction: TrendDirection = TrendDirection.UNKNOWN
    slope: float = 0.0
    forecast_date: Optional[datetime] = None
    confidence: float = 0.0
    data_points: int = 0
    min_value: float = 0.0
    max_value: float = 0.0
    avg_value: float = 0.0
    std_deviation: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert trend to dictionary representation.

        Returns:
            Dictionary representation of the trend.
        """
        return {
            "metric_id": self.metric_id,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "direction": self.direction.name,
            "slope": round(self.slope, 4),
            "forecast_date": self.forecast_date.isoformat() if self.forecast_date else None,
            "confidence": round(self.confidence, 2),
            "data_points": self.data_points,
            "min_value": round(self.min_value, 2),
            "max_value": round(self.max_value, 2),
            "avg_value": round(self.avg_value, 2),
            "std_deviation": round(self.std_deviation, 2),
        }


@dataclass
class ProcurementRecommendation:
    """Represents a capacity procurement recommendation.

    Attributes:
        recommendation_id: Unique identifier.
        metric_id: Associated capacity metric.
        priority: Recommendation priority level.
        title: Short recommendation title.
        description: Detailed description.
        current_capacity: Current capacity value.
        recommended_capacity: Recommended additional capacity.
        estimated_cost: Estimated procurement cost.
        currency: Cost currency.
        rationale: Reasoning for recommendation.
        urgency_reason: Explanation of urgency.
        created_at: Creation timestamp.
        vendor_suggestions: Vendor-specific suggestions.
        timeline: Recommended implementation timeline.
    """

    recommendation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metric_id: str = ""
    priority: RecommendationPriority = RecommendationPriority.MEDIUM
    title: str = ""
    description: str = ""
    current_capacity: float = 0.0
    recommended_capacity: float = 0.0
    estimated_cost: Optional[float] = None
    currency: str = "USD"
    rationale: str = ""
    urgency_reason: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    vendor_suggestions: List[Dict[str, Any]] = field(default_factory=list)
    timeline: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert recommendation to dictionary representation.

        Returns:
            Dictionary representation of the recommendation.
        """
        return {
            "recommendation_id": self.recommendation_id,
            "metric_id": self.metric_id,
            "priority": self.priority.name,
            "title": self.title,
            "description": self.description,
            "current_capacity": self.current_capacity,
            "recommended_capacity": self.recommended_capacity,
            "estimated_cost": self.estimated_cost,
            "currency": self.currency,
            "rationale": self.rationale,
            "urgency_reason": self.urgency_reason,
            "created_at": self.created_at.isoformat(),
            "vendor_suggestions": self.vendor_suggestions,
            "timeline": self.timeline,
        }


class VendorCapacityMapper:
    """Maps vendor-specific capacity data to unified format.

    Provides normalization rules for Ericsson and Huawei capacity
    metrics to ensure consistent tracking across vendors.
    """

    # Ericsson field mappings
    ERICSSON_MAPPINGS = {
        "rf_spectrum": {
            "field": "spectrumCapacity",
            "total_field": "totalSpectrumMHz",
            "used_field": "usedSpectrumMHz",
            "unit": CapacityUnit.MEGAHERTZ,
        },
        "rf_power": {
            "field": "powerCapacity",
            "total_field": "maxPowerWatt",
            "used_field": "currentPowerWatt",
            "unit": CapacityUnit.WATT,
        },
        "throughput": {
            "field": "throughputCapacity",
            "total_field": "maxThroughputGbps",
            "used_field": "currentThroughputGbps",
            "unit": CapacityUnit.GIGABITS_PER_SECOND,
        },
        "subscriber_active": {
            "field": "activeSubscriberCapacity",
            "total_field": "maxActiveSubscribers",
            "used_field": "currentActiveSubscribers",
            "unit": CapacityUnit.COUNT,
        },
        "subscriber_total": {
            "field": "totalSubscriberCapacity",
            "total_field": "maxTotalSubscribers",
            "used_field": "currentTotalSubscribers",
            "unit": CapacityUnit.COUNT,
        },
    }

    # Huawei field mappings
    HUAWEI_MAPPINGS = {
        "rf_spectrum": {
            "field": "SpectrumCapacity",
            "total_field": "TotalSpectrum",
            "used_field": "UsedSpectrum",
            "unit": CapacityUnit.MEGAHERTZ,
        },
        "rf_power": {
            "field": "PowerCapacity",
            "total_field": "MaxPower",
            "used_field": "CurrentPower",
            "unit": CapacityUnit.DECIBEL_MILLIWATT,
        },
        "throughput": {
            "field": "BandwidthCapacity",
            "total_field": "MaxBandwidth",
            "used_field": "UsedBandwidth",
            "unit": CapacityUnit.MEGABITS_PER_SECOND,
        },
        "subscriber_active": {
            "field": "ActiveUserCapacity",
            "total_field": "MaxActiveUser",
            "used_field": "CurrentActiveUser",
            "unit": CapacityUnit.COUNT,
        },
        "subscriber_total": {
            "field": "TotalUserCapacity",
            "total_field": "MaxTotalUser",
            "used_field": "CurrentTotalUser",
            "unit": CapacityUnit.COUNT,
        },
    }

    @classmethod
    def normalize(
        cls,
        vendor_data: Dict[str, Any],
        vendor: VendorType,
        capacity_type: CapacityType,
        network_element_id: str,
    ) -> Optional[CapacityMetric]:
        """Normalize vendor-specific capacity data.

        Args:
            vendor_data: Raw vendor capacity data.
            vendor: Vendor identifier.
            capacity_type: Type of capacity to extract.
            network_element_id: Network element identifier.

        Returns:
            Normalized CapacityMetric or None if not found.
        """
        type_name = capacity_type.name.lower()

        if vendor.lower() == "ericsson":
            mapping = cls.ERICSSON_MAPPINGS.get(type_name)
        elif vendor.lower() == "huawei":
            mapping = cls.HUAWEI_MAPPINGS.get(type_name)
        else:
            # Assume data is already in CIM format
            return cls._parse_cim_data(vendor_data, capacity_type, network_element_id)

        if mapping is None:
            return None

        field_name = mapping["field"]
        if field_name not in vendor_data:
            return None

        field_data = vendor_data[field_name]

        return CapacityMetric(
            name=f"{capacity_type.name.replace('_', ' ').title()} - {network_element_id}",
            capacity_type=capacity_type,
            vendor=vendor.lower(),
            network_element_id=network_element_id,
            total_capacity=float(field_data.get(mapping["total_field"], 0)),
            used_capacity=float(field_data.get(mapping["used_field"], 0)),
            unit=mapping["unit"],
            vendor_metadata=vendor_data,
            timestamp=cls._parse_timestamp(vendor_data.get("timestamp")),
        )

    @classmethod
    def _parse_cim_data(
        cls,
        data: Dict[str, Any],
        capacity_type: CapacityType,
        network_element_id: str,
    ) -> Optional[CapacityMetric]:
        """Parse CIM-formatted capacity data.

        Args:
            data: CIM format capacity data.
            capacity_type: Type of capacity.
            network_element_id: Network element identifier.

        Returns:
            CapacityMetric or None.
        """
        type_name = str(capacity_type)

        if type_name not in data:
            return None

        metric_data = data[type_name]

        return CapacityMetric(
            metric_id=metric_data.get("metricId", str(uuid.uuid4())),
            name=metric_data.get("name", f"{capacity_type.name} - {network_element_id}"),
            capacity_type=capacity_type,
            vendor="cim",
            network_element_id=network_element_id,
            total_capacity=float(metric_data.get("totalCapacity", 0)),
            used_capacity=float(metric_data.get("usedCapacity", 0)),
            unit=CapacityUnit[metric_data.get("unit", "COUNT")],
            timestamp=cls._parse_timestamp(metric_data.get("timestamp")),
            tags=metric_data.get("tags", {}),
        )

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime:
        """Parse timestamp from various formats.

        Args:
            value: Timestamp value.

        Returns:
            Parsed datetime.
        """
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
        return datetime.now(timezone.utc)


class CapacityTracker:
    """Tracks and manages network capacity across multi-vendor environments.

    This class provides comprehensive capacity management including:
    - RF capacity monitoring (spectrum, power)
    - Throughput capacity tracking
    - Subscriber capacity management
    - Multi-vendor normalization
    - Procurement recommendations
    - Trend analysis and forecasting
    - BSS integration for billing

    Attributes:
        metrics: Dictionary of tracked capacity metrics.
        alerts: List of generated capacity alerts.
        utilization_thresholds: Threshold percentages for alerts.
        trend_window_days: Days of data for trend analysis.
    """

    # Default utilization thresholds
    DEFAULT_THRESHOLDS = {
        "warning": 75.0,
        "critical": 90.0,
        "exceeded": 100.0,
    }

    # Default trend analysis window
    DEFAULT_TREND_WINDOW = 30  # days

    def __init__(
        self,
        db_pool: Optional[Any] = None,
        bss_client: Optional[Any] = None,
        utilization_thresholds: Optional[Dict[str, float]] = None,
        trend_window_days: int = DEFAULT_TREND_WINDOW,
    ) -> None:
        """Initialize the Capacity Tracker.

        Args:
            db_pool: Database connection pool for persistence.
            bss_client: BSS integration client for billing.
            utilization_thresholds: Custom threshold percentages.
            trend_window_days: Days of data for trend analysis.
        """
        self._db_pool = db_pool
        self._bss_client = bss_client
        self._metrics: Dict[str, CapacityMetric] = {}
        self._metric_history: Dict[str, List[CapacityMetric]] = {}
        self._alerts: List[CapacityAlert] = []
        self._recommendations: List[ProcurementRecommendation] = []
        self._lock = asyncio.Lock()

        self.utilization_thresholds = utilization_thresholds or self.DEFAULT_THRESHOLDS
        self.trend_window_days = trend_window_days

        logger.info(
            f"CapacityTracker initialized with thresholds: {self.utilization_thresholds}"
        )

    async def track_capacity(
        self,
        vendor_data: Dict[str, Any],
        vendor: VendorType,
        capacity_types: Optional[List[CapacityType]] = None,
        network_element_id: str = "",
        persist: bool = True,
    ) -> List[CapacityMetric]:
        """Track capacity from vendor data.

        Args:
            vendor_data: Raw vendor capacity data.
            vendor: Vendor identifier (ericsson, huawei).
            capacity_types: Specific capacity types to track.
            network_element_id: Associated network element.
            persist: Whether to persist to database.

        Returns:
            List of normalized CapacityMetric objects.
        """
        if capacity_types is None:
            capacity_types = [
                CapacityType.RF_SPECTRUM,
                CapacityType.RF_POWER,
                CapacityType.THROUGHPUT,
                CapacityType.SUBSCRIBER_ACTIVE,
                CapacityType.SUBSCRIBER_TOTAL,
            ]

        metrics = []
        alerts = []

        async with self._lock:
            for cap_type in capacity_types:
                metric = VendorCapacityMapper.normalize(
                    vendor_data, vendor, cap_type, network_element_id
                )

                if metric is None:
                    continue

                # Store metric
                self._metrics[metric.metric_id] = metric

                # Add to history
                if metric.metric_id not in self._metric_history:
                    self._metric_history[metric.metric_id] = []
                self._metric_history[metric.metric_id].append(metric)

                # Trim history to window
                cutoff = datetime.now(timezone.utc) - timedelta(days=self.trend_window_days)
                self._metric_history[metric.metric_id] = [
                    m for m in self._metric_history[metric.metric_id]
                    if m.timestamp >= cutoff
                ]

                # Check thresholds and generate alerts
                alert = self._check_threshold(metric)
                if alert:
                    alerts.append(alert)
                    self._alerts.append(alert)

                metrics.append(metric)

        if persist and self._db_pool:
            await self._persist_metrics(metrics)

        if alerts:
            logger.info(f"Generated {len(alerts)} capacity alerts for {network_element_id}")

        return metrics

    def _check_threshold(self, metric: CapacityMetric) -> Optional[CapacityAlert]:
        """Check if metric exceeds thresholds.

        Args:
            metric: Capacity metric to check.

        Returns:
            CapacityAlert if threshold exceeded, None otherwise.
        """
        utilization = metric.utilization_percentage

        if utilization >= self.utilization_thresholds["exceeded"]:
            return CapacityAlert(
                metric_id=metric.metric_id,
                alert_type="capacity_exceeded",
                severity=AlertSeverity.CRITICAL,
                message=(
                    f"Capacity exceeded for {metric.name}: "
                    f"{utilization:.1f}% utilized"
                ),
                current_value=utilization,
                threshold_value=self.utilization_thresholds["exceeded"],
                recommendation=(
                    "Immediate capacity expansion required. "
                    "Consider emergency procurement or load redistribution."
                ),
                details={
                    "total_capacity": metric.total_capacity,
                    "used_capacity": metric.used_capacity,
                    "unit": metric.unit.name,
                    "network_element_id": metric.network_element_id,
                },
            )

        if utilization >= self.utilization_thresholds["critical"]:
            return CapacityAlert(
                metric_id=metric.metric_id,
                alert_type="capacity_critical",
                severity=AlertSeverity.HIGH,
                message=(
                    f"Critical capacity level for {metric.name}: "
                    f"{utilization:.1f}% utilized"
                ),
                current_value=utilization,
                threshold_value=self.utilization_thresholds["critical"],
                recommendation=(
                    "Plan for capacity expansion within 1-2 weeks. "
                    "Initiate procurement process if not already started."
                ),
                details={
                    "total_capacity": metric.total_capacity,
                    "used_capacity": metric.used_capacity,
                    "available_capacity": metric.available_capacity,
                    "unit": metric.unit.name,
                    "network_element_id": metric.network_element_id,
                },
            )

        if utilization >= self.utilization_thresholds["warning"]:
            return CapacityAlert(
                metric_id=metric.metric_id,
                alert_type="capacity_warning",
                severity=AlertSeverity.MEDIUM,
                message=(
                    f"Capacity warning for {metric.name}: "
                    f"{utilization:.1f}% utilized"
                ),
                current_value=utilization,
                threshold_value=self.utilization_thresholds["warning"],
                recommendation=(
                    "Monitor capacity closely and plan for expansion "
                    "within the next 1-2 months."
                ),
                details={
                    "total_capacity": metric.total_capacity,
                    "used_capacity": metric.used_capacity,
                    "available_capacity": metric.available_capacity,
                    "unit": metric.unit.name,
                    "network_element_id": metric.network_element_id,
                },
            )

        return None

    async def get_utilization(
        self,
        capacity_type: Optional[CapacityType] = None,
        network_element_id: Optional[str] = None,
        vendor: Optional[VendorType] = None,
    ) -> Dict[str, Any]:
        """Get capacity utilization metrics.

        Args:
            capacity_type: Filter by capacity type.
            network_element_id: Filter by network element.
            vendor: Filter by vendor.

        Returns:
            Utilization summary dictionary.
        """
        filtered_metrics = list(self._metrics.values())

        # Apply filters
        if capacity_type:
            filtered_metrics = [
                m for m in filtered_metrics if m.capacity_type == capacity_type
            ]
        if network_element_id:
            filtered_metrics = [
                m for m in filtered_metrics if m.network_element_id == network_element_id
            ]
        if vendor:
            filtered_metrics = [
                m for m in filtered_metrics if m.vendor == vendor.lower()
            ]

        if not filtered_metrics:
            return {
                "metrics": [],
                "summary": {},
            }

        # Calculate summary
        total_capacity = sum(m.total_capacity for m in filtered_metrics)
        total_used = sum(m.used_capacity for m in filtered_metrics)
        overall_utilization = (
            (total_used / total_capacity * 100) if total_capacity > 0 else 0
        )

        # Group by capacity type
        by_type: Dict[str, Dict[str, Any]] = {}
        for metric in filtered_metrics:
            type_name = str(metric.capacity_type)
            if type_name not in by_type:
                by_type[type_name] = {
                    "total_capacity": 0.0,
                    "used_capacity": 0.0,
                    "metrics": [],
                }
            by_type[type_name]["total_capacity"] += metric.total_capacity
            by_type[type_name]["used_capacity"] += metric.used_capacity
            by_type[type_name]["metrics"].append(metric.metric_id)

        # Calculate per-type utilization
        for type_name, data in by_type.items():
            data["utilization_percentage"] = (
                (data["used_capacity"] / data["total_capacity"] * 100)
                if data["total_capacity"] > 0
                else 0
            )

        return {
            "metrics": [m.to_dict() for m in filtered_metrics],
            "summary": {
                "metric_count": len(filtered_metrics),
                "total_capacity": total_capacity,
                "total_used": total_used,
                "overall_utilization": round(overall_utilization, 2),
                "by_capacity_type": {
                    k: {
                        "total_capacity": v["total_capacity"],
                        "used_capacity": v["used_capacity"],
                        "utilization_percentage": round(v["utilization_percentage"], 2),
                    }
                    for k, v in by_type.items()
                },
            },
        }

    async def generate_recommendations(
        self,
        min_utilization: float = 75.0,
        include_forecast: bool = True,
    ) -> List[ProcurementRecommendation]:
        """Generate procurement recommendations based on utilization.

        Args:
            min_utilization: Minimum utilization to generate recommendation.
            include_forecast: Include trend-based forecasting.

        Returns:
            List of procurement recommendations.
        """
        recommendations = []

        for metric in self._metrics.values():
            if metric.utilization_percentage < min_utilization:
                continue

            # Get trend if available
            trend = None
            if include_forecast:
                trend = await self.get_trends(metric.metric_id)
                if trend:
                    trend = trend[0] if trend else None

            # Calculate recommended capacity
            recommended_increase = self._calculate_capacity_increase(
                metric, trend
            )

            # Determine priority
            priority = self._get_recommendation_priority(metric, trend)

            # Create recommendation
            recommendation = ProcurementRecommendation(
                metric_id=metric.metric_id,
                priority=priority,
                title=f"Capacity Expansion: {metric.name}",
                description=(
                    f"Current utilization at {metric.utilization_percentage:.1f}% "
                    f"({metric.used_capacity:.2f}/{metric.total_capacity:.2f} "
                    f"{metric.unit.format_value(0).split()[-1] if metric.unit != CapacityUnit.COUNT else 'units'})"
                ),
                current_capacity=metric.total_capacity,
                recommended_capacity=metric.total_capacity + recommended_increase,
                rationale=self._generate_rationale(metric, trend),
                urgency_reason=self._generate_urgency_reason(metric, trend),
                vendor_suggestions=self._get_vendor_suggestions(metric),
                timeline=self._get_timeline(priority),
            )

            recommendations.append(recommendation)

        # Sort by priority
        priority_order = {
            RecommendationPriority.URGENT: 0,
            RecommendationPriority.HIGH: 1,
            RecommendationPriority.MEDIUM: 2,
            RecommendationPriority.LOW: 3,
            RecommendationPriority.INFORMATIONAL: 4,
        }
        recommendations.sort(key=lambda r: priority_order.get(r.priority, 5))

        async with self._lock:
            self._recommendations.extend(recommendations)

        logger.info(f"Generated {len(recommendations)} procurement recommendations")
        return recommendations

    def _calculate_capacity_increase(
        self,
        metric: CapacityMetric,
        trend: Optional[CapacityTrend],
    ) -> float:
        """Calculate recommended capacity increase.

        Args:
            metric: Current capacity metric.
            trend: Trend analysis (optional).

        Returns:
            Recommended additional capacity.
        """
        # Base increase: 50% of current capacity for headroom
        base_increase = metric.total_capacity * 0.5

        # If trending upward, factor in growth rate
        if trend and trend.direction == TrendDirection.INCREASING:
            # Project growth over next 6 months
            daily_growth = trend.slope
            monthly_growth = daily_growth * 30
            six_month_growth = monthly_growth * 6

            # Add projected growth plus buffer
            base_increase = max(base_increase, six_month_growth * 1.2)

        return base_increase

    def _get_recommendation_priority(
        self,
        metric: CapacityMetric,
        trend: Optional[CapacityTrend],
    ) -> RecommendationPriority:
        """Determine recommendation priority.

        Args:
            metric: Capacity metric.
            trend: Trend analysis.

        Returns:
            Recommendation priority level.
        """
        utilization = metric.utilization_percentage

        if utilization >= 100:
            return RecommendationPriority.URGENT
        if utilization >= 90:
            if trend and trend.direction == TrendDirection.INCREASING:
                return RecommendationPriority.URGENT
            return RecommendationPriority.HIGH
        if utilization >= 80:
            if trend and trend.forecast_date:
                days_to_exhaustion = (
                    trend.forecast_date - datetime.now(timezone.utc)
                ).days
                if days_to_exhaustion <= 30:
                    return RecommendationPriority.HIGH
            return RecommendationPriority.MEDIUM
        if utilization >= 75:
            return RecommendationPriority.LOW
        return RecommendationPriority.INFORMATIONAL

    def _generate_rationale(
        self,
        metric: CapacityMetric,
        trend: Optional[CapacityTrend],
    ) -> str:
        """Generate rationale for recommendation.

        Args:
            metric: Capacity metric.
            trend: Trend analysis.

        Returns:
            Rationale string.
        """
        rationale = (
            f"Current capacity utilization is {metric.utilization_percentage:.1f}%, "
            f"which exceeds the recommended threshold. "
        )

        if trend:
            if trend.direction == TrendDirection.INCREASING:
                rationale += (
                    f"Utilization has been increasing at a rate of "
                    f"{trend.slope:.2f} units per day. "
                )
                if trend.forecast_date:
                    rationale += (
                        f"At current growth rate, capacity will be exhausted "
                        f"by {trend.forecast_date.strftime('%Y-%m-%d')}. "
                    )
            elif trend.direction == TrendDirection.STABLE:
                rationale += "Utilization has been relatively stable. "

        rationale += (
            "Procurement action is recommended to ensure service continuity "
            "and accommodate future growth."
        )

        return rationale

    def _generate_urgency_reason(
        self,
        metric: CapacityMetric,
        trend: Optional[CapacityTrend],
    ) -> str:
        """Generate urgency reason for recommendation.

        Args:
            metric: Capacity metric.
            trend: Trend analysis.

        Returns:
            Urgency reason string.
        """
        if metric.utilization_percentage >= 100:
            return (
                "Capacity has been exceeded. Service degradation or outage "
                "risk is imminent without immediate action."
            )

        if metric.utilization_percentage >= 90:
            return (
                "Capacity is at critical level. There is limited headroom "
                "for traffic spikes or unexpected demand increases."
            )

        if trend and trend.forecast_date:
            days = (trend.forecast_date - datetime.now(timezone.utc)).days
            if days <= 30:
                return (
                    f"Based on current trends, capacity will be exhausted "
                    f"in approximately {days} days."
                )

        return (
            "Capacity utilization is elevated and should be addressed "
            "proactively to avoid future constraints."
        )

    def _get_vendor_suggestions(self, metric: CapacityMetric) -> List[Dict[str, Any]]:
        """Get vendor-specific suggestions for capacity expansion.

        Args:
            metric: Capacity metric.

        Returns:
            List of vendor suggestions.
        """
        suggestions = []

        # Generic suggestions based on capacity type
        type_suggestions = {
            CapacityType.RF_SPECTRUM: [
                {
                    "vendor": "ericsson",
                    "suggestion": "Acquire additional spectrum license or optimize spectrum efficiency",
                    "products": ["Spectrum License Extension", "Carrier Aggregation Upgrade"],
                },
                {
                    "vendor": "huawei",
                    "suggestion": "Expand spectrum allocation or implement dynamic spectrum sharing",
                    "products": ["Spectrum Management Module", "DSS License"],
                },
            ],
            CapacityType.RF_POWER: [
                {
                    "vendor": "ericsson",
                    "suggestion": "Upgrade power amplifiers or add additional RF units",
                    "products": ["High-Power PA Module", "RF Unit Expansion"],
                },
                {
                    "vendor": "huawei",
                    "suggestion": "Increase power budget or optimize power allocation",
                    "products": ["Power Amplifier Upgrade", "Power Optimization License"],
                },
            ],
            CapacityType.THROUGHPUT: [
                {
                    "vendor": "ericsson",
                    "suggestion": "Upgrade backhaul or add processing capacity",
                    "products": ["Backhaul Expansion", "Baseband Processing Unit"],
                },
                {
                    "vendor": "huawei",
                    "suggestion": "Expand bandwidth capacity or optimize data paths",
                    "products": ["Bandwidth License", "Processing Board Upgrade"],
                },
            ],
            CapacityType.SUBSCRIBER_ACTIVE: [
                {
                    "vendor": "ericsson",
                    "suggestion": "Expand subscriber license or add processing capacity",
                    "products": ["Subscriber License Extension", "MME Expansion"],
                },
                {
                    "vendor": "huawei",
                    "suggestion": "Increase subscriber capacity license",
                    "products": ["User Capacity License", "EPC Expansion Module"],
                },
            ],
        }

        return type_suggestions.get(metric.capacity_type, [])

    def _get_timeline(self, priority: RecommendationPriority) -> str:
        """Get implementation timeline based on priority.

        Args:
            priority: Recommendation priority.

        Returns:
            Timeline string.
        """
        timelines = {
            RecommendationPriority.URGENT: "Immediate (0-2 weeks)",
            RecommendationPriority.HIGH: "Short-term (2-4 weeks)",
            RecommendationPriority.MEDIUM: "Medium-term (1-2 months)",
            RecommendationPriority.LOW: "Planned (2-3 months)",
            RecommendationPriority.INFORMATIONAL: "As budget allows (3-6 months)",
        }
        return timelines.get(priority, "As needed")

    async def get_trends(
        self,
        metric_id: Optional[str] = None,
        period_days: int = 30,
    ) -> List[CapacityTrend]:
        """Analyze capacity trends for forecasting.

        Args:
            metric_id: Specific metric to analyze, or None for all.
            period_days: Number of days to analyze.

        Returns:
            List of trend analysis results.
        """
        trends = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=period_days)

        metric_ids = [metric_id] if metric_id else list(self._metric_history.keys())

        for mid in metric_ids:
            history = self._metric_history.get(mid, [])
            if len(history) < 2:
                continue

            # Filter to period
            history = [m for m in history if m.timestamp >= cutoff]
            if len(history) < 2:
                continue

            # Sort by timestamp
            history.sort(key=lambda m: m.timestamp)

            # Calculate statistics
            values = [m.utilization_percentage for m in history]
            min_val = min(values)
            max_val = max(values)
            avg_val = statistics.mean(values)

            if len(values) > 1:
                std_dev = statistics.stdev(values)
            else:
                std_dev = 0.0

            # Calculate trend direction and slope using linear regression
            slope, direction, forecast_date, confidence = self._calculate_trend(
                history
            )

            trend = CapacityTrend(
                metric_id=mid,
                period_start=history[0].timestamp,
                period_end=history[-1].timestamp,
                direction=direction,
                slope=slope,
                forecast_date=forecast_date,
                confidence=confidence,
                data_points=len(history),
                min_value=min_val,
                max_value=max_val,
                avg_value=avg_val,
                std_deviation=std_dev,
            )

            trends.append(trend)

        return trends

    def _calculate_trend(
        self,
        history: List[CapacityMetric],
    ) -> Tuple[float, TrendDirection, Optional[datetime], float]:
        """Calculate trend using linear regression.

        Args:
            history: List of historical capacity metrics.

        Returns:
            Tuple of (slope, direction, forecast_date, confidence).
        """
        if len(history) < 2:
            return 0.0, TrendDirection.UNKNOWN, None, 0.0

        # Extract data points
        first_timestamp = history[0].timestamp
        x_values = [
            (m.timestamp - first_timestamp).total_seconds() / 86400  # days
            for m in history
        ]
        y_values = [m.utilization_percentage for m in history]

        # Linear regression (least squares)
        n = len(x_values)
        sum_x = sum(x_values)
        sum_y = sum(y_values)
        sum_xy = sum(x * y for x, y in zip(x_values, y_values))
        sum_x2 = sum(x * x for x in x_values)

        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            return 0.0, TrendDirection.STABLE, None, 0.0

        slope = (n * sum_xy - sum_x * sum_y) / denominator
        intercept = (sum_y - slope * sum_x) / n

        # Determine direction
        if slope > 0.5:
            direction = TrendDirection.INCREASING
        elif slope < -0.5:
            direction = TrendDirection.DECREASING
        else:
            direction = TrendDirection.STABLE

        # Calculate R-squared for confidence
        y_mean = sum_y / n
        ss_tot = sum((y - y_mean) ** 2 for y in y_values)
        ss_res = sum(
            (y - (slope * x + intercept)) ** 2
            for x, y in zip(x_values, y_values)
        )
        r_squared = 1 - (ss_res / ss_tot) if ss_tot > 0 else 0
        confidence = max(0, min(1, r_squared))

        # Forecast exhaustion date if trending upward
        forecast_date = None
        if slope > 0 and confidence > 0.3:
            latest = history[-1]
            if latest.total_capacity > 0:
                current_utilization = latest.utilization_percentage
                remaining_utilization = 100 - current_utilization
                days_to_exhaustion = remaining_utilization / slope

                if days_to_exhaustion > 0 and days_to_exhaustion < 365:
                    forecast_date = datetime.now(timezone.utc) + timedelta(
                        days=days_to_exhaustion
                    )

        return slope, direction, forecast_date, confidence

    async def get_alerts(
        self,
        metric_id: Optional[str] = None,
        severity: Optional[AlertSeverity] = None,
        unacknowledged_only: bool = False,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get capacity alerts with optional filtering.

        Args:
            metric_id: Filter by metric ID.
            severity: Filter by alert severity.
            unacknowledged_only: Only return unacknowledged alerts.
            limit: Maximum number of alerts to return.

        Returns:
            List of alert dictionaries.
        """
        alerts = []

        for alert in reversed(self._alerts):
            if metric_id and alert.metric_id != metric_id:
                continue
            if severity and alert.severity != severity:
                continue
            if unacknowledged_only and alert.acknowledged:
                continue

            alerts.append(alert.to_dict())

            if len(alerts) >= limit:
                break

        return alerts

    async def acknowledge_alert(
        self,
        alert_id: str,
        user: str,
    ) -> bool:
        """Acknowledge an alert.

        Args:
            alert_id: Alert identifier.
            user: User acknowledging the alert.

        Returns:
            True if alert was acknowledged, False if not found.
        """
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.acknowledge(user)
                logger.info(f"Alert {alert_id} acknowledged by {user}")
                return True
        return False

    def get_all_metrics(self) -> List[Dict[str, Any]]:
        """Get all tracked capacity metrics.

        Returns:
            List of metric dictionaries.
        """
        return [m.to_dict() for m in self._metrics.values()]

    async def export_for_bss(
        self,
        include_recommendations: bool = True,
    ) -> Dict[str, Any]:
        """Export capacity data for BSS integration.

        Args:
            include_recommendations: Include procurement recommendations.

        Returns:
            BSS-formatted capacity data.
        """
        export_data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics": [m.to_dict() for m in self._metrics.values()],
            "utilization_summary": await self.get_utilization(),
        }

        if include_recommendations:
            export_data["recommendations"] = [
                r.to_dict() for r in self._recommendations
            ]

        # Send to BSS if configured
        if self._bss_client and hasattr(self._bss_client, "receive_capacity_data"):
            try:
                await self._bss_client.receive_capacity_data(export_data)
                logger.info("Exported capacity data to BSS")
            except Exception as e:
                logger.error(f"Failed to export to BSS: {e}")

        return export_data

    async def _persist_metrics(self, metrics: List[CapacityMetric]) -> None:
        """Persist metrics to database.

        Args:
            metrics: Metrics to persist.
        """
        if self._db_pool is None:
            return

        try:
            logger.debug(f"Persisting {len(metrics)} capacity metrics")
        except Exception as e:
            logger.error(f"Failed to persist metrics: {e}")

    async def run_capacity_audit(self) -> Dict[str, Any]:
        """Run comprehensive capacity audit.

        Returns:
            Audit report dictionary.
        """
        report = {
            "audit_timestamp": datetime.now(timezone.utc).isoformat(),
            "metrics_tracked": len(self._metrics),
            "alerts_summary": {
                "total": len(self._alerts),
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
            "utilization_summary": {
                "healthy": 0,
                "warning": 0,
                "critical": 0,
                "exceeded": 0,
            },
            "by_capacity_type": {},
            "recommendations_pending": len(self._recommendations),
            "issues": [],
        }

        # Summarize by utilization status
        for metric in self._metrics.values():
            status = metric.utilization_status
            report["utilization_summary"][status] += 1

            # Group by capacity type
            type_name = str(metric.capacity_type)
            if type_name not in report["by_capacity_type"]:
                report["by_capacity_type"][type_name] = {
                    "count": 0,
                    "total_capacity": 0.0,
                    "total_used": 0.0,
                }
            report["by_capacity_type"][type_name]["count"] += 1
            report["by_capacity_type"][type_name]["total_capacity"] += metric.total_capacity
            report["by_capacity_type"][type_name]["total_used"] += metric.used_capacity

        # Summarize alerts
        for alert in self._alerts:
            if not alert.acknowledged:
                report["alerts_summary"][alert.severity.name.lower()] += 1

        # Identify issues
        for metric in self._metrics.values():
            if metric.utilization_status in ("critical", "exceeded"):
                report["issues"].append({
                    "metric_id": metric.metric_id,
                    "type": "high_utilization",
                    "severity": "critical" if metric.utilization_status == "exceeded" else "high",
                    "message": (
                        f"{metric.name}: {metric.utilization_percentage:.1f}% utilized "
                        f"({metric.network_element_id})"
                    ),
                })

        return report

    async def get_forecast(
        self,
        metric_id: str,
        days_ahead: int = 90,
    ) -> Optional[Dict[str, Any]]:
        """Generate capacity forecast for a specific metric.

        Args:
            metric_id: Metric identifier.
            days_ahead: Number of days to forecast.

        Returns:
            Forecast data or None if insufficient history.
        """
        trends = await self.get_trends(metric_id)
        if not trends:
            return None

        trend = trends[0]
        metric = self._metrics.get(metric_id)
        if metric is None:
            return None

        if trend.direction != TrendDirection.INCREASING:
            return {
                "metric_id": metric_id,
                "forecast_type": "stable",
                "message": "Capacity is stable, no growth trend detected",
                "current_utilization": metric.utilization_percentage,
            }

        # Project future utilization
        daily_growth = trend.slope
        forecast_points = []

        for days in range(0, days_ahead + 1, 7):  # Weekly points
            projected_utilization = metric.utilization_percentage + (daily_growth * days)
            projected_utilization = min(100, projected_utilization)

            forecast_points.append({
                "date": (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%d"),
                "projected_utilization": round(projected_utilization, 2),
                "days_ahead": days,
            })

        # Calculate when thresholds will be crossed
        threshold_crossings = {}
        for threshold_name, threshold_value in self.utilization_thresholds.items():
            if daily_growth > 0:
                days_to_threshold = (
                    threshold_value - metric.utilization_percentage
                ) / daily_growth
                if days_to_threshold > 0:
                    threshold_crossings[threshold_name] = {
                        "days": int(days_to_threshold),
                        "date": (
                            datetime.now(timezone.utc) + timedelta(days=days_to_threshold)
                        ).strftime("%Y-%m-%d"),
                    }

        return {
            "metric_id": metric_id,
            "forecast_type": "growth",
            "current_utilization": round(metric.utilization_percentage, 2),
            "daily_growth_rate": round(daily_growth, 4),
            "confidence": round(trend.confidence, 2),
            "forecast_points": forecast_points,
            "threshold_crossings": threshold_crossings,
            "exhaustion_date": (
                trend.forecast_date.strftime("%Y-%m-%d") if trend.forecast_date else None
            ),
        }
