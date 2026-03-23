"""
Fault Management Module for Unified OSS Framework.

This module provides comprehensive fault management functionality including
alarm management, correlation, and normalization for multi-vendor networks.

Modules:
    alarm_manager: Alarm lifecycle management and notification
    correlation: Alarm correlation and root cause analysis
    normalization: Vendor-specific alarm normalization

Example:
    >>> from unified_oss.fcaps.fault import AlarmManager, AlarmCorrelator, AlarmNormalizer
    >>> manager = AlarmManager()
    >>> normalizer = AlarmNormalizer()
    >>> result = normalizer.normalize_alarm(vendor_data)
"""

from .alarm_manager import (
    Alarm,
    AlarmAlreadyExistsError,
    AlarmCategory,
    AlarmLifecycle,
    AlarmManager,
    AlarmManagerError,
    AlarmNotFoundError,
    AlarmNotifier,
    AlarmSeverity,
    AlarmSource,
    AlarmState,
    AlarmType,
    NotificationCallback,
    NotificationSubscription,
    RootCauseAnalyzer,
    SeverityMapper,
)
from .correlation import (
    AlarmCorrelator,
    AlarmGrouper,
    CorrelatedAlarmGroup,
    CorrelationEngine,
    CorrelationError,
    CorrelationMetrics,
    CorrelationMethod,
    CorrelationPriority,
    CorrelationResult,
    CorrelationRule,
    CorrelationType,
    RootCauseCandidate,
    TopologyInfo,
)
from .normalization import (
    AlarmNormalizer,
    CIMSeverity,
    ITUTMapper,
    NormalizationError,
    NormalizationResult,
    NormalizedAlarm,
    ProbableCauseMapper,
    ResourcePathGenerator,
    SeverityMapper,
    SeverityMappingError,
    TimestampNormalizer,
    TimestampParsingError,
    VendorAlarmParser,
    VendorType,
)

__all__ = [
    # Alarm Manager
    "Alarm",
    "AlarmAlreadyExistsError",
    "AlarmCategory",
    "AlarmLifecycle",
    "AlarmManager",
    "AlarmManagerError",
    "AlarmNotFoundError",
    "AlarmNotifier",
    "AlarmSeverity",
    "AlarmSource",
    "AlarmState",
    "AlarmType",
    "NotificationCallback",
    "NotificationSubscription",
    "RootCauseAnalyzer",
    "SeverityMapper",
    # Correlation
    "AlarmCorrelator",
    "AlarmGrouper",
    "CorrelatedAlarmGroup",
    "CorrelationEngine",
    "CorrelationError",
    "CorrelationMetrics",
    "CorrelationMethod",
    "CorrelationPriority",
    "CorrelationResult",
    "CorrelationRule",
    "CorrelationType",
    "RootCauseCandidate",
    "TopologyInfo",
    # Normalization
    "AlarmNormalizer",
    "CIMSeverity",
    "ITUTMapper",
    "NormalizationError",
    "NormalizedAlarm",
    "NormalizationResult",
    "ProbableCauseMapper",
    "ResourcePathGenerator",
    "SeverityMapper",
    "SeverityMappingError",
    "TimestampNormalizer",
    "TimestampParsingError",
    "VendorAlarmParser",
    "VendorType",
]
