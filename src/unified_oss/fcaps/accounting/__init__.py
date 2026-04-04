"""
Accounting Management Module for Unified OSS Framework.

This module provides comprehensive FCAPS Accounting Management capabilities
including license management, capacity tracking, and multi-vendor normalization.

Key Components:
    - LicenseManager: Software license lifecycle and compliance management
    - CapacityTracker: Network capacity monitoring and forecasting
    - Multi-vendor normalization (Ericsson, Huawei, CIM)

Example:
    >>> from unified_oss.fcaps.accounting import LicenseManager, CapacityTracker
    >>> 
    >>> # Initialize license manager
    >>> license_mgr = LicenseManager()
    >>> 
    >>> # Normalize vendor license data
    >>> license = license_mgr.normalize_license(vendor_data, "ericsson")
    >>> 
    >>> # Track capacity
    >>> tracker = CapacityTracker()
    >>> metrics = await tracker.track_capacity(capacity_data, "huawei")
"""

from .license_manager import (
    AlertSeverity as LicenseAlertSeverity,
    ComplianceStatus,
    License,
    LicenseAlert,
    LicenseFeature,
    LicenseManager,
    LicenseStatus,
    LicenseType,
    VendorNormalizationRule,
)
from .capacity_tracker import (
    AlertSeverity as CapacityAlertSeverity,
    CapacityAlert,
    CapacityMetric,
    CapacityTracker,
    CapacityType,
    CapacityUnit,
    CapacityTrend,
    ProcurementRecommendation,
    RecommendationPriority,
    TrendDirection,
    VendorCapacityMapper,
)

__all__ = [
    # License Management
    "LicenseManager",
    "License",
    "LicenseStatus",
    "LicenseType",
    "LicenseFeature",
    "LicenseAlert",
    "LicenseAlertSeverity",
    "ComplianceStatus",
    "VendorNormalizationRule",
    # Capacity Tracking
    "CapacityTracker",
    "CapacityMetric",
    "CapacityAlert",
    "CapacityType",
    "CapacityUnit",
    "CapacityTrend",
    "TrendDirection",
    "ProcurementRecommendation",
    "RecommendationPriority",
    "VendorCapacityMapper",
    "CapacityAlertSeverity",
]

__version__ = "1.0.0"
