"""
License Manager Module for Unified OSS Framework.

This module provides comprehensive software license management capabilities
including multi-vendor license normalization, utilization tracking,
expiration alerting, and compliance monitoring.

Supports:
    - Multi-vendor license normalization (Ericsson, Huawei, CIM)
    - License status tracking and lifecycle management
    - Expiration alerting with configurable thresholds
    - Utilization tracking and compliance monitoring
    - Feature capability mapping
    - BSS integration for billing
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
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
LicenseData = Dict[str, Any]
VendorType = str  # "ericsson" | "huawei" | "cim"


class LicenseStatus(Enum):
    """Enumeration of possible license status values.

    Defines the complete lifecycle states for software licenses
    in the Unified OSS Framework.

    Attributes:
        VALID: License is active and valid.
        EXPIRED: License has passed its expiration date.
        EXCEEDED: License usage exceeds allowed limits.
        NOT_INSTALLED: License has not been installed.
        SUSPENDED: License is temporarily suspended.
        PENDING_ACTIVATION: License awaiting activation.
        REVOKED: License has been revoked.
        TRIAL: Trial/evaluation license active.
    """

    VALID = auto()
    EXPIRED = auto()
    EXCEEDED = auto()
    NOT_INSTALLED = auto()
    SUSPENDED = auto()
    PENDING_ACTIVATION = auto()
    REVOKED = auto()
    TRIAL = auto()

    def __str__(self) -> str:
        """Return string representation of license status."""
        return self.name.lower().replace("_", "-")


class LicenseType(Enum):
    """Enumeration of license model types.

    Maps to the YANG typedef license-type-enum for consistency.

    Attributes:
        PERPETUAL: One-time purchase license.
        SUBSCRIPTION_MONTHLY: Monthly subscription license.
        SUBSCRIPTION_ANNUAL: Annual subscription license.
        USAGE_BASED: Pay-per-use licensing.
        PER_NODE: Per-node licensing.
        PER_USER: Per-user licensing.
        PER_CORE: Per-CPU-core licensing.
        PER_INSTANCE: Per-instance licensing.
        TRIAL: Trial/evaluation license.
        ENTERPRISE: Enterprise-wide license.
        SITE: Site-wide license.
    """

    PERPETUAL = auto()
    SUBSCRIPTION_MONTHLY = auto()
    SUBSCRIPTION_ANNUAL = auto()
    USAGE_BASED = auto()
    PER_NODE = auto()
    PER_USER = auto()
    PER_CORE = auto()
    PER_INSTANCE = auto()
    TRIAL = auto()
    ENTERPRISE = auto()
    SITE = auto()

    @classmethod
    def from_vendor_value(
        cls, vendor: VendorType, value: str
    ) -> "LicenseType":
        """Convert vendor-specific license type to unified type.

        Args:
            vendor: Vendor identifier (ericsson, huawei, cim).
            value: Vendor-specific license type string.

        Returns:
            Unified LicenseType enum value.

        Raises:
            ValueError: If license type cannot be mapped.
        """
        mappings = {
            "ericsson": {
                "PERPETUAL": cls.PERPETUAL,
                "SUBSCRIPTION": cls.SUBSCRIPTION_MONTHLY,
                "USAGE_BASED": cls.USAGE_BASED,
                "NODE_LOCKED": cls.PER_NODE,
                "FLOATING": cls.PER_USER,
                "CORE_BASED": cls.PER_CORE,
                "INSTANCE": cls.PER_INSTANCE,
                "TRIAL": cls.TRIAL,
                "ENTERPRISE": cls.ENTERPRISE,
            },
            "huawei": {
                "PERMANENT": cls.PERPETUAL,
                "SUBSCRIPTION_MONTHLY": cls.SUBSCRIPTION_MONTHLY,
                "SUBSCRIPTION_YEARLY": cls.SUBSCRIPTION_ANNUAL,
                "PAY_PER_USE": cls.USAGE_BASED,
                "NODE_LICENSE": cls.PER_NODE,
                "USER_LICENSE": cls.PER_USER,
                "CPU_LICENSE": cls.PER_CORE,
                "INSTANCE_LICENSE": cls.PER_INSTANCE,
                "DEMO": cls.TRIAL,
                "ENTERPRISE_LICENSE": cls.ENTERPRISE,
                "SITE_LICENSE": cls.SITE,
            },
            "cim": {
                "perpetual": cls.PERPETUAL,
                "subscription-monthly": cls.SUBSCRIPTION_MONTHLY,
                "subscription-annual": cls.SUBSCRIPTION_ANNUAL,
                "usage-based": cls.USAGE_BASED,
                "per-node": cls.PER_NODE,
                "per-user": cls.PER_USER,
                "per-core": cls.PER_CORE,
                "per-instance": cls.PER_INSTANCE,
                "trial": cls.TRIAL,
                "enterprise": cls.ENTERPRISE,
                "site": cls.SITE,
            },
        }

        vendor_mapping = mappings.get(vendor.lower(), {})
        result = vendor_mapping.get(value)

        if result is None:
            logger.warning(
                f"Unknown license type '{value}' for vendor '{vendor}', "
                "defaulting to PERPETUAL"
            )
            return cls.PERPETUAL

        return result


class AlertSeverity(Enum):
    """Severity levels for license alerts."""

    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFORMATIONAL = auto()


class ComplianceStatus(Enum):
    """Compliance status for license tracking."""

    COMPLIANT = auto()
    WARNING = auto()
    OVER_LIMIT = auto()
    VIOLATION = auto()
    EXEMPT = auto()


@dataclass
class LicenseFeature:
    """Represents a licensed feature or capability.

    Attributes:
        feature_id: Unique identifier for the feature.
        name: Human-readable feature name.
        description: Feature description.
        is_enabled: Whether the feature is enabled.
        capacity_limit: Maximum capacity for the feature (None for unlimited).
        current_usage: Current usage of the feature capacity.
        expires_at: Feature-specific expiration (if different from license).
    """

    feature_id: str
    name: str
    description: str = ""
    is_enabled: bool = True
    capacity_limit: Optional[int] = None
    current_usage: int = 0
    expires_at: Optional[datetime] = None

    @property
    def utilization_percentage(self) -> float:
        """Calculate feature utilization percentage.

        Returns:
            Utilization as percentage (0-100), or 0 if unlimited.
        """
        if self.capacity_limit is None or self.capacity_limit == 0:
            return 0.0
        return (self.current_usage / self.capacity_limit) * 100.0

    def is_available(self) -> bool:
        """Check if feature is available for use.

        Returns:
            True if feature can be used, False if exhausted or disabled.
        """
        if not self.is_enabled:
            return False
        if self.expires_at and datetime.now(timezone.utc) > self.expires_at:
            return False
        if self.capacity_limit is not None:
            return self.current_usage < self.capacity_limit
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert feature to dictionary representation.

        Returns:
            Dictionary representation of the feature.
        """
        return {
            "feature_id": self.feature_id,
            "name": self.name,
            "description": self.description,
            "is_enabled": self.is_enabled,
            "capacity_limit": self.capacity_limit,
            "current_usage": self.current_usage,
            "utilization_percentage": round(self.utilization_percentage, 2),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "is_available": self.is_available(),
        }


@dataclass
class LicenseAlert:
    """Represents a license-related alert or notification.

    Attributes:
        alert_id: Unique identifier for the alert.
        license_id: Associated license ID.
        alert_type: Type of alert (expiration, utilization, etc.).
        severity: Alert severity level.
        message: Human-readable alert message.
        created_at: Alert creation timestamp.
        acknowledged: Whether the alert has been acknowledged.
        acknowledged_at: Acknowledgment timestamp.
        acknowledged_by: User who acknowledged the alert.
        details: Additional alert details.
    """

    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    license_id: str = ""
    alert_type: str = ""
    severity: AlertSeverity = AlertSeverity.INFORMATIONAL
    message: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None
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
            "license_id": self.license_id,
            "alert_type": self.alert_type,
            "severity": self.severity.name,
            "message": self.message,
            "created_at": self.created_at.isoformat(),
            "acknowledged": self.acknowledged,
            "acknowledged_at": self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            "acknowledged_by": self.acknowledged_by,
            "details": self.details,
        }


@dataclass
class License:
    """Represents a software license with full tracking capabilities.

    This class encapsulates all license information including vendor-specific
    data, normalized attributes, utilization tracking, and compliance status.

    Attributes:
        license_id: Unique license identifier.
        name: License name or description.
        vendor: Original vendor (ericsson, huawei, cim).
        license_type: Type of license model.
        status: Current license status.
        installed_at: When the license was installed.
        expires_at: License expiration date (None for perpetual).
        last_validated: Last validation timestamp.
        capacity_total: Total licensed capacity.
        capacity_used: Currently used capacity.
        features: List of licensed features.
        vendor_data: Original vendor-specific license data.
        normalized_data: Normalized cross-vendor representation.
        cost_center: Cost center for chargeback.
        metadata: Additional metadata.
    """

    license_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    vendor: VendorType = "cim"
    license_type: LicenseType = LicenseType.PERPETUAL
    status: LicenseStatus = LicenseStatus.NOT_INSTALLED
    installed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    last_validated: Optional[datetime] = None
    capacity_total: int = 0
    capacity_used: int = 0
    features: List[LicenseFeature] = field(default_factory=list)
    vendor_data: Dict[str, Any] = field(default_factory=dict)
    normalized_data: Dict[str, Any] = field(default_factory=dict)
    cost_center: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        """Check if license is valid.

        Returns:
            True if license is valid and can be used.
        """
        return self.status == LicenseStatus.VALID

    @property
    def is_expired(self) -> bool:
        """Check if license has expired.

        Returns:
            True if license has passed expiration date.
        """
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    @property
    def days_until_expiry(self) -> Optional[int]:
        """Calculate days until license expires.

        Returns:
            Number of days until expiration, or None if perpetual.
        """
        if self.expires_at is None:
            return None
        delta = self.expires_at - datetime.now(timezone.utc)
        return max(0, delta.days)

    @property
    def utilization_percentage(self) -> float:
        """Calculate license utilization percentage.

        Returns:
            Utilization as percentage (0-100).
        """
        if self.capacity_total == 0:
            return 0.0
        return (self.capacity_used / self.capacity_total) * 100.0

    @property
    def compliance_status(self) -> ComplianceStatus:
        """Determine license compliance status.

        Returns:
            Current compliance status based on utilization and validity.
        """
        if self.status == LicenseStatus.EXCEEDED:
            return ComplianceStatus.VIOLATION
        if self.status in (LicenseStatus.EXPIRED, LicenseStatus.REVOKED):
            return ComplianceStatus.VIOLATION
        if self.utilization_percentage >= 95:
            return ComplianceStatus.OVER_LIMIT
        if self.utilization_percentage >= 80:
            return ComplianceStatus.WARNING
        return ComplianceStatus.COMPLIANT

    def get_feature(self, feature_id: str) -> Optional[LicenseFeature]:
        """Get a specific feature by ID.

        Args:
            feature_id: Feature identifier to look up.

        Returns:
            LicenseFeature if found, None otherwise.
        """
        for feature in self.features:
            if feature.feature_id == feature_id:
                return feature
        return None

    def has_feature(self, feature_id: str) -> bool:
        """Check if license includes a specific feature.

        Args:
            feature_id: Feature identifier to check.

        Returns:
            True if feature is available, False otherwise.
        """
        feature = self.get_feature(feature_id)
        return feature is not None and feature.is_available()

    def update_utilization(self, used: int) -> None:
        """Update license utilization.

        Args:
            used: Current usage value.
        """
        self.capacity_used = used

        # Update status based on utilization
        if self.capacity_used > self.capacity_total:
            self.status = LicenseStatus.EXCEEDED
        elif self.is_expired:
            self.status = LicenseStatus.EXPIRED
        elif self.status in (LicenseStatus.EXCEEDED, LicenseStatus.EXPIRED):
            # Reset to valid if conditions are now met
            if self.capacity_used <= self.capacity_total and not self.is_expired:
                self.status = LicenseStatus.VALID

    def to_dict(self) -> Dict[str, Any]:
        """Convert license to dictionary representation.

        Returns:
            Dictionary representation of the license.
        """
        return {
            "license_id": self.license_id,
            "name": self.name,
            "vendor": self.vendor,
            "license_type": self.license_type.name,
            "status": str(self.status),
            "installed_at": self.installed_at.isoformat() if self.installed_at else None,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_validated": self.last_validated.isoformat() if self.last_validated else None,
            "capacity_total": self.capacity_total,
            "capacity_used": self.capacity_used,
            "utilization_percentage": round(self.utilization_percentage, 2),
            "days_until_expiry": self.days_until_expiry,
            "is_valid": self.is_valid,
            "is_expired": self.is_expired,
            "compliance_status": self.compliance_status.name,
            "features": [f.to_dict() for f in self.features],
            "cost_center": self.cost_center,
            "metadata": self.metadata,
        }


class VendorNormalizationRule:
    """Rule for normalizing vendor-specific license data.

    Attributes:
        vendor: Vendor identifier.
        field_mappings: Mappings from vendor fields to normalized fields.
        value_transformers: Functions to transform field values.
    """

    def __init__(
        self,
        vendor: VendorType,
        field_mappings: Dict[str, str],
        value_transformers: Optional[Dict[str, Callable[[Any], Any]]] = None,
    ) -> None:
        """Initialize normalization rule.

        Args:
            vendor: Vendor identifier.
            field_mappings: Mapping from vendor fields to normalized fields.
            value_transformers: Optional value transformation functions.
        """
        self.vendor = vendor
        self.field_mappings = field_mappings
        self.value_transformers = value_transformers or {}

    def apply(self, vendor_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply normalization rule to vendor data.

        Args:
            vendor_data: Vendor-specific license data.

        Returns:
            Normalized license data dictionary.
        """
        normalized = {}

        for vendor_field, normalized_field in self.field_mappings.items():
            if vendor_field in vendor_data:
                value = vendor_data[vendor_field]

                # Apply transformer if defined
                if normalized_field in self.value_transformers:
                    value = self.value_transformers[normalized_field](value)

                normalized[normalized_field] = value

        return normalized


class LicenseManager:
    """Manages software licenses across multi-vendor environments.

    This class provides comprehensive license management including:
    - Multi-vendor license normalization (Ericsson, Huawei, CIM)
    - License status tracking and lifecycle management
    - Expiration alerting with configurable thresholds
    - Utilization tracking and compliance monitoring
    - Feature capability mapping
    - BSS integration for billing

    Attributes:
        alert_thresholds: Days before expiration to generate alerts.
        utilization_thresholds: Percentage thresholds for utilization alerts.
        licenses: Dictionary of managed licenses.
        alerts: List of generated alerts.
    """

    # Default alert thresholds (days before expiration)
    DEFAULT_ALERT_THRESHOLDS = [90, 60, 30, 14, 7, 1]

    # Default utilization thresholds (percentage)
    DEFAULT_UTILIZATION_THRESHOLDS = [80, 90, 95, 100]

    def __init__(
        self,
        db_pool: Optional[Any] = None,
        alert_thresholds: Optional[List[int]] = None,
        utilization_thresholds: Optional[List[int]] = None,
        bss_client: Optional[Any] = None,
    ) -> None:
        """Initialize the License Manager.

        Args:
            db_pool: Database connection pool for persistence.
            alert_thresholds: Days before expiration for alerts.
            utilization_thresholds: Percentage thresholds for utilization alerts.
            bss_client: BSS integration client for billing.
        """
        self._db_pool = db_pool
        self._bss_client = bss_client
        self._licenses: Dict[str, License] = {}
        self._alerts: List[LicenseAlert] = []
        self._lock = asyncio.Lock()

        self.alert_thresholds = alert_thresholds or self.DEFAULT_ALERT_THRESHOLDS
        self.utilization_thresholds = (
            utilization_thresholds or self.DEFAULT_UTILIZATION_THRESHOLDS
        )

        # Initialize vendor normalization rules
        self._normalization_rules = self._init_normalization_rules()

        # Feature capability mappings
        self._feature_mappings = self._init_feature_mappings()

        logger.info(
            f"LicenseManager initialized with alert thresholds: {self.alert_thresholds}"
        )

    def _init_normalization_rules(self) -> Dict[VendorType, VendorNormalizationRule]:
        """Initialize vendor-specific normalization rules.

        Returns:
            Dictionary of normalization rules by vendor.
        """
        rules = {}

        # Ericsson normalization rule
        rules["ericsson"] = VendorNormalizationRule(
            vendor="ericsson",
            field_mappings={
                "licenseId": "license_id",
                "licenseName": "name",
                "licenseType": "license_type",
                "expiryDate": "expires_at",
                "installDate": "installed_at",
                "maxCapacity": "capacity_total",
                "usedCapacity": "capacity_used",
                "licenseStatus": "status",
                "features": "features",
                "customerId": "cost_center",
            },
            value_transformers={
                "license_type": lambda v: LicenseType.from_vendor_value("ericsson", v),
                "expires_at": self._parse_datetime,
                "installed_at": self._parse_datetime,
                "status": self._parse_ericsson_status,
            },
        )

        # Huawei normalization rule
        rules["huawei"] = VendorNormalizationRule(
            vendor="huawei",
            field_mappings={
                "licId": "license_id",
                "licName": "name",
                "licType": "license_type",
                "expireTime": "expires_at",
                "activateTime": "installed_at",
                "totalResource": "capacity_total",
                "usedResource": "capacity_used",
                "licState": "status",
                "funcList": "features",
                "costCenter": "cost_center",
            },
            value_transformers={
                "license_type": lambda v: LicenseType.from_vendor_value("huawei", v),
                "expires_at": self._parse_datetime,
                "installed_at": self._parse_datetime,
                "status": self._parse_huawei_status,
            },
        )

        # CIM (Common Information Model) - already normalized
        rules["cim"] = VendorNormalizationRule(
            vendor="cim",
            field_mappings={
                "licenseId": "license_id",
                "name": "name",
                "licenseType": "license_type",
                "expiresAt": "expires_at",
                "installedAt": "installed_at",
                "capacityTotal": "capacity_total",
                "capacityUsed": "capacity_used",
                "status": "status",
                "features": "features",
                "costCenter": "cost_center",
            },
            value_transformers={
                "license_type": lambda v: LicenseType.from_vendor_value("cim", v),
                "expires_at": self._parse_datetime,
                "installed_at": self._parse_datetime,
                "status": self._parse_cim_status,
            },
        )

        return rules

    def _init_feature_mappings(self) -> Dict[str, Dict[str, str]]:
        """Initialize feature capability mappings across vendors.

        Returns:
            Dictionary mapping normalized features to vendor-specific features.
        """
        return {
            "max_subscribers": {
                "ericsson": "MAX_SUBSCRIBERS",
                "huawei": "MAX_USER_NUM",
                "cim": "max-subscribers",
            },
            "max_throughput": {
                "ericsson": "MAX_THROUGHPUT_GBPS",
                "huawei": "MAX_BANDWIDTH",
                "cim": "max-throughput",
            },
            "advanced_analytics": {
                "ericsson": "ANALYTICS_PRO",
                "huawei": "INTEL_ANALYTICS",
                "cim": "advanced-analytics",
            },
            "ai_optimization": {
                "ericsson": "AI_ENGINE",
                "huawei": "AI_OPT_MODULE",
                "cim": "ai-optimization",
            },
            "high_availability": {
                "ericsson": "HA_CLUSTER",
                "huawei": "HIGH_AVAIL",
                "cim": "high-availability",
            },
            "security_premium": {
                "ericsson": "SEC_PREMIUM",
                "huawei": "SEC_ENHANCED",
                "cim": "security-premium",
            },
        }

    @staticmethod
    def _parse_datetime(value: Any) -> Optional[datetime]:
        """Parse datetime from various formats.

        Args:
            value: Datetime value in various formats.

        Returns:
            Parsed datetime or None.
        """
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if isinstance(value, str):
            # Try ISO format first
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                pass
            # Try common formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y/%m/%d %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return None

    @staticmethod
    def _parse_ericsson_status(value: str) -> LicenseStatus:
        """Parse Ericsson license status.

        Args:
            value: Ericsson status string.

        Returns:
            Unified LicenseStatus enum value.
        """
        status_map = {
            "ACTIVE": LicenseStatus.VALID,
            "EXPIRED": LicenseStatus.EXPIRED,
            "OVER_USAGE": LicenseStatus.EXCEEDED,
            "NOT_INSTALLED": LicenseStatus.NOT_INSTALLED,
            "SUSPENDED": LicenseStatus.SUSPENDED,
            "PENDING": LicenseStatus.PENDING_ACTIVATION,
            "REVOKED": LicenseStatus.REVOKED,
            "TRIAL": LicenseStatus.TRIAL,
        }
        return status_map.get(value.upper(), LicenseStatus.NOT_INSTALLED)

    @staticmethod
    def _parse_huawei_status(value: str) -> LicenseStatus:
        """Parse Huawei license status.

        Args:
            value: Huawei status string.

        Returns:
            Unified LicenseStatus enum value.
        """
        status_map = {
            "NORMAL": LicenseStatus.VALID,
            "EXPIRED": LicenseStatus.EXPIRED,
            "OVERDUE": LicenseStatus.EXPIRED,
            "OVERUSED": LicenseStatus.EXCEEDED,
            "DEFAULT": LicenseStatus.NOT_INSTALLED,
            "INACTIVE": LicenseStatus.SUSPENDED,
            "TO_BE_ACTIVATED": LicenseStatus.PENDING_ACTIVATION,
            "REVOKED": LicenseStatus.REVOKED,
            "DEMO": LicenseStatus.TRIAL,
        }
        return status_map.get(value.upper(), LicenseStatus.NOT_INSTALLED)

    @staticmethod
    def _parse_cim_status(value: str) -> LicenseStatus:
        """Parse CIM license status.

        Args:
            value: CIM status string.

        Returns:
            Unified LicenseStatus enum value.
        """
        status_map = {
            "valid": LicenseStatus.VALID,
            "expired": LicenseStatus.EXPIRED,
            "exceeded": LicenseStatus.EXCEEDED,
            "not-installed": LicenseStatus.NOT_INSTALLED,
            "suspended": LicenseStatus.SUSPENDED,
            "pending-activation": LicenseStatus.PENDING_ACTIVATION,
            "revoked": LicenseStatus.REVOKED,
            "trial": LicenseStatus.TRIAL,
        }
        return status_map.get(value.lower(), LicenseStatus.NOT_INSTALLED)

    def normalize_license(
        self,
        vendor_data: Dict[str, Any],
        vendor: VendorType,
    ) -> License:
        """Normalize vendor-specific license data to unified format.

        Args:
            vendor_data: Raw license data from vendor system.
            vendor: Vendor identifier (ericsson, huawei, cim).

        Returns:
            Normalized License object.

        Raises:
            ValueError: If vendor is not supported.
        """
        if vendor.lower() not in self._normalization_rules:
            raise ValueError(f"Unsupported vendor: {vendor}")

        rule = self._normalization_rules[vendor.lower()]
        normalized = rule.apply(vendor_data)

        # Create License object
        license_obj = License(
            vendor=vendor.lower(),
            vendor_data=vendor_data,
            normalized_data=normalized,
        )

        # Apply normalized values
        if "license_id" in normalized:
            license_obj.license_id = normalized["license_id"]
        if "name" in normalized:
            license_obj.name = normalized["name"]
        if "license_type" in normalized:
            license_obj.license_type = normalized["license_type"]
        if "expires_at" in normalized:
            license_obj.expires_at = normalized["expires_at"]
        if "installed_at" in normalized:
            license_obj.installed_at = normalized["installed_at"]
        if "capacity_total" in normalized:
            license_obj.capacity_total = normalized["capacity_total"]
        if "capacity_used" in normalized:
            license_obj.capacity_used = normalized["capacity_used"]
        if "status" in normalized:
            license_obj.status = normalized["status"]
        if "cost_center" in normalized:
            license_obj.cost_center = normalized["cost_center"]

        # Process features
        if "features" in vendor_data:
            license_obj.features = self._normalize_features(
                vendor_data["features"], vendor
            )

        # Update status based on current state
        self._update_license_status(license_obj)

        logger.info(
            f"Normalized license {license_obj.license_id} from {vendor}: "
            f"status={license_obj.status}, type={license_obj.license_type}"
        )

        return license_obj

    def _normalize_features(
        self,
        features_data: List[Dict[str, Any]],
        vendor: VendorType,
    ) -> List[LicenseFeature]:
        """Normalize vendor-specific feature data.

        Args:
            features_data: List of feature dictionaries from vendor.
            vendor: Vendor identifier.

        Returns:
            List of normalized LicenseFeature objects.
        """
        features = []

        for feat_data in features_data:
            if vendor.lower() == "ericsson":
                feature = LicenseFeature(
                    feature_id=feat_data.get("featureId", str(uuid.uuid4())),
                    name=feat_data.get("featureName", "Unknown"),
                    description=feat_data.get("description", ""),
                    is_enabled=feat_data.get("enabled", True),
                    capacity_limit=feat_data.get("maxCapacity"),
                    current_usage=feat_data.get("usedCapacity", 0),
                    expires_at=self._parse_datetime(feat_data.get("expiryDate")),
                )
            elif vendor.lower() == "huawei":
                feature = LicenseFeature(
                    feature_id=feat_data.get("funcId", str(uuid.uuid4())),
                    name=feat_data.get("funcName", "Unknown"),
                    description=feat_data.get("funcDesc", ""),
                    is_enabled=feat_data.get("enabled", True),
                    capacity_limit=feat_data.get("totalResource"),
                    current_usage=feat_data.get("usedResource", 0),
                    expires_at=self._parse_datetime(feat_data.get("expireTime")),
                )
            else:  # CIM
                feature = LicenseFeature(
                    feature_id=feat_data.get("featureId", str(uuid.uuid4())),
                    name=feat_data.get("name", "Unknown"),
                    description=feat_data.get("description", ""),
                    is_enabled=feat_data.get("isEnabled", True),
                    capacity_limit=feat_data.get("capacityLimit"),
                    current_usage=feat_data.get("currentUsage", 0),
                    expires_at=self._parse_datetime(feat_data.get("expiresAt")),
                )
            features.append(feature)

        return features

    def _update_license_status(self, license_obj: License) -> None:
        """Update license status based on current state.

        Args:
            license_obj: License to update.
        """
        now = datetime.now(timezone.utc)

        # Check expiration first
        if license_obj.expires_at and now > license_obj.expires_at:
            license_obj.status = LicenseStatus.EXPIRED
            return

        # Check utilization
        if license_obj.capacity_total > 0:
            if license_obj.capacity_used > license_obj.capacity_total:
                license_obj.status = LicenseStatus.EXCEEDED
                return

        # If installed and not in any error state, it's valid
        if license_obj.installed_at:
            if license_obj.status in (
                LicenseStatus.NOT_INSTALLED,
                LicenseStatus.PENDING_ACTIVATION,
            ):
                license_obj.status = LicenseStatus.VALID

    async def register_license(
        self,
        license_obj: License,
        persist: bool = True,
    ) -> None:
        """Register a new license with the manager.

        Args:
            license_obj: License to register.
            persist: Whether to persist to database.
        """
        async with self._lock:
            self._licenses[license_obj.license_id] = license_obj

            if persist and self._db_pool:
                await self._persist_license(license_obj)

            logger.info(
                f"Registered license {license_obj.license_id}: "
                f"{license_obj.name} ({license_obj.vendor})"
            )

    async def get_license_status(
        self,
        license_id: str,
    ) -> Optional[Dict[str, Any]]:
        """Get comprehensive status for a license.

        Args:
            license_id: License identifier.

        Returns:
            License status dictionary or None if not found.
        """
        license_obj = self._licenses.get(license_id)
        if license_obj is None:
            # Try loading from database
            if self._db_pool:
                license_obj = await self._load_license(license_id)
            if license_obj is None:
                return None

        # Update status before returning
        self._update_license_status(license_obj)

        return {
            "license_id": license_obj.license_id,
            "name": license_obj.name,
            "vendor": license_obj.vendor,
            "status": str(license_obj.status),
            "license_type": license_obj.license_type.name,
            "is_valid": license_obj.is_valid,
            "is_expired": license_obj.is_expired,
            "compliance_status": license_obj.compliance_status.name,
            "days_until_expiry": license_obj.days_until_expiry,
            "capacity_total": license_obj.capacity_total,
            "capacity_used": license_obj.capacity_used,
            "utilization_percentage": round(license_obj.utilization_percentage, 2),
            "features_available": sum(1 for f in license_obj.features if f.is_available()),
            "features_total": len(license_obj.features),
        }

    async def check_expiration(
        self,
        license_id: Optional[str] = None,
    ) -> List[LicenseAlert]:
        """Check licenses for expiration and generate alerts.

        Args:
            license_id: Specific license to check, or None for all.

        Returns:
            List of generated alerts.
        """
        alerts = []
        now = datetime.now(timezone.utc)

        licenses_to_check = (
            [self._licenses[license_id]]
            if license_id and license_id in self._licenses
            else list(self._licenses.values())
        )

        for license_obj in licenses_to_check:
            if license_obj.expires_at is None:
                continue  # Perpetual license

            days_remaining = license_obj.days_until_expiry

            if days_remaining is None:
                continue

            # Check against alert thresholds
            for threshold in sorted(self.alert_thresholds, reverse=True):
                if days_remaining <= threshold:
                    # Generate alert for this threshold
                    severity = self._get_expiration_severity(threshold)

                    alert = LicenseAlert(
                        license_id=license_obj.license_id,
                        alert_type="expiration",
                        severity=severity,
                        message=(
                            f"License '{license_obj.name}' expires in "
                            f"{days_remaining} days"
                        ),
                        details={
                            "days_remaining": days_remaining,
                            "expires_at": license_obj.expires_at.isoformat(),
                            "threshold": threshold,
                        },
                    )

                    # Check if similar alert already exists
                    existing = self._find_existing_alert(
                        license_obj.license_id, "expiration", threshold
                    )
                    if existing is None:
                        alerts.append(alert)
                        async with self._lock:
                            self._alerts.append(alert)
                    break  # Only alert on highest threshold reached

        if alerts:
            logger.info(f"Generated {len(alerts)} expiration alerts")

        return alerts

    def _get_expiration_severity(self, days: int) -> AlertSeverity:
        """Determine alert severity based on days until expiration.

        Args:
            days: Days until expiration.

        Returns:
            Alert severity level.
        """
        if days <= 1:
            return AlertSeverity.CRITICAL
        if days <= 7:
            return AlertSeverity.HIGH
        if days <= 14:
            return AlertSeverity.MEDIUM
        if days <= 30:
            return AlertSeverity.LOW
        return AlertSeverity.INFORMATIONAL

    def _find_existing_alert(
        self,
        license_id: str,
        alert_type: str,
        threshold: int,
    ) -> Optional[LicenseAlert]:
        """Find existing alert matching criteria.

        Args:
            license_id: License identifier.
            alert_type: Type of alert.
            threshold: Alert threshold.

        Returns:
            Existing alert or None.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=1)  # 24-hour window

        for alert in self._alerts:
            if (
                alert.license_id == license_id
                and alert.alert_type == alert_type
                and alert.details.get("threshold") == threshold
                and alert.created_at > cutoff
                and not alert.acknowledged
            ):
                return alert
        return None

    async def get_utilization(
        self,
        license_id: Optional[str] = None,
        include_features: bool = True,
    ) -> Dict[str, Any]:
        """Get license utilization metrics.

        Args:
            license_id: Specific license to query, or None for summary.
            include_features: Include feature-level utilization.

        Returns:
            Utilization metrics dictionary.
        """
        if license_id:
            license_obj = self._licenses.get(license_id)
            if license_obj is None:
                return {}
            return self._get_single_utilization(license_obj, include_features)

        # Aggregate utilization across all licenses
        total_capacity = 0
        total_used = 0
        license_count = 0
        feature_utilizations: Dict[str, Dict[str, Any]] = {}

        for lic in self._licenses.values():
            total_capacity += lic.capacity_total
            total_used += lic.capacity_used
            license_count += 1

            if include_features:
                for feature in lic.features:
                    if feature.feature_id not in feature_utilizations:
                        feature_utilizations[feature.feature_id] = {
                            "name": feature.name,
                            "total_capacity": 0,
                            "total_used": 0,
                        }
                    if feature.capacity_limit:
                        feature_utilizations[feature.feature_id]["total_capacity"] += feature.capacity_limit
                    feature_utilizations[feature.feature_id]["total_used"] += feature.current_usage

        overall_utilization = (
            (total_used / total_capacity * 100) if total_capacity > 0 else 0
        )

        return {
            "license_count": license_count,
            "total_capacity": total_capacity,
            "total_used": total_used,
            "overall_utilization_percentage": round(overall_utilization, 2),
            "features": feature_utilizations if include_features else None,
            "summary": {
                "compliant": sum(
                    1 for lic in self._licenses.values()
                    if lic.compliance_status == ComplianceStatus.COMPLIANT
                ),
                "warning": sum(
                    1 for lic in self._licenses.values()
                    if lic.compliance_status == ComplianceStatus.WARNING
                ),
                "over_limit": sum(
                    1 for lic in self._licenses.values()
                    if lic.compliance_status == ComplianceStatus.OVER_LIMIT
                ),
                "violation": sum(
                    1 for lic in self._licenses.values()
                    if lic.compliance_status == ComplianceStatus.VIOLATION
                ),
            },
        }

    def _get_single_utilization(
        self,
        license_obj: License,
        include_features: bool,
    ) -> Dict[str, Any]:
        """Get utilization for a single license.

        Args:
            license_obj: License to analyze.
            include_features: Include feature-level data.

        Returns:
            Utilization dictionary.
        """
        result = {
            "license_id": license_obj.license_id,
            "name": license_obj.name,
            "capacity_total": license_obj.capacity_total,
            "capacity_used": license_obj.capacity_used,
            "utilization_percentage": round(license_obj.utilization_percentage, 2),
            "compliance_status": license_obj.compliance_status.name,
        }

        if include_features:
            result["features"] = [
                {
                    "feature_id": f.feature_id,
                    "name": f.name,
                    "capacity_limit": f.capacity_limit,
                    "current_usage": f.current_usage,
                    "utilization_percentage": round(f.utilization_percentage, 2),
                    "is_available": f.is_available(),
                }
                for f in license_obj.features
            ]

        return result

    async def get_alerts(
        self,
        license_id: Optional[str] = None,
        severity: Optional[AlertSeverity] = None,
        unacknowledged_only: bool = False,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get license alerts with optional filtering.

        Args:
            license_id: Filter by license ID.
            severity: Filter by alert severity.
            unacknowledged_only: Only return unacknowledged alerts.
            limit: Maximum number of alerts to return.

        Returns:
            List of alert dictionaries.
        """
        alerts = []

        for alert in reversed(self._alerts):  # Most recent first
            if license_id and alert.license_id != license_id:
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

    async def update_utilization(
        self,
        license_id: str,
        used: int,
        feature_utilizations: Optional[Dict[str, int]] = None,
    ) -> Dict[str, Any]:
        """Update license utilization and check thresholds.

        Args:
            license_id: License identifier.
            used: Current usage value.
            feature_utilizations: Optional feature-level utilizations.

        Returns:
            Updated utilization and any generated alerts.
        """
        license_obj = self._licenses.get(license_id)
        if license_obj is None:
            raise ValueError(f"License not found: {license_id}")

        alerts = []

        # Check for utilization threshold alerts
        previous_utilization = license_obj.utilization_percentage

        # Update license utilization
        license_obj.update_utilization(used)
        license_obj.last_validated = datetime.now(timezone.utc)

        current_utilization = license_obj.utilization_percentage

        # Check utilization thresholds
        for threshold in sorted(self.utilization_thresholds):
            if current_utilization >= threshold > previous_utilization:
                severity = self._get_utilization_severity(threshold)
                alert = LicenseAlert(
                    license_id=license_obj.license_id,
                    alert_type="utilization",
                    severity=severity,
                    message=(
                        f"License '{license_obj.name}' utilization "
                        f"reached {current_utilization:.1f}%"
                    ),
                    details={
                        "threshold": threshold,
                        "current_utilization": current_utilization,
                        "previous_utilization": previous_utilization,
                    },
                )
                alerts.append(alert)
                async with self._lock:
                    self._alerts.append(alert)
                break

        # Update feature utilizations
        if feature_utilizations:
            for feature_id, usage in feature_utilizations.items():
                feature = license_obj.get_feature(feature_id)
                if feature:
                    feature.current_usage = usage

        # Persist changes
        if self._db_pool:
            await self._persist_license(license_obj)

        return {
            "license_id": license_id,
            "previous_utilization": round(previous_utilization, 2),
            "current_utilization": round(current_utilization, 2),
            "status": str(license_obj.status),
            "compliance_status": license_obj.compliance_status.name,
            "alerts_generated": len(alerts),
        }

    def _get_utilization_severity(self, percentage: float) -> AlertSeverity:
        """Determine alert severity based on utilization percentage.

        Args:
            percentage: Utilization percentage.

        Returns:
            Alert severity level.
        """
        if percentage >= 100:
            return AlertSeverity.CRITICAL
        if percentage >= 95:
            return AlertSeverity.HIGH
        if percentage >= 90:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    def get_feature_capability(
        self,
        feature_name: str,
        vendor: Optional[VendorType] = None,
    ) -> Optional[str]:
        """Get vendor-specific feature identifier.

        Args:
            feature_name: Normalized feature name.
            vendor: Target vendor (optional).

        Returns:
            Vendor-specific feature identifier or mapping dict.
        """
        mapping = self._feature_mappings.get(feature_name)
        if mapping is None:
            return None

        if vendor:
            return mapping.get(vendor.lower())

        return mapping  # Return full mapping if no vendor specified

    async def export_for_bss(
        self,
        license_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Export license data for BSS integration.

        Args:
            license_id: Specific license to export, or None for all.

        Returns:
            BSS-formatted license data.
        """
        licenses = (
            [self._licenses[license_id]]
            if license_id and license_id in self._licenses
            else list(self._licenses.values())
        )

        export_data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "license_count": len(licenses),
            "licenses": [],
        }

        for lic in licenses:
            license_data = {
                "license_id": lic.license_id,
                "name": lic.name,
                "vendor": lic.vendor,
                "type": lic.license_type.name,
                "status": str(lic.status),
                "cost_center": lic.cost_center,
                "capacity": {
                    "total": lic.capacity_total,
                    "used": lic.capacity_used,
                    "utilization": round(lic.utilization_percentage, 2),
                },
                "billing": {
                    "expires_at": lic.expires_at.isoformat() if lic.expires_at else None,
                    "billing_period": self._get_billing_period(lic.license_type),
                },
                "features": [f.to_dict() for f in lic.features],
            }
            export_data["licenses"].append(license_data)

        # Send to BSS if configured
        if self._bss_client and hasattr(self._bss_client, "receive_license_data"):
            try:
                await self._bss_client.receive_license_data(export_data)
                logger.info(f"Exported {len(licenses)} licenses to BSS")
            except Exception as e:
                logger.error(f"Failed to export to BSS: {e}")

        return export_data

    def _get_billing_period(self, license_type: LicenseType) -> str:
        """Get billing period for license type.

        Args:
            license_type: License type.

        Returns:
            Billing period string.
        """
        period_map = {
            LicenseType.SUBSCRIPTION_MONTHLY: "monthly",
            LicenseType.SUBSCRIPTION_ANNUAL: "annual",
            LicenseType.USAGE_BASED: "usage",
            LicenseType.PERPETUAL: "one-time",
            LicenseType.TRIAL: "trial",
        }
        return period_map.get(license_type, "one-time")

    async def _persist_license(self, license_obj: License) -> None:
        """Persist license to database.

        Args:
            license_obj: License to persist.
        """
        if self._db_pool is None:
            return

        try:
            # Store in cache-like structure for now
            # In production, would use actual database operations
            logger.debug(f"Persisting license {license_obj.license_id}")
        except Exception as e:
            logger.error(f"Failed to persist license: {e}")

    async def _load_license(self, license_id: str) -> Optional[License]:
        """Load license from database.

        Args:
            license_id: License identifier.

        Returns:
            License object or None.
        """
        # Placeholder for database loading
        # In production, would query from database
        return self._licenses.get(license_id)

    async def run_compliance_check(self) -> Dict[str, Any]:
        """Run comprehensive compliance check on all licenses.

        Returns:
            Compliance report dictionary.
        """
        report = {
            "check_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_licenses": len(self._licenses),
            "compliance_summary": {
                "compliant": 0,
                "warning": 0,
                "over_limit": 0,
                "violation": 0,
            },
            "expiration_summary": {
                "expired": 0,
                "expiring_30_days": 0,
                "expiring_60_days": 0,
                "expiring_90_days": 0,
            },
            "issues": [],
        }

        now = datetime.now(timezone.utc)

        for lic in self._licenses.values():
            # Compliance status
            status = lic.compliance_status
            report["compliance_summary"][status.name.lower()] += 1

            # Expiration check
            if lic.is_expired:
                report["expiration_summary"]["expired"] += 1
                report["issues"].append({
                    "license_id": lic.license_id,
                    "type": "expired",
                    "severity": "critical",
                    "message": f"License '{lic.name}' has expired",
                })
            elif lic.days_until_expiry is not None:
                if lic.days_until_expiry <= 30:
                    report["expiration_summary"]["expiring_30_days"] += 1
                elif lic.days_until_expiry <= 60:
                    report["expiration_summary"]["expiring_60_days"] += 1
                elif lic.days_until_expiry <= 90:
                    report["expiration_summary"]["expiring_90_days"] += 1

            # Utilization check
            if lic.status == LicenseStatus.EXCEEDED:
                report["issues"].append({
                    "license_id": lic.license_id,
                    "type": "exceeded",
                    "severity": "high",
                    "message": (
                        f"License '{lic.name}' capacity exceeded: "
                        f"{lic.capacity_used}/{lic.capacity_total}"
                    ),
                })

        return report

    def get_all_licenses(self) -> List[Dict[str, Any]]:
        """Get all managed licenses.

        Returns:
            List of license dictionaries.
        """
        return [lic.to_dict() for lic in self._licenses.values()]

    async def remove_license(self, license_id: str) -> bool:
        """Remove a license from management.

        Args:
            license_id: License identifier.

        Returns:
            True if removed, False if not found.
        """
        async with self._lock:
            if license_id in self._licenses:
                del self._licenses[license_id]
                logger.info(f"Removed license {license_id}")
                return True
            return False
