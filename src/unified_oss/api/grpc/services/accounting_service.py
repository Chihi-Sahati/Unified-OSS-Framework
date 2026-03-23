"""
Accounting Service gRPC Implementation for Unified OSS Framework.

This module provides the gRPC service implementation for license and
capacity management operations, integrating with fcaps.accounting module.

Features:
    - License status tracking and validation
    - Capacity utilization monitoring
    - Procurement recommendations
    - Integration with LicenseManager and CapacityTracker

Example:
    >>> from unified_oss.api.grpc.services.accounting_service import AccountingServiceServicer
    >>> from unified_oss.fcaps.accounting.license_manager import LicenseManager
    >>> license_manager = LicenseManager()
    >>> servicer = AccountingServiceServicer(license_manager)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    Any,
    Dict,
    List,
    Optional,
    TYPE_CHECKING,
)

# gRPC imports
try:
    import grpc
    from grpc import aio
    GRPC_AVAILABLE = True
except ImportError:
    GRPC_AVAILABLE = False
    grpc = None
    aio = None

# Import from fcaps module
from unified_oss.fcaps.accounting.license_manager import (
    LicenseManager,
    License,
    LicenseFeature,
    LicenseStatus,
    LicenseType,
    AlertSeverity,
    ComplianceStatus,
)
from unified_oss.fcaps.accounting.capacity_tracker import (
    CapacityTracker,
    CapacityMetric,
    CapacityType,
    CapacityUnit,
    CapacityAlert,
    CapacityTrend,
    TrendDirection,
    ProcurementRecommendation,
    RecommendationPriority,
)

# Configure module logger
logger = logging.getLogger(__name__)


def license_status_to_enum(status: LicenseStatus) -> int:
    """Convert LicenseStatus to proto enum value.
    
    Args:
        status: LicenseStatus enum value.
        
    Returns:
        Integer value for proto LicenseStatus enum.
    """
    mapping = {
        LicenseStatus.VALID: 1,
        LicenseStatus.EXPIRED: 2,
        LicenseStatus.EXCEEDED: 3,
        LicenseStatus.NOT_INSTALLED: 4,
        LicenseStatus.SUSPENDED: 5,
        LicenseStatus.PENDING_ACTIVATION: 6,
        LicenseStatus.REVOKED: 7,
        LicenseStatus.TRIAL: 8,
    }
    return mapping.get(status, 0)


def license_type_to_enum(license_type: LicenseType) -> int:
    """Convert LicenseType to proto enum value.
    
    Args:
        license_type: LicenseType enum value.
        
    Returns:
        Integer value for proto LicenseType enum.
    """
    mapping = {
        LicenseType.PERPETUAL: 1,
        LicenseType.SUBSCRIPTION_MONTHLY: 2,
        LicenseType.SUBSCRIPTION_ANNUAL: 3,
        LicenseType.USAGE_BASED: 4,
        LicenseType.PER_NODE: 5,
        LicenseType.PER_USER: 6,
        LicenseType.PER_CORE: 7,
        LicenseType.PER_INSTANCE: 8,
        LicenseType.ENTERPRISE: 9,
    }
    return mapping.get(license_type, 0)


def vendor_to_enum(vendor: str) -> int:
    """Convert vendor string to proto enum value.
    
    Args:
        vendor: Vendor string.
        
    Returns:
        Integer value for proto Vendor enum.
    """
    mapping = {
        "ericsson": 1,
        "huawei": 2,
        "nokia": 3,
        "cisco": 4,
        "zte": 5,
    }
    return mapping.get(vendor.lower(), 0)


def priority_to_string(priority: RecommendationPriority) -> str:
    """Convert RecommendationPriority to string.
    
    Args:
        priority: RecommendationPriority enum value.
        
    Returns:
        String representation.
    """
    mapping = {
        RecommendationPriority.URGENT: "urgent",
        RecommendationPriority.HIGH: "high",
        RecommendationPriority.MEDIUM: "medium",
        RecommendationPriority.LOW: "low",
        RecommendationPriority.INFORMATIONAL: "informational",
    }
    return mapping.get(priority, "medium")


class AccountingServiceServicer:
    """gRPC servicer for AccountingService operations.
    
    Provides license and capacity management operations including
    status tracking, utilization monitoring, and procurement recommendations.
    
    Attributes:
        license_manager: LicenseManager instance.
        capacity_tracker: CapacityTracker instance.
    
    Example:
        >>> license_manager = LicenseManager()
        >>> capacity_tracker = CapacityTracker()
        >>> servicer = AccountingServiceServicer(license_manager, capacity_tracker)
        >>> # Register with gRPC server
        >>> add_AccountingServiceServicer_to_server(servicer, server)
    """

    def __init__(
        self,
        license_manager: LicenseManager,
        capacity_tracker: Optional[CapacityTracker] = None,
    ) -> None:
        """Initialize the AccountingService servicer.
        
        Args:
            license_manager: LicenseManager instance.
            capacity_tracker: CapacityTracker instance.
        """
        self._license_manager = license_manager
        self._capacity_tracker = capacity_tracker
        self._license_cache: Dict[str, License] = {}
        self._cache_lock = asyncio.Lock()

        logger.info("AccountingServiceServicer initialized")

    async def GetLicenseStatus(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Get license status information.
        
        Retrieves comprehensive status for a license including
        features, utilization, and compliance status.
        
        Args:
            request: GetLicenseStatusRequest with license_id.
            context: gRPC context.
            
        Returns:
            GetLicenseStatusResponse with license details.
        """
        try:
            # Extract parameters
            license_id = getattr(request, "license_id", "")
            include_features = getattr(request, "include_features", True)
            include_utilization = getattr(request, "include_utilization", True)

            if not license_id:
                await context.abort(
                    grpc.StatusCode.INVALID_ARGUMENT if GRPC_AVAILABLE else 3,
                    "license_id is required"
                )

            # Get license status from manager
            status_dict = await self._license_manager.get_license_status(license_id)

            if not status_dict:
                await context.abort(
                    grpc.StatusCode.NOT_FOUND if GRPC_AVAILABLE else 5,
                    f"License not found: {license_id}"
                )

            # Get the full license object
            license_obj = self._license_manager._licenses.get(license_id)

            # Build response
            response = {
                "license": self._license_to_dict(status_dict, license_obj),
                "is_valid": status_dict.get("is_valid", False),
                "is_expired": status_dict.get("is_expired", False),
                "compliance_status": status_dict.get("compliance_status", "UNKNOWN"),
                "features_available": status_dict.get("features_available", 0),
                "features_total": status_dict.get("features_total", 0),
                "vendor_data": {},
            }

            if include_features and license_obj:
                response["license"]["features"] = [
                    self._feature_to_dict(f) for f in license_obj.features
                ]

            logger.info(f"GetLicenseStatus for {license_id}: valid={response['is_valid']}")

            return response

        except Exception as e:
            logger.error(f"GetLicenseStatus error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to get license status: {str(e)}"
                )

    def _license_to_dict(
        self,
        status_dict: Dict[str, Any],
        license_obj: Optional[License],
    ) -> Dict[str, Any]:
        """Convert license data to proto-compatible dictionary.
        
        Args:
            status_dict: Status dictionary from manager.
            license_obj: Optional License object.
            
        Returns:
            Dictionary with proto-compatible fields.
        """
        if license_obj:
            return {
                "license_id": license_obj.license_id,
                "name": license_obj.name,
                "vendor": vendor_to_enum(license_obj.vendor),
                "license_type": license_type_to_enum(license_obj.license_type),
                "status": license_status_to_enum(license_obj.status),
                "installed_at": license_obj.installed_at,
                "expires_at": license_obj.expires_at,
                "capacity_total": license_obj.capacity_total,
                "capacity_used": license_obj.capacity_used,
                "utilization_percentage": round(license_obj.utilization_percentage, 2),
                "days_until_expiry": license_obj.days_until_expiry,
                "features": [],
                "cost_center": license_obj.cost_center or "",
                "metadata": license_obj.metadata,
            }

        return {
            "license_id": status_dict.get("license_id", ""),
            "name": status_dict.get("name", ""),
            "vendor": vendor_to_enum(status_dict.get("vendor", "cim")),
            "license_type": license_type_to_enum(
                LicenseType.PERPETUAL
            ),
            "status": 0,
            "installed_at": None,
            "expires_at": None,
            "capacity_total": status_dict.get("capacity_total", 0),
            "capacity_used": status_dict.get("capacity_used", 0),
            "utilization_percentage": round(status_dict.get("utilization_percentage", 0), 2),
            "days_until_expiry": status_dict.get("days_until_expiry"),
            "features": [],
            "cost_center": "",
            "metadata": {},
        }

    def _feature_to_dict(self, feature: LicenseFeature) -> Dict[str, Any]:
        """Convert LicenseFeature to proto-compatible dictionary.
        
        Args:
            feature: LicenseFeature instance.
            
        Returns:
            Dictionary with proto-compatible fields.
        """
        return {
            "feature_id": feature.feature_id,
            "name": feature.name,
            "description": feature.description,
            "is_enabled": feature.is_enabled,
            "capacity_limit": feature.capacity_limit,
            "current_usage": feature.current_usage,
            "utilization_percentage": round(feature.utilization_percentage, 2),
            "expires_at": feature.expires_at,
            "is_available": feature.is_available(),
        }

    async def GetCapacitySummary(
        self,
        request: Any,
        context: Any,
    ) -> Any:
        """Get capacity utilization summary.
        
        Retrieves capacity metrics and utilization summary with
        optional procurement recommendations.
        
        Args:
            request: GetCapacitySummaryRequest with filters.
            context: gRPC context.
            
        Returns:
            GetCapacitySummaryResponse with metrics and recommendations.
        """
        try:
            if not self._capacity_tracker:
                await context.abort(
                    grpc.StatusCode.UNAVAILABLE if GRPC_AVAILABLE else 14,
                    "Capacity tracking not available"
                )

            # Extract parameters
            capacity_types = list(getattr(request, "capacity_types", []))
            ne_id = getattr(request, "ne_id", "")
            vendor = getattr(request, "vendor", 0)
            include_recommendations = getattr(request, "include_recommendations", False)

            # Map capacity type strings
            type_filters: List[CapacityType] = []
            for type_str in capacity_types:
                try:
                    type_filters.append(CapacityType[type_str.upper().replace("-", "_")])
                except KeyError:
                    pass

            # Get utilization
            utilization = await self._capacity_tracker.get_utilization(
                capacity_type=type_filters[0] if type_filters else None,
                network_element_id=ne_id if ne_id else None,
            )

            # Get metrics
            metrics = utilization.get("metrics", [])
            summary = utilization.get("summary", {})

            # Count critical and warning
            critical_count = 0
            warning_count = 0
            for metric in metrics:
                util_pct = metric.get("utilization_percentage", 0)
                if util_pct >= 90:
                    critical_count += 1
                elif util_pct >= 75:
                    warning_count += 1

            # Get recommendations
            recommendations = []
            if include_recommendations:
                recs = await self._capacity_tracker.generate_recommendations(
                    min_utilization=75.0
                )
                recommendations = [
                    self._recommendation_to_dict(r) for r in recs
                ]

            # Build capacity by type
            capacity_by_type = {}
            for type_name, type_data in summary.get("by_capacity_type", {}).items():
                capacity_by_type[type_name] = type_data.get("utilization_percentage", 0)

            logger.info(
                f"GetCapacitySummary returned {len(metrics)} metrics, "
                f"{len(recommendations)} recommendations"
            )

            return {
                "metrics": metrics,
                "overall_utilization": round(summary.get("overall_utilization", 0), 2),
                "critical_count": critical_count,
                "warning_count": warning_count,
                "recommendations": recommendations,
                "capacity_by_type": capacity_by_type,
                "last_updated": datetime.now(timezone.utc),
            }

        except Exception as e:
            logger.error(f"GetCapacitySummary error: {e}")
            if GRPC_AVAILABLE:
                await context.abort(
                    grpc.StatusCode.INTERNAL,
                    f"Failed to get capacity summary: {str(e)}"
                )

    def _recommendation_to_dict(
        self,
        recommendation: ProcurementRecommendation,
    ) -> Dict[str, Any]:
        """Convert ProcurementRecommendation to proto-compatible dict.
        
        Args:
            recommendation: ProcurementRecommendation instance.
            
        Returns:
            Dictionary with proto-compatible fields.
        """
        return {
            "recommendation_id": recommendation.recommendation_id,
            "metric_id": recommendation.metric_id,
            "priority": priority_to_string(recommendation.priority),
            "title": recommendation.title,
            "description": recommendation.description,
            "current_capacity": recommendation.current_capacity,
            "recommended_capacity": recommendation.recommended_capacity,
            "estimated_cost": recommendation.estimated_cost,
            "currency": recommendation.currency,
            "rationale": recommendation.rationale,
            "created_at": recommendation.created_at,
        }

    async def check_all_licenses(self) -> Dict[str, Any]:
        """Check status of all registered licenses.
        
        Returns:
            Dictionary with overall license status.
        """
        licenses = self._license_manager._licenses
        results = {
            "total": len(licenses),
            "valid": 0,
            "expired": 0,
            "exceeded": 0,
            "warnings": [],
        }

        for license_id, license_obj in licenses.items():
            status = await self._license_manager.get_license_status(license_id)
            if status:
                if status.get("is_valid"):
                    results["valid"] += 1
                elif status.get("is_expired"):
                    results["expired"] += 1
                elif status.get("status") == "exceeded":
                    results["exceeded"] += 1

                # Check for warnings
                days = status.get("days_until_expiry")
                if days is not None and days <= 30:
                    results["warnings"].append({
                        "license_id": license_id,
                        "type": "expiring_soon",
                        "days_remaining": days,
                    })

        return results

    async def get_capacity_alerts(self) -> List[Dict[str, Any]]:
        """Get current capacity alerts.
        
        Returns:
            List of capacity alert dictionaries.
        """
        if not self._capacity_tracker:
            return []

        alerts = self._capacity_tracker._alerts
        return [a.to_dict() for a in alerts if not a.acknowledged]

    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics.
        
        Returns:
            Dictionary with service statistics.
        """
        stats = {
            "total_licenses": len(self._license_manager._licenses),
            "license_alerts": len(self._license_manager._alerts),
        }

        if self._capacity_tracker:
            stats.update({
                "total_metrics": len(self._capacity_tracker._metrics),
                "capacity_alerts": len(self._capacity_tracker._alerts),
                "total_recommendations": len(self._capacity_tracker._recommendations),
            })

        return stats


# Additional service classes for capacity type mapping
CAPACITY_TYPE_MAPPING = {
    "rf-spectrum": CapacityType.RF_SPECTRUM,
    "rf-power": CapacityType.RF_POWER,
    "throughput": CapacityType.THROUGHPUT,
    "subscriber-active": CapacityType.SUBSCRIBER_ACTIVE,
    "subscriber-total": CapacityType.SUBSCRIBER_TOTAL,
    "session": CapacityType.SESSION,
    "storage": CapacityType.STORAGE,
    "compute": CapacityType.COMPUTE,
    "memory": CapacityType.MEMORY,
}
