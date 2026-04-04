"""
gRPC Service Implementations for Unified OSS Framework.

This module provides servicer implementations for all FCAPS management
services, integrating with the fcaps module components.

Available Services:
    - AlarmService: Fault management with alarm lifecycle operations
    - PerformanceService: KPI management and metrics collection
    - ConfigurationService: Configuration versioning and deployment
    - SecurityService: Access control and audit logging
    - AccountingService: License and capacity management

Integration:
    Each service integrates with its corresponding fcaps module:
    
    >>> from unified_oss.fcaps.fault.alarm_manager import AlarmManager
    >>> from unified_oss.fcaps.performance.kpi_manager import KPIManager
    >>> from unified_oss.fcaps.configuration.config_manager import ConfigManager
    >>> from unified_oss.fcaps.security.auth import AuthManager
    >>> from unified_oss.fcaps.accounting.license_manager import LicenseManager
    >>>
    >>> # Initialize servicers with fcaps managers
    >>> alarm_servicer = AlarmServiceServicer(alarm_manager)
    >>> perf_servicer = PerformanceServiceServicer(kpi_manager)
    >>> config_servicer = ConfigurationServiceServicer(config_manager)
    >>> security_servicer = SecurityServiceServicer(auth_manager)
    >>> accounting_servicer = AccountingServiceServicer(license_manager)
"""

from unified_oss.api.grpc.services.alarm_service import (
    AlarmServiceServicer,
    AlarmSubscription,
)
from unified_oss.api.grpc.services.performance_service import (
    PerformanceServiceServicer,
    KPIStreamSubscription,
    ThresholdBreachRecord,
)
from unified_oss.api.grpc.services.config_service import (
    ConfigurationServiceServicer,
    ApplyOperation,
)
from unified_oss.api.grpc.services.security_service import (
    SecurityServiceServicer,
    AuthorizationManager,
    AuditLogEntry,
    CredentialRotationTask,
    Permission,
    Role,
)
from unified_oss.api.grpc.services.accounting_service import (
    AccountingServiceServicer,
    CAPACITY_TYPE_MAPPING,
)

__all__ = [
    # Alarm Service
    "AlarmServiceServicer",
    "AlarmSubscription",
    # Performance Service
    "PerformanceServiceServicer",
    "KPIStreamSubscription",
    "ThresholdBreachRecord",
    # Configuration Service
    "ConfigurationServiceServicer",
    "ApplyOperation",
    # Security Service
    "SecurityServiceServicer",
    "AuthorizationManager",
    "AuditLogEntry",
    "CredentialRotationTask",
    "Permission",
    "Role",
    # Accounting Service
    "AccountingServiceServicer",
    "CAPACITY_TYPE_MAPPING",
]

# Service version
SERVICE_VERSION = "1.0.0"
