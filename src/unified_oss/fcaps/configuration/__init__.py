"""
Configuration Management Module for Unified OSS Framework.

This module provides comprehensive configuration management functionality
including version control, drift detection, and NETCONF-based workflows.

Modules:
    config_manager: Configuration profile management with version control
    drift_detection: Configuration drift detection and alerting
    workflow: NETCONF 7-step workflow implementation

Classes:
    ConfigManager: Central configuration management with version control
    ConfigSnapshot: Configuration snapshot for comparison and backup
    ConfigVersion: Configuration version representation
    DriftDetector: Configuration drift detection engine
    DriftReport: Comprehensive drift detection report
    DriftEntry: Single configuration drift entry
    ConfigWorkflow: NETCONF 7-step configuration workflow
    WorkflowStep: Workflow step enumeration
    WorkflowState: Workflow execution states

Example:
    >>> from unified_oss.fcaps.configuration import ConfigManager, DriftDetector
    >>> manager = ConfigManager()
    >>> version = await manager.apply_config("router-001", config_xml, "admin")
"""

from .config_manager import (
    AuditEntry,
    ConfigManager,
    ConfigOperation,
    ConfigSnapshot,
    ConfigStatus,
    ConfigVersion,
    ConfigurationError,
    ConfigurationValidator,
    RollbackError,
    ValidationFailedError,
    VersionNotFoundError,
    VendorNormalizer,
    VendorType,
    ValidationLevel,
)
from .drift_detection import (
    BaselineNotFoundError,
    ComparisonError,
    ComparisonMode,
    DriftAlert,
    DriftDetector,
    DriftEntry,
    DriftReport,
    DriftSeverity,
    DriftType,
    DriftDetectionError,
    MonitoringSchedule,
    MonitoringState,
    SeverityClassifier,
)
from .workflow import (
    ApprovalRequest,
    ApprovalStatus,
    CommitFailedError,
    CommitMode,
    ConfigWorkflow,
    DatastoreType,
    LockFailedError,
    TimeoutError as WorkflowTimeoutError,
    ValidationError as WorkflowValidationError,
    WorkflowError,
    WorkflowErrorType,
    WorkflowManager,
    WorkflowResult,
    WorkflowState,
    WorkflowStep,
    WorkflowStepResult,
    AuditLogEntry,
)

__all__ = [
    # Config Manager
    "ConfigManager",
    "ConfigSnapshot",
    "ConfigVersion",
    "ConfigOperation",
    "ConfigStatus",
    "VendorType",
    "VendorNormalizer",
    "ConfigurationValidator",
    "ValidationLevel",
    "AuditEntry",
    "ConfigurationError",
    "ValidationFailedError",
    "VersionNotFoundError",
    "RollbackError",
    # Drift Detection
    "DriftDetector",
    "DriftReport",
    "DriftEntry",
    "DriftType",
    "DriftSeverity",
    "ComparisonMode",
    "MonitoringState",
    "MonitoringSchedule",
    "SeverityClassifier",
    "DriftAlert",
    "DriftDetectionError",
    "BaselineNotFoundError",
    "ComparisonError",
    # Workflow
    "ConfigWorkflow",
    "WorkflowStep",
    "WorkflowState",
    "WorkflowResult",
    "WorkflowManager",
    "WorkflowStepResult",
    "DatastoreType",
    "CommitMode",
    "ApprovalStatus",
    "ApprovalRequest",
    "WorkflowError",
    "WorkflowErrorType",
    "LockFailedError",
    "WorkflowValidationError",
    "CommitFailedError",
    "WorkflowTimeoutError",
    "AuditLogEntry",
]

__version__ = "1.0.0"
